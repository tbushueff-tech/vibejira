import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

const ORIGIN = "https://tbushueff-tech.github.io";
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

function makeEnv() {
  const store = new Map();
  return {
    store,
    AUTH_SECRET: "test-secret",
    USER_STORE: {
      async get(k) {
        if (Array.isArray(k)) return new Map(k.map(x => [x, store.get(x)]));
        return store.get(k) ?? null;
      },
      async put(k, v) { store.set(k, v); },
      async delete(k) { store.delete(k); },
      async list({ prefix }) {
        const keys = [...store.keys()].filter(x => x.startsWith(prefix)).map(name => ({ name }));
        return { keys, list_complete: true };
      }
    }
  };
}

function client(env) {
  return async function call(path, method, body, token, origin = ORIGIN) {
    const headers = { "Content-Type": "text/plain" };
    if (origin) headers.Origin = origin;
    if (token) headers.Authorization = "Bearer " + token;
    const res = await worker.fetch(new Request("https://worker.example" + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body)
    }), env);
    let data = null;
    try { data = await res.json(); } catch (e) { /* 204 */ }
    return { status: res.status, data };
  };
}

const bundle = { v: 1, alg: "AES-256-GCM", kdf: "PBKDF2-SHA-256", iterations: 600000, salt: "s", iv: "i", wrappedKey: "k" };
const item = (id, ttl = HOUR) => ({ v: 2, id, expiresAt: Date.now() + ttl, iv: "iv", ciphertext: "ct" });
const buffer = (ids, baseRevision, ttl) => ({ v: 2, baseRevision, items: ids.map(id => item(id, ttl)) });

async function registered(username = "alice", password = "secret1") {
  const env = makeEnv();
  const call = client(env);
  const res = await call("/auth/register", "POST", { username, password, crypto: bundle });
  assert.equal(res.status, 201);
  return { env, call, token: res.data.token };
}

test("login returns profile and crypto bundle; wrong or unknown credentials get 401", async () => {
  const { call, token } = await registered();
  await call("/auth/profile", "POST", { displayName: "Alice", avatar: null }, token);

  const ok = await call("/auth/login", "POST", { username: "ALICE", password: "secret1" });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.username, "alice");
  assert.deepEqual(ok.data.profile, { displayName: "Alice", avatar: null });
  assert.equal(ok.data.crypto.wrappedKey, "k");

  assert.equal((await call("/auth/login", "POST", { username: "alice", password: "nope12" })).status, 401);
  assert.equal((await call("/auth/login", "POST", { username: "ghost", password: "secret1" })).status, 401);
});

test("auth endpoints reject a foreign Origin; buffer requires a token", async () => {
  const { call } = await registered();
  assert.equal((await call("/auth/login", "POST", { username: "alice", password: "secret1" }, undefined, "https://evil.example")).status, 403);
  assert.equal((await call("/", "GET")).status, 401);
  assert.equal((await call("/", "GET", undefined, "not.a.token")).status, 401);
});

test("deleting items (including the last one) is accepted with the current revision", async () => {
  const { call, token } = await registered();

  let res = await call("/", "GET", undefined, token);
  assert.deepEqual(res.data, { v: 2, rev: 0, items: [] });

  res = await call("/", "POST", buffer(["a", "b", "c"], 0), token);
  assert.deepEqual(res.data, { ok: true, revision: 1 });

  res = await call("/", "POST", buffer(["a", "b"], 1), token);     // delete c
  assert.equal(res.status, 200);
  assert.equal(res.data.revision, 2);

  res = await call("/", "POST", buffer([], 2), token);             // delete everything
  assert.equal(res.status, 200);
  assert.equal(res.data.revision, 3);

  res = await call("/", "GET", undefined, token);
  assert.deepEqual(res.data, { v: 2, rev: 3, items: [] });

  // the revision counter survives an empty buffer
  res = await call("/", "POST", buffer(["x"], 3), token);
  assert.equal(res.status, 200);
  assert.equal(res.data.revision, 4);
});

test("a stale revision is refused and nothing is overwritten", async () => {
  const { call, token } = await registered();
  await call("/", "POST", buffer(["a", "b"], 0), token);            // device A -> rev 1

  const stale = await call("/", "POST", buffer(["z"], 0), token);   // device B still at rev 0
  assert.equal(stale.status, 409);
  assert.equal(stale.data.conflict, true);
  assert.equal(stale.data.revision, 1);

  const now = await call("/", "GET", undefined, token);
  assert.deepEqual(now.data.items.map(i => i.id), ["a", "b"]);
});

test("old clients without baseRevision keep the shrink guard", async () => {
  const { call, token } = await registered();
  await call("/", "POST", buffer(["a", "b", "c"], 0), token);
  const res = await call("/", "POST", buffer(["a"], undefined), token);
  assert.equal(res.status, 409);
  const same = await call("/", "POST", buffer(["a", "b", "c", "d"], undefined), token);
  assert.equal(same.status, 200);
});

test("expired items are hidden on read and dropped on write; expiry is clamped", async () => {
  const { env, call, token } = await registered();
  const body = {
    v: 2, baseRevision: 0,
    items: [item("fresh"), item("forever", 365 * DAY), { ...item("gone"), expiresAt: Date.now() - 1000 }]
  };
  assert.equal((await call("/", "POST", body, token)).status, 200);

  const stored = JSON.parse(env.store.get("buffer:alice"));
  assert.deepEqual(stored.items.map(i => i.id).sort(), ["forever", "fresh"]);
  const forever = stored.items.find(i => i.id === "forever");
  assert.ok(forever.expiresAt <= Date.now() + 8 * DAY + 1000, "expiresAt must be clamped to 8 days");

  // an item that expires after being stored is not served any more
  stored.items.find(i => i.id === "fresh").expiresAt = Date.now() - 1;
  env.store.set("buffer:alice", JSON.stringify(stored));
  const res = await call("/", "GET", undefined, token);
  assert.deepEqual(res.data.items.map(i => i.id), ["forever"]);
});

test("payload validation: duplicates, too many items, malformed body, size", async () => {
  const { call, token } = await registered();
  const dup = { v: 2, baseRevision: 0, items: [item("a"), item("a")] };
  assert.equal((await call("/", "POST", dup, token)).status, 400);

  const many = { v: 2, baseRevision: 0, items: Array.from({ length: 1001 }, (_, i) => item("i" + i)) };
  assert.equal((await call("/", "POST", many, token)).status, 400);

  assert.equal((await call("/", "POST", { v: 1, items: [] }, token)).status, 400);
  assert.equal((await call("/", "POST", { v: 2, baseRevision: -1, items: [] }, token)).status, 400);

  const huge = { v: 2, baseRevision: 0, items: [{ ...item("big"), ciphertext: "x".repeat(4 * 1024 * 1024 + 1) }] };
  assert.equal((await call("/", "POST", huge, token)).status, 413);
});

test("the key bundle is created once and /auth/me exposes it to the owner only", async () => {
  const env = makeEnv();
  const call = client(env);
  // account without a bundle (created before encryption existed)
  const reg = await call("/auth/register", "POST", { username: "bob", password: "secret1" });
  const token = reg.data.token;
  assert.equal(reg.data.crypto, null);

  const first = await call("/auth/crypto", "POST", { crypto: bundle }, token);
  assert.equal(first.data.crypto.wrappedKey, "k");
  const other = { ...bundle, wrappedKey: "REPLACED" };
  const second = await call("/auth/crypto", "POST", { crypto: other }, token);
  assert.equal(second.data.crypto.wrappedKey, "k", "existing bundle must not be replaced");

  const me = await call("/auth/me", "GET", undefined, token);
  assert.equal(me.data.crypto.wrappedKey, "k");
  assert.equal((await call("/auth/me", "GET")).status, 401);
});

test("password change checks the current password and stores the new bundle", async () => {
  const { call, token } = await registered();
  const next = { ...bundle, wrappedKey: "NEW" };

  const bad = await call("/auth/password", "POST", { currentPassword: "wrong1", newPassword: "newpass1", crypto: next }, token);
  assert.equal(bad.status, 401);

  const ok = await call("/auth/password", "POST", { currentPassword: "secret1", newPassword: "newpass1", crypto: next }, token);
  assert.equal(ok.status, 200);

  assert.equal((await call("/auth/login", "POST", { username: "alice", password: "secret1" })).status, 401);
  const login = await call("/auth/login", "POST", { username: "alice", password: "newpass1" });
  assert.equal(login.status, 200);
  assert.equal(login.data.crypto.wrappedKey, "NEW");
});

test("errors do not leak internals", async () => {
  const { env, call, token } = await registered();
  env.USER_STORE.get = async () => { throw new Error("secret kv failure details"); };
  const res = await call("/", "GET", undefined, token);
  assert.equal(res.status, 500);
  assert.ok(!JSON.stringify(res.data).includes("secret kv failure"));
});

test("OPTIONS: allowed origin gets 204, others 403", async () => {
  const env = makeEnv();
  const call = client(env);
  assert.equal((await call("/", "OPTIONS")).status, 204);
  assert.equal((await call("/", "OPTIONS", undefined, undefined, "https://evil.example")).status, 403);
});

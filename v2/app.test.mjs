import test from "node:test";
import assert from "node:assert/strict";
import { CloudApi, ApiError } from "./api.js";
import { createEncryption, unlockEncryption, encryptBuffer, decryptBuffer, rotateEncryption } from "./crypto.js";

test("AES-GCM encrypted envelopes are backward-compatible and decrypt accurately", async () => {
  const { key, bundle } = await createEncryption("sample-password-only-for-tests");
  const original = [{ id: "t1", title: "Пример", text: "Секретный текст", copies: 3, expiresAt: Date.now() + 60000 }];
  const encrypted = await encryptBuffer(original, key);
  assert.equal(encrypted.v, 2);
  assert.equal(encrypted.items.length, 1);
  assert.ok(!JSON.stringify(encrypted).includes("Секретный"));
  const restored = await unlockEncryption(bundle, "sample-password-only-for-tests");
  assert.deepEqual(await decryptBuffer(encrypted, restored), original);
  const rotated = await rotateEncryption(bundle, "sample-password-only-for-tests", "changed-password");
  const newKey = await unlockEncryption(rotated.bundle, "changed-password");
  assert.deepEqual(await decryptBuffer(encrypted, newKey), original);
});

test("chunk API reconstructs large encrypted JSON safely and sends authorization", async () => {
  const original = { v: 2, items: Array.from({ length: 20 }, (_, i) => ({
    v: 2, id: "item" + i, expiresAt: 12345678, iv: "abcd",
    ciphertext: "A".repeat(1000)
  })) };
  const payload = JSON.stringify(original);
  const version = 7;
  const oldFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, options) => {
    seen.push({ url: String(url), authorization: options.headers.Authorization });
    const u = new URL(url);
    if (u.searchParams.has("meta")) return new Response(JSON.stringify({
      v: 3, total: payload.length, revision: version
    }), { status: 200 });
    const at = Number(u.searchParams.get("chunk"));
    return new Response(JSON.stringify({
      v: 3, total: payload.length, revision: version, offset: at,
      chunk: payload.slice(at, at + 2048),
      next: at + 2048 < payload.length ? at + 2048 : null
    }), { status: 200 });
  };
  try {
    const api = new CloudApi();
    api.setToken("test-signed-token");
    const result = await api.readBuffer();
    assert.deepEqual(result.envelope, original);
    assert.ok(seen.length > 6);
    assert.ok(seen.every(x => x.authorization === "Bearer test-signed-token"));
    assert.ok(seen.every(x => /\?(meta=1|chunk=\d+)/.test(x.url)));
  } finally { globalThis.fetch = oldFetch; }
});

test("truncated chunk response never becomes an accepted buffer", async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    const u = new URL(url);
    const value = u.searchParams.has("meta")
      ? { v: 3, total: 20000, revision: "rev-1" }
      : { v: 3, total: 20000, revision: "rev-1", offset: 0, chunk: "", next: null };
    return new Response(JSON.stringify(value), { status: 200 });
  };
  try {
    await assert.rejects(() => new CloudApi().readBuffer(), ApiError);
  } finally { globalThis.fetch = oldFetch; }
});

test("server errors are surfaced, not mistaken for an empty clipboard", async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error: "Temporary KV failure" }), { status: 503 });
  try {
    const api = new CloudApi(); api.setToken("token");
    await assert.rejects(() => api.readBuffer(), /Temporary KV failure/);
  } finally { globalThis.fetch = oldFetch; }
});

test("bad encryption key never silently returns an empty buffer", async () => {
  const a = await createEncryption("password-a");
  const b = await createEncryption("password-b");
  const encrypted = await encryptBuffer([{ id: "1", text: "must-not-drop", expiresAt: 1 }], a.key);
  await assert.rejects(() => decryptBuffer(encrypted, b.key));
});

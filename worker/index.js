const ALLOWED_ORIGIN = "https://tbushueff-tech.github.io";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// An item may live at most 7 days (+1 day of clock-skew slack). The client
// chooses expiresAt, so the server clamps it: nobody can pin data forever.
const MAX_ITEM_TTL_MS = 8 * 24 * 60 * 60 * 1000;
const MAX_ITEMS = 1000;
const MAX_BODY_CHARS = 4 * 1024 * 1024;
const MAX_PASSWORD_CHARS = 128;
// Used to spend the same CPU time for unknown usernames as for real ones.
const DUMMY_SALT = "AAAAAAAAAAAAAAAAAAAAAA";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };
}

function json(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...(extraHeaders || {})
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function timingSafeEqual(a, b) {
  a = String(a);
  b = String(b);
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  // 100000 is the maximum iteration count Cloudflare Workers allow for PBKDF2.
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return base64url(new Uint8Array(bits));
}

function randomSalt() {
  return base64url(crypto.getRandomValues(new Uint8Array(16)));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createSession(username, env) {
  const payload = { username, exp: Date.now() + SESSION_TTL_MS };
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await hmacKey(env.AUTH_SECRET);
  const signature = base64url(new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body))
  ));
  return body + "." + signature;
}

// Sessions are signed bearer tokens only (the client never used cookies).
async function verifySession(request, env) {
  if (!env.AUTH_SECRET) return null;
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const parts = auth.slice(7).trim().split(".");
  if (parts.length !== 2) return null;

  try {
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0])));
    if (!payload || typeof payload.username !== "string" || !payload.username ||
        typeof payload.exp !== "number" || payload.exp <= Date.now()) {
      return null;
    }
    const key = await hmacKey(env.AUTH_SECRET);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64urlDecode(parts[1]),
      new TextEncoder().encode(parts[0])
    );
    return valid ? payload : null;
  } catch (e) {
    return null;
  }
}

async function readJson(request) {
  const data = await request.json();
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new SyntaxError("Request body must be a JSON object");
  }
  return data;
}

function userKey(username) {
  return "user:" + String(username).toLowerCase();
}

async function readUserRecord(env, username) {
  if (!env.USER_STORE) return null;
  const raw = await env.USER_STORE.get(userKey(username));
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error("Invalid user record:", userKey(username), e);
    return null;
  }
}

function validCryptoBundle(bundle) {
  return !!bundle && bundle.v === 1 &&
    typeof bundle.salt === "string" &&
    typeof bundle.iv === "string" &&
    typeof bundle.wrappedKey === "string";
}

// ---------------------------------------------------------------------------
// Encrypted clipboard buffer: one KV document per user.
//   { v: 2, rev: <integer>, items: [ { v:2, id, expiresAt, iv, ciphertext } ] }
// `rev` increases by one on every write. Writers send the revision they last
// saw (baseRevision); a mismatch means another device wrote in between, and
// the write is refused with 409 instead of silently overwriting that data.
// ---------------------------------------------------------------------------

function bufferKey(username) {
  return "buffer:" + username.toLowerCase();
}

function legacyMigrationMarkerKey(username) {
  // Permanent marker: when the main buffer expires, do not rescan old keys.
  return "legacy-migration:v2:" + username.toLowerCase();
}

function kvExpiration(expiresAtMs) {
  return Math.max(
    Math.floor(expiresAtMs / 1000),
    Math.floor(Date.now() / 1000) + 60
  );
}

function validateEncryptedPayload(payload) {
  if (!payload || payload.v !== 2 || !Array.isArray(payload.items)) {
    throw new Error("Encrypted buffer required");
  }
  if (payload.items.length > MAX_ITEMS) {
    throw new Error("Too many items");
  }
  if (payload.baseRevision !== undefined &&
      !(Number.isSafeInteger(payload.baseRevision) && payload.baseRevision >= 0)) {
    throw new Error("Invalid baseRevision");
  }
  const seen = new Set();
  for (const item of payload.items) {
    if (!item || item.v !== 2 ||
        typeof item.id !== "string" || item.id.length < 1 || item.id.length > 64 ||
        typeof item.expiresAt !== "number" || !Number.isFinite(item.expiresAt) ||
        typeof item.iv !== "string" || item.iv.length > 64 ||
        typeof item.ciphertext !== "string") {
      throw new Error("Invalid encrypted buffer item");
    }
    if (seen.has(item.id)) throw new Error("Duplicate item id");
    seen.add(item.id);
  }
}

function isActive(item, now) {
  return !item || !item.expiresAt || item.expiresAt > now;
}

async function getLegacyPerItemBuffer(env, username) {
  const prefix = bufferKey(username) + ":";
  let cursor;
  const encryptedItems = [];
  do {
    const page = await env.USER_STORE.list({ prefix, cursor });
    const names = page.keys.map(key => key.name);
    if (names.length) {
      const values = await env.USER_STORE.get(names);
      for (const name of names) {
        const raw = values.get(name);
        if (!raw) continue;
        try {
          const envelope = JSON.parse(raw);
          if (envelope && envelope.v === 2) encryptedItems.push(envelope);
        } catch (e) {
          console.error("Invalid encrypted buffer item:", name, e);
        }
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return { v: 2, items: encryptedItems };
}

// Returns { items, rev, legacyPlain }. `legacyPlain` marks an old unencrypted
// array that is still served as-is until the client overwrites it.
async function loadBuffer(env, username, cacheTtl) {
  const key = bufferKey(username);
  const raw = cacheTtl
    ? await env.USER_STORE.get(key, { cacheTtl })
    : await env.USER_STORE.get(key);

  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.v === 2 && Array.isArray(parsed.items)) {
        const rev = Number.isSafeInteger(parsed.rev) && parsed.rev >= 0 ? parsed.rev : 0;
        return { items: parsed.items, rev, legacyPlain: false };
      }
      if (Array.isArray(parsed)) return { items: parsed, rev: 0, legacyPlain: true };
    } catch (e) {
      console.error("Invalid buffer:", key, e);
    }
  }

  // The legacy per-item scan must happen at most once per user, not on
  // every GET to an empty buffer (which happens every polling interval).
  const marker = legacyMigrationMarkerKey(username);
  if (await env.USER_STORE.get(marker)) {
    return { items: [], rev: 0, legacyPlain: false };
  }

  const legacy = await getLegacyPerItemBuffer(env, username);
  if (legacy.items.length) {
    // Save the migrated data before setting the marker. On a failed write,
    // a later request can safely retry migration rather than lose records.
    const maxExpiresAt = Math.max(...legacy.items.map(item => item.expiresAt || 0));
    await env.USER_STORE.put(key, JSON.stringify(legacy), {
      expiration: kvExpiration(Math.min(maxExpiresAt, Date.now() + MAX_ITEM_TTL_MS))
    });
  }
  // KV markers have no expiration; unlike buffers, they are not deleted by TTL.
  await env.USER_STORE.put(marker, "1");

  return { items: legacy.items, rev: 0, legacyPlain: false };
}

// Drops expired items, clamps expiresAt and keeps only known fields.
// An empty buffer is stored as a short document too, so that the revision
// counter survives deleting the last item.
async function saveBuffer(env, username, items, rev) {
  const now = Date.now();
  const kept = [];
  for (const item of items) {
    if (item.expiresAt <= now) continue;
    kept.push({
      v: 2,
      id: item.id,
      expiresAt: Math.min(item.expiresAt, now + MAX_ITEM_TTL_MS),
      iv: item.iv,
      ciphertext: item.ciphertext
    });
  }
  const latest = kept.reduce((max, item) => Math.max(max, item.expiresAt), 0);
  await env.USER_STORE.put(
    bufferKey(username),
    JSON.stringify({ v: 2, rev, items: kept }),
    { expiration: kvExpiration(kept.length ? latest : now + SESSION_TTL_MS) }
  );
}

async function handleBuffer(request, env, session) {
  const username = session.username;
  const now = Date.now();

  if (request.method === "GET") {
    const current = await loadBuffer(env, username, 30);
    const items = current.items.filter(item => isActive(item, now));
    // Original JSON GET is unchanged for existing devices. The new client
    // downloads the same snapshot in short, independently readable chunks.
    // The numeric revision stays compatible with the existing KV schema.
    const payload = current.legacyPlain ? items : { v: 2, rev: current.rev, items };
    const url = new URL(request.url);
    if (url.searchParams.get("meta") === "1" || url.searchParams.has("chunk")) {
      const body = JSON.stringify(payload);
      if (url.searchParams.get("meta") === "1") {
        return json({ v: 3, total: body.length, revision: current.rev }, 200);
      }
      const rawOffset = url.searchParams.get("chunk");
      if (!/^(0|[1-9][0-9]*)$/.test(rawOffset || "")) {
        return json({ ok: false, error: "Invalid chunk offset" }, 400);
      }
      const offset = Number(rawOffset);
      if (!Number.isSafeInteger(offset) || offset >= body.length) {
        return json({ ok: false, error: "Chunk offset out of range" }, 416);
      }
      const nextOffset = Math.min(offset + 2048, body.length);
      return json({
        v: 3, offset, revision: current.rev, total: body.length,
        chunk: body.slice(offset, nextOffset),
        next: nextOffset < body.length ? nextOffset : null
      }, 200);
    }
    return json(payload, 200);
  }

  if (request.method === "POST") {
    const text = await request.text();
    if (text.length > MAX_BODY_CHARS) {
      return json({ ok: false, error: "Слишком большой запрос" }, 413);
    }
    let data;
    try {
      data = JSON.parse(text);
      validateEncryptedPayload(data);
    } catch (e) {
      return json({ ok: false, error: "Некорректные данные: " + String(e && e.message ? e.message : e) }, 400);
    }

    // Fresh (not edge-cached) read: this is the value being compared.
    const current = await loadBuffer(env, username);

    if (data.baseRevision === undefined) {
      // Old clients do not know about revisions. Keep the original guard for
      // them: never let a smaller snapshot replace a larger cloud buffer.
      if (current.items.length > data.items.length) {
        return json({
          ok: false,
          error: "Защита данных: неполная загрузка облака. Запись заблокирована.",
          revision: current.rev
        }, 409);
      }
    } else if (data.baseRevision !== current.rev) {
      return json({
        ok: false,
        conflict: true,
        error: "Облако изменилось на другом устройстве. Данные не перезаписаны.",
        revision: current.rev
      }, 409);
    }

    const revision = current.rev + 1;
    await saveBuffer(env, username, data.items, revision);
    return json({ ok: true, revision }, 200);
  }

  return json({ ok: false, error: "Method not allowed" }, 405);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: origin === ALLOWED_ORIGIN ? 204 : 403,
        headers: corsHeaders()
      });
    }

    const url = new URL(request.url);
    const isAuthPost = url.pathname.startsWith("/auth/") && request.method === "POST";

    try {
      if (isAuthPost && url.pathname !== "/auth/logout" && origin !== ALLOWED_ORIGIN) {
        return json({ ok: false, error: "Недопустимый источник запроса" }, 403);
      }

      if (url.pathname === "/auth/register" && request.method === "POST") {
        if (!env.USER_STORE) {
          return json({ ok: false, error: "Регистрация не настроена: USER_STORE отсутствует" }, 503);
        }
        if (!env.AUTH_SECRET) {
          return json({ ok: false, error: "Регистрация не настроена: AUTH_SECRET отсутствует" }, 503);
        }

        const data = await readJson(request);
        const username = String(data.username || "").trim();
        const password = String(data.password || "");

        if (!/^[A-Za-zА-Яа-яЁё0-9_.-]{3,32}$/.test(username)) {
          return json({ ok: false, error: "Логин: 3–32 символа, только буквы, цифры, _, -, ." }, 400);
        }
        if (password.length < 6 || password.length > MAX_PASSWORD_CHARS) {
          return json({ ok: false, error: "Пароль должен быть от 6 до 128 символов" }, 400);
        }
        if (await env.USER_STORE.get(userKey(username))) {
          return json({ ok: false, error: "Такой логин уже зарегистрирован" }, 409);
        }

        const salt = randomSalt();
        const hash = await hashPassword(password, salt);
        const cryptoBundle = validCryptoBundle(data.crypto) ? data.crypto : null;

        await env.USER_STORE.put(userKey(username), JSON.stringify({
          username,
          salt,
          hash,
          crypto: cryptoBundle,
          createdAt: Date.now()
        }));
        // New accounts have no legacy per-item records. This is an optional
        // optimization: marker failure must not leave registration half-failed.
        try {
          await env.USER_STORE.put(legacyMigrationMarkerKey(username), "1");
        } catch (e) {
          console.warn("Legacy marker creation failed for new account:", e);
        }

        const token = await createSession(username, env);
        return json({ ok: true, username, token, crypto: cryptoBundle, profile: null }, 201);
      }

      if (url.pathname === "/auth/login" && request.method === "POST") {
        if (!env.AUTH_SECRET) {
          return json({ ok: false, error: "Авторизация не настроена на сервере" }, 503);
        }
        if (!env.USER_STORE) {
          return json({ ok: false, error: "Авторизация не настроена на сервере" }, 503);
        }
        const data = await readJson(request);
        const username = String(data.username || "").trim();
        const password = String(data.password || "");

        if (username.length > 64 || password.length > MAX_PASSWORD_CHARS) {
          return json({ ok: false, error: "Неверный логин или пароль" }, 401);
        }

        const record = await readUserRecord(env, username);
        // Hash even for unknown users so response time does not reveal
        // which logins exist.
        const hash = await hashPassword(password, record ? record.salt : DUMMY_SALT);
        if (!record || !timingSafeEqual(hash, record.hash)) {
          return json({ ok: false, error: "Неверный логин или пароль" }, 401);
        }

        const canonical = record.username || username;
        const token = await createSession(canonical, env);
        return json({
          ok: true,
          username: canonical,
          token,
          crypto: record.crypto || null,
          profile: record.profile || null
        }, 200);
      }

      if (url.pathname === "/auth/password" && request.method === "POST") {
        const session = await verifySession(request, env);
        if (!session || !env.USER_STORE) {
          return json({ ok: false, error: "Unauthorized" }, 401);
        }

        const data = await readJson(request);
        const currentPassword = String(data.currentPassword || "");
        const newPassword = String(data.newPassword || "");

        if (newPassword.length < 6 || newPassword.length > MAX_PASSWORD_CHARS) {
          return json({ ok: false, error: "Новый пароль должен быть от 6 до 128 символов" }, 400);
        }
        if (!validCryptoBundle(data.crypto)) {
          return json({ ok: false, error: "Некорректные параметры шифрования" }, 400);
        }

        const record = await readUserRecord(env, session.username);
        if (!record) return json({ ok: false, error: "Пользователь не найден" }, 404);

        const currentHash = await hashPassword(currentPassword.slice(0, MAX_PASSWORD_CHARS), record.salt);
        if (!timingSafeEqual(currentHash, record.hash)) {
          return json({ ok: false, error: "Неверный текущий пароль" }, 401);
        }

        const salt = randomSalt();
        record.salt = salt;
        record.hash = await hashPassword(newPassword, salt);
        record.crypto = data.crypto;
        await env.USER_STORE.put(userKey(session.username), JSON.stringify(record));

        return json({ ok: true }, 200);
      }

      if (url.pathname === "/auth/crypto" && request.method === "POST") {
        const session = await verifySession(request, env);
        if (!session || !env.USER_STORE) {
          return json({ ok: false, error: "Unauthorized" }, 401);
        }

        const data = await readJson(request);
        if (!validCryptoBundle(data && data.crypto)) {
          return json({ ok: false, error: "Некорректные параметры шифрования" }, 400);
        }

        const record = await readUserRecord(env, session.username);
        if (!record) return json({ ok: false, error: "Пользователь не найден" }, 404);

        // The key bundle is created once. Replacing an existing one would make
        // the already encrypted buffer unreadable; password changes go through
        // /auth/password, which verifies the current password first.
        if (record.crypto) {
          return json({ ok: true, crypto: record.crypto }, 200);
        }
        record.crypto = data.crypto;
        await env.USER_STORE.put(userKey(session.username), JSON.stringify(record));

        return json({ ok: true, crypto: record.crypto }, 200);
      }

      // Profile data is separate from the E2EE clipboard: display name + small avatar.
      if (url.pathname === "/auth/profile" && request.method === "POST") {
        const session = await verifySession(request, env);
        if (!session || !env.USER_STORE) {
          return json({ ok: false, error: "Необходим вход в аккаунт" }, 401);
        }
        const data = await readJson(request);
        const displayName = String(data.displayName || "").trim();
        const avatar = data.avatar === null ? null : data.avatar;
        if (displayName.length < 1 || displayName.length > 40 || /[\u0000-\u001F\u007F]/.test(displayName)) {
          return json({ ok: false, error: "Имя должно содержать от 1 до 40 символов" }, 400);
        }
        if (avatar !== null && (typeof avatar !== "string" ||
            avatar.length > 90000 ||
            !/^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(avatar))) {
          return json({ ok: false, error: "Неверный формат или размер аватара" }, 400);
        }
        const record = await readUserRecord(env, session.username);
        if (!record) return json({ ok: false, error: "Аккаунт не найден" }, 404);
        record.profile = { displayName, avatar };
        await env.USER_STORE.put(userKey(session.username), JSON.stringify(record));
        return json({ ok: true, profile: record.profile }, 200);
      }

      if (url.pathname === "/auth/me" && request.method === "GET") {
        const session = await verifySession(request, env);
        if (!session) return json({ authenticated: false }, 401);
        const record = await readUserRecord(env, session.username);
        return json({
          authenticated: true,
          username: session.username,
          profile: record && record.profile ? record.profile : null,
          // Wrapped (password-encrypted) master key: needed to change the
          // password after a page refresh. It is also returned by /auth/login.
          crypto: record && record.crypto ? record.crypto : null
        }, 200);
      }

      if (url.pathname === "/auth/logout" && request.method === "POST") {
        // Sessions are stateless signed tokens: the client discards its token.
        return json({ ok: true }, 200);
      }

      if (url.pathname.startsWith("/auth/")) {
        return json({ ok: false, error: "Not found" }, 404);
      }

      const session = await verifySession(request, env);
      if (!session) {
        return json({ ok: false, error: "Unauthorized" }, 401);
      }
      if (!env.USER_STORE) {
        return json({ ok: false, error: "Хранилище не настроено" }, 503);
      }
      return await handleBuffer(request, env, session);
    } catch (e) {
      console.error("Request failed:", url.pathname, e);
      const status = e instanceof SyntaxError ? 400 : 500;
      return json({
        ok: false,
        error: status === 400 ? "Некорректный запрос" : "Внутренняя ошибка сервера"
      }, status);
    }
  }
};

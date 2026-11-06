const REPO = "tbushueff-tech/vibejira";
const FILE_PATH = "data/texts.json";
const API_BASE = "https://api.github.com/repos/" + REPO + "/contents/" + FILE_PATH;
const ALLOWED_ORIGIN = "https://tbushueff-tech.github.io";
const AUTO_DELETE_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// Force Cloudflare deployment after auth configuration update.

function corsHeaders(origin, request) {
  const headers = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Buffer-Key, Authorization",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };

  const requestedHeaders = request && request.headers.get("Access-Control-Request-Headers");
  if (requestedHeaders) headers["Access-Control-Allow-Headers"] = requestedHeaders;

  return headers;
}

function json(data, status, origin, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin),
      ...(extraHeaders || {})
    }
  });
}

async function githubFetch(url, options, env) {
  return fetch(url, {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "vibejira-buffer",
      "Authorization": "Bearer " + env.GITHUB_TOKEN,
      ...(options && options.headers ? options.headers : {})
    }
  });
}

function decodeFile(file) {
  const decoded = atob(file.content.replace(/\n/g, ""));
  const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

function encodeItems(items) {
  const bytes = new TextEncoder().encode(JSON.stringify(items, null, 2) + "\n");
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

async function readFile(env) {
  const res = await githubFetch(API_BASE + "?ref=main&t=" + Date.now(), {}, env);
  if (!res.ok) throw new Error("GitHub GET " + res.status);
  const file = await res.json();
  const items = decodeFile(file);
  if (!Array.isArray(items)) throw new Error("Stored data is not an array");
  return { file, items };
}

async function writeFile(items, sha, message, env) {
  const updateRes = await githubFetch(API_BASE, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message,
      content: encodeItems(items),
      sha,
      branch: "main"
    })
  }, env);

  if (!updateRes.ok) {
    const body = await updateRes.text();
    throw new Error("GitHub PUT " + updateRes.status + ": " + body);
  }
}

function bufferKey(username) {
  return "buffer:" + username.toLowerCase();
}

function bufferPrefix(username) {
  return bufferKey(username) + ":";
}

function validateEncryptedPayload(payload) {
  if (!payload || payload.v !== 2 || !Array.isArray(payload.items)) {
    throw new Error("Encrypted buffer required");
  }
  for (const item of payload.items) {
    if (!item || item.v !== 2 || typeof item.id !== "string" ||
        typeof item.expiresAt !== "number" ||
        typeof item.iv !== "string" || typeof item.ciphertext !== "string") {
      throw new Error("Invalid encrypted buffer item");
    }
  }
}

async function getLegacyPerItemBuffer(env, username) {
  const prefix = bufferPrefix(username);
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

function legacyMigrationMarkerKey(username) {
  // Permanent marker: when the main buffer expires, do not rescan old keys.
  return "legacy-migration:v2:" + username.toLowerCase();
}

async function getEncryptedUserBuffer(env, username) {
  const key = bufferKey(username);
  const raw = await env.USER_STORE.get(key, { cacheTtl: 30 });

  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.v === 2 && Array.isArray(parsed.items)) {
        return parsed;
      }
      // Legacy plaintext array. Frontend will immediately migrate it.
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      console.error("Invalid buffer:", key, e);
    }
  }

  // The legacy per-item scan must happen at most once per user, not on
  // every GET to an empty buffer (which happens every polling interval).
  const marker = legacyMigrationMarkerKey(username);
  if (await env.USER_STORE.get(marker)) {
    return { v: 2, items: [] };
  }

  const legacy = await getLegacyPerItemBuffer(env, username);
  if (legacy.items.length) {
    // Save the migrated data before setting the marker. On a failed write,
    // a later request can safely retry migration rather than lose records.
    const maxExpiresAt = Math.max(...legacy.items.map(item => item.expiresAt || 0));
    await env.USER_STORE.put(key, JSON.stringify(legacy), {
      expiration: Math.max(
        Math.floor(maxExpiresAt / 1000),
        Math.floor(Date.now() / 1000) + 60
      )
    });
  }
  // KV markers have no expiration; unlike buffers, they are not deleted by TTL.
  await env.USER_STORE.put(marker, "1");

  return legacy;
}

async function saveEncryptedUserBuffer(env, username, payload) {
  validateEncryptedPayload(payload);
  const key = bufferKey(username);

  if (payload.items.length === 0) {
    await env.USER_STORE.delete(key);
    return;
  }

  const maxExpiresAt = Math.max(...payload.items.map(item => item.expiresAt));
  const expiration = Math.max(
    Math.floor(maxExpiresAt / 1000),
    Math.floor(Date.now() / 1000) + 60
  );

  // One encrypted document per user: one read / one write, no list() on normal use.
  await env.USER_STORE.put(key, JSON.stringify(payload), { expiration });
}

function normalizeBuffer(items, now) {
  let changed = false;

  const normalized = items
    .map(item => {
      if (!item.expiresAt) {
        changed = true;
        return {
          ...item,
          expiresAt: item.createdAt
            ? item.createdAt + AUTO_DELETE_MS
            : now + AUTO_DELETE_MS
        };
      }
      return item;
    })
    .filter(item => {
      if (item.expiresAt <= now) {
        changed = true;
        return false;
      }
      return true;
    });

  return { normalized, changed };
}

async function cleanupExpiredBuffers(env) {
  if (!env.USER_STORE) return { changed: false, count: 0 };

  let cursor;
  let changed = false;
  let count = 0;

  do {
    const page = await env.USER_STORE.list({ prefix: "buffer:", cursor });
    for (const key of page.keys) {
      if (key.name.split(":").length >= 3) {
        count++;
        continue;
      }

      const raw = await env.USER_STORE.get(key.name);
      if (!raw) continue;
      try {
        const items = JSON.parse(raw);
        if (!Array.isArray(items)) continue;
        const result = normalizeBuffer(items, Date.now());
        if (result.changed) {
          await env.USER_STORE.put(key.name, JSON.stringify(result.normalized));
          changed = true;
        }
        count += result.normalized.length;
      } catch (e) {
        console.error("Invalid legacy buffer:", key.name, e);
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return { changed, count };
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

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return base64url(new Uint8Array(bits));
}

function randomSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return base64url(bytes);
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
  const payload = {
    username,
    exp: Date.now() + SESSION_TTL_MS
  };
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await hmacKey(env.AUTH_SECRET);
  const signature = base64url(new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body))
  ));
  return body + "." + signature;
}

async function verifySession(request, env) {
  if (!env.AUTH_SECRET) return null;

  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) {
    const token = auth.slice(7).trim();
    const parts = token.split(".");
    if (parts.length === 2) {
      try {
        const bodyBytes = base64urlDecode(parts[0]);
        const body = new TextDecoder().decode(bodyBytes);
        const payload = JSON.parse(body);
        if (!payload.username || !payload.exp || payload.exp <= Date.now()) return null;

        return hmacKey(env.AUTH_SECRET).then(async key => {
          const signature = base64urlDecode(parts[1]);
          const valid = await crypto.subtle.verify(
            "HMAC",
            key,
            signature,
            new TextEncoder().encode(parts[0])
          );
          return valid ? payload : null;
        });
      } catch (e) {
        return null;
      }
    }
  }

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)buffer_session=([^;]+)/);
  if (!match) return null;

  const token = match[1];
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  try {
    const bodyBytes = base64urlDecode(parts[0]);
    const body = new TextDecoder().decode(bodyBytes);
    const payload = JSON.parse(body);
    if (!payload.username || !payload.exp || payload.exp <= Date.now()) return null;

    const key = await hmacKey(env.AUTH_SECRET);
    const signature = base64urlDecode(parts[1]);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(parts[0])
    );
    return valid ? payload : null;
  } catch (e) {
    return null;
  }
}

function sessionCookie(token) {
  return "buffer_session=" + token +
    "; Max-Age=" + Math.floor(SESSION_TTL_MS / 1000) +
    "; Path=/; HttpOnly; Secure; SameSite=None; Partitioned";
}

function clearSessionCookie() {
  return "buffer_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None; Partitioned";
}

function checkKey(request, env) {
  const key = request.headers.get("X-Buffer-Key");
  return !!env.BUFFER_KEY && key === env.BUFFER_KEY;
}

export default {
  async scheduled() {
    // No KV scan is needed anymore. Buffer keys expire automatically in KV.
  },

  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      if (origin !== ALLOWED_ORIGIN) {
        return new Response(null, { status: 403, headers: corsHeaders(origin, request) });
      }
      return new Response(null, { status: 204, headers: corsHeaders(origin, request) });
    }

    const url = new URL(request.url);

    if (url.pathname === "/auth/register" && request.method === "POST") {
      try {
        if (origin !== ALLOWED_ORIGIN) {
          return json({ ok: false, error: "Недопустимый источник запроса" }, 403, origin);
        }
        if (!env.USER_STORE) {
          return json({ ok: false, error: "Регистрация не настроена: USER_STORE отсутствует" }, 503, origin);
        }
        if (!env.AUTH_SECRET) {
          return json({ ok: false, error: "Регистрация не настроена: AUTH_SECRET отсутствует" }, 503, origin);
        }

        const data = await request.json();
        const username = String(data.username || "").trim();
        const password = String(data.password || "");

        if (!/^[A-Za-zА-Яа-яЁё0-9_.-]{3,32}$/.test(username)) {
          return json({ ok: false, error: "Логин: 3–32 символа, только буквы, цифры, _, -, ." }, 400, origin);
        }
        if (password.length < 6 || password.length > 128) {
          return json({ ok: false, error: "Пароль должен быть от 6 до 128 символов" }, 400, origin);
        }

        const userKey = "user:" + username.toLowerCase();
        if (await env.USER_STORE.get(userKey)) {
          return json({ ok: false, error: "Такой логин уже зарегистрирован" }, 409, origin);
        }

        const salt = randomSalt();
        const hash = await hashPassword(password, salt);
        const cryptoBundle = data.crypto && typeof data.crypto === "object"
          ? data.crypto
          : null;

        await env.USER_STORE.put(userKey, JSON.stringify({
          username,
          salt,
          hash,
          crypto: cryptoBundle,
          createdAt: Date.now()
        }));
        // New accounts cannot have legacy per-item records. Skip scans entirely.
        await env.USER_STORE.put(legacyMigrationMarkerKey(username), "1");

        const token = await createSession(username, env);
        return json(
          { ok: true, username, token, crypto: cryptoBundle },
          201,
          origin
        );
      } catch (e) {
        console.error("Registration failed:", e);
        return json({ ok: false, error: "Не удалось создать аккаунт: " + String(e && e.message ? e.message : e) }, 500, origin);
      }
    }

    if (url.pathname === "/auth/login" && request.method === "POST") {
      try {
        if (origin !== ALLOWED_ORIGIN) {
          return json({ ok: false, error: "Недопустимый источник запроса" }, 403, origin);
        }
        const data = await request.json();
        const username = String(data.username || "");
        const password = String(data.password || "");

        if (!env.AUTH_SECRET) {
          return json({ ok: false, error: "Авторизация не настроена на сервере" }, 503, origin);
        }

        let valid = false;
        let cryptoBundle = null;
        let profile = null;
        if (env.USER_STORE) {
          const recordRaw = await env.USER_STORE.get("user:" + username.toLowerCase());
          if (recordRaw) {
            const record = JSON.parse(recordRaw);
            const hash = await hashPassword(password, record.salt);
            valid = hash === record.hash;
            cryptoBundle = record.crypto || null;
            if (valid) profile = record.profile || null;
          }
        }

        if (!valid && env.AUTH_USER && env.AUTH_PASSWORD) {
          valid = username === env.AUTH_USER && password === env.AUTH_PASSWORD;
        }

        if (!valid) {
          return json({ ok: false, error: "Неверный логин или пароль" }, 401, origin);
        }

        const token = await createSession(username, env);
        return json(
          { ok: true, username, token, crypto: cryptoBundle },
          200,
          origin
        );
      } catch (e) {
        return json({ ok: false, error: "Некорректный запрос" }, 400, origin);
      }
    }

    if (url.pathname === "/auth/password" && request.method === "POST") {
      try {
        if (origin !== ALLOWED_ORIGIN) {
          return json({ ok: false, error: "Недопустимый источник запроса" }, 403, origin);
        }
        const session = await verifySession(request, env);
        if (!session || !env.USER_STORE) {
          return json({ ok: false, error: "Unauthorized" }, 401, origin);
        }

        const data = await request.json();
        const currentPassword = String(data.currentPassword || "");
        const newPassword = String(data.newPassword || "");
        const cryptoBundle = data && data.crypto;

        if (newPassword.length < 6 || newPassword.length > 128) {
          return json({ ok: false, error: "Новый пароль должен быть от 6 до 128 символов" }, 400, origin);
        }
        if (!cryptoBundle || cryptoBundle.v !== 1 ||
            typeof cryptoBundle.salt !== "string" ||
            typeof cryptoBundle.iv !== "string" ||
            typeof cryptoBundle.wrappedKey !== "string") {
          return json({ ok: false, error: "Некорректные параметры шифрования" }, 400, origin);
        }

        const userKey = "user:" + String(session.username).toLowerCase();
        const raw = await env.USER_STORE.get(userKey);
        if (!raw) return json({ ok: false, error: "Пользователь не найден" }, 404, origin);

        const record = JSON.parse(raw);
        const currentHash = await hashPassword(currentPassword, record.salt);
        if (currentHash !== record.hash) {
          return json({ ok: false, error: "Неверный текущий пароль" }, 401, origin);
        }

        const salt = randomSalt();
        const hash = await hashPassword(newPassword, salt);
        record.salt = salt;
        record.hash = hash;
        record.crypto = cryptoBundle;
        await env.USER_STORE.put(userKey, JSON.stringify(record));

        return json({ ok: true }, 200, origin);
      } catch (e) {
        console.error("Password change failed:", e);
        return json({ ok: false, error: "Не удалось сменить пароль" }, 500, origin);
      }
    }

    if (url.pathname === "/auth/crypto" && request.method === "POST") {
      try {
        if (origin !== ALLOWED_ORIGIN) {
          return json({ ok: false, error: "Недопустимый источник запроса" }, 403, origin);
        }
        const session = await verifySession(request, env);
        if (!session || !env.USER_STORE) {
          return json({ ok: false, error: "Unauthorized" }, 401, origin);
        }

        const data = await request.json();
        const cryptoBundle = data && data.crypto;
        if (!cryptoBundle || cryptoBundle.v !== 1 ||
            typeof cryptoBundle.salt !== "string" ||
            typeof cryptoBundle.iv !== "string" ||
            typeof cryptoBundle.wrappedKey !== "string") {
          return json({ ok: false, error: "Некорректные параметры шифрования" }, 400, origin);
        }

        const userKey = "user:" + String(session.username).toLowerCase();
        const raw = await env.USER_STORE.get(userKey);
        if (!raw) return json({ ok: false, error: "Пользователь не найден" }, 404, origin);

        const record = JSON.parse(raw);
        record.crypto = cryptoBundle;
        await env.USER_STORE.put(userKey, JSON.stringify(record));

        return json({ ok: true, crypto: cryptoBundle }, 200, origin);
      } catch (e) {
        console.error("Crypto setup failed:", e);
        return json({ ok: false, error: "Не удалось сохранить настройки шифрования" }, 500, origin);
      }
    }

    // Profile data is separate from the E2EE clipboard: display name + small avatar.
    if (url.pathname === "/auth/profile" && request.method === "POST") {
      try {
        if (origin !== ALLOWED_ORIGIN) {
          return json({ ok: false, error: "Недопустимый источник запроса" }, 403, origin);
        }
        const session = await verifySession(request, env);
        if (!session || !env.USER_STORE) {
          return json({ ok: false, error: "Необходим вход в аккаунт" }, 401, origin);
        }
        const data = await request.json();
        const displayName = String(data.displayName || "").trim();
        const avatar = data.avatar === null ? null : data.avatar;
        if (displayName.length < 1 || displayName.length > 40 || /[\u0000-\u001F\u007F]/.test(displayName)) {
          return json({ ok: false, error: "Имя должно содержать от 1 до 40 символов" }, 400, origin);
        }
        if (avatar !== null && (typeof avatar !== "string" ||
            avatar.length > 90000 ||
            !/^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(avatar))) {
          return json({ ok: false, error: "Неверный формат или размер аватара" }, 400, origin);
        }
        const key = "user:" + String(session.username).toLowerCase();
        const raw = await env.USER_STORE.get(key);
        if (!raw) return json({ ok: false, error: "Аккаунт не найден" }, 404, origin);
        const record = JSON.parse(raw);
        record.profile = { displayName, avatar };
        await env.USER_STORE.put(key, JSON.stringify(record));
        return json({ ok: true, profile: record.profile }, 200, origin);
      } catch (e) {
        console.error("Profile update failed:", e);
        return json({ ok: false, error: "Не удалось сохранить профиль" }, 500, origin);
      }
    }

    if (url.pathname === "/auth/me" && request.method === "GET") {
      const session = await verifySession(request, env);
      if (!session) return json({ authenticated: false }, 401, origin);
      const raw = env.USER_STORE
        ? await env.USER_STORE.get("user:" + String(session.username).toLowerCase())
        : null;
      const record = raw ? JSON.parse(raw) : null;
      return json({
        authenticated: true,
        username: session.username,
        profile: record && record.profile ? record.profile : null
      }, 200, origin);
    }

    if (url.pathname === "/auth/logout" && request.method === "POST") {
      return json(
        { ok: true },
        200,
        origin,
        { "Set-Cookie": clearSessionCookie() }
      );
    }

    const session = await verifySession(request, env);
    if (!session) {
      return json({ ok: false, error: "Unauthorized" }, 401, origin);
    }

    if (!checkKey(request, env)) {
      return json({ ok: false, error: "Unauthorized" }, 401, origin);
    }

    try {
      const username = session.username;
      const now = Date.now();

      if (request.method === "GET") {
        const encrypted = await getEncryptedUserBuffer(env, username);
        return json(encrypted, 200, origin);
      }

      if (request.method === "POST") {
        const data = await request.json();
        try {
          validateEncryptedPayload(data);
        } catch (e) {
          return json({ ok: false, error: String(e.message || e) }, 400, origin);
        }
        await saveEncryptedUserBuffer(env, username, data);
        return json({ ok: true }, 200, origin);
      }

      return json({ ok: false, error: "Method not allowed" }, 405, origin);
    } catch (e) {
      return json(
        { ok: false, error: String(e && e.message ? e.message : e) },
        500,
        origin
      );
    }
  }
};

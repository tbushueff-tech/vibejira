const REPO = "tbushueff-tech/vibejira";
const FILE_PATH = "data/texts.json";
const API_BASE = "https://api.github.com/repos/" + REPO + "/contents/" + FILE_PATH;
const ALLOWED_ORIGIN = "https://tbushueff-tech.github.io";
const AUTO_DELETE_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function corsHeaders(origin, request) {
  const headers = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Buffer-Key",
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
      ...corsHeaders(origin, request),
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

async function cleanupExpired(env) {
  const { file, items } = await readFile(env);
  const now = Date.now();
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

  if (changed) {
    await writeFile(normalized, file.sha, "Auto-clean text buffer", env);
  }

  return { changed, count: normalized.length };
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
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 120000, hash: "SHA-256" },
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
    "; Path=/; HttpOnly; Secure; SameSite=None";
}

function clearSessionCookie() {
  return "buffer_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None";
}

function checkKey(request, env) {
  const key = request.headers.get("X-Buffer-Key");
  return !!env.BUFFER_KEY && key === env.BUFFER_KEY;
}

export default {
  async scheduled(controller, env) {
    try {
      const result = await cleanupExpired(env);
      console.log("Auto-clean:", controller.cron, result);
    } catch (e) {
      console.error("Auto-clean failed:", e);
      throw e;
    }
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
        await env.USER_STORE.put(userKey, JSON.stringify({
          username,
          salt,
          hash,
          createdAt: Date.now()
        }));

        const token = await createSession(username, env);
        return json(
          { ok: true, username },
          201,
          origin,
          { "Set-Cookie": sessionCookie(token) }
        );
      } catch (e) {
        console.error("Registration failed:", e);
        return json({ ok: false, error: "Не удалось создать аккаунт" }, 500, origin);
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
        if (env.USER_STORE) {
          const recordRaw = await env.USER_STORE.get("user:" + username.toLowerCase());
          if (recordRaw) {
            const record = JSON.parse(recordRaw);
            const hash = await hashPassword(password, record.salt);
            valid = hash === record.hash;
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
          { ok: true, username },
          200,
          origin,
          { "Set-Cookie": sessionCookie(token) }
        );
      } catch (e) {
        return json({ ok: false, error: "Некорректный запрос" }, 400, origin);
      }
    }

    if (url.pathname === "/auth/me" && request.method === "GET") {
      const session = await verifySession(request, env);
      if (!session) return json({ authenticated: false }, 401, origin);
      return json({ authenticated: true, username: session.username }, 200, origin);
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
      if (request.method === "GET") {
        const { file, items } = await readFile(env);
        const now = Date.now();
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

        if (changed) await writeFile(normalized, file.sha, "Auto-clean text buffer", env);

        return new Response(JSON.stringify(normalized), {
          status: 200,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            ...corsHeaders(origin, request)
          }
        });
      }

      if (request.method === "POST") {
        const data = await request.json();
        if (!Array.isArray(data)) {
          return json({ ok: false, error: "Body must be an array" }, 400, origin);
        }

        const current = await readFile(env);
        const existingById = new Map(
          current.items.map(item => [item.id, item])
        );
        const now = Date.now();

        const normalized = data.map(item => {
          if (item.expiresAt) return item;

          const old = existingById.get(item.id);
          if (old && old.expiresAt) {
            return { ...item, expiresAt: old.expiresAt };
          }

          return {
            ...item,
            expiresAt: item.createdAt
              ? item.createdAt + AUTO_DELETE_MS
              : now + AUTO_DELETE_MS
          };
        });

        await writeFile(normalized, current.file.sha, "Update text buffer", env);
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

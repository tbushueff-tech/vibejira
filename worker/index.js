const REPO = "tbushueff-tech/vibejira";
const FILE_PATH = "data/texts.json";
const API_BASE = "https://api.github.com/repos/" + REPO + "/contents/" + FILE_PATH;
const ALLOWED_ORIGIN = "https://tbushueff-tech.github.io";
const AUTO_DELETE_MS = 5 * 60 * 1000;

function corsHeaders(origin) {
  const allowed = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Buffer-Key",
    "Cache-Control": "no-store"
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin)
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
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
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
            ...corsHeaders(origin)
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

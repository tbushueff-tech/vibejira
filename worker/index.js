const REPO = "tbushueff-tech/vibejira";
const FILE_PATH = "data/texts.json";
const API_BASE = "https://api.github.com/repos/" + REPO + "/contents/" + FILE_PATH;
const ALLOWED_ORIGIN = "https://tbushueff-tech.github.io";

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

function checkKey(request, env) {
  const key = request.headers.get("X-Buffer-Key");
  return !!env.BUFFER_KEY && key === env.BUFFER_KEY;
}

export default {
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
        const res = await githubFetch(API_BASE + "?ref=main&t=" + Date.now(), {}, env);
        const body = await res.text();
        if (!res.ok) return json({ ok: false, error: "GitHub GET " + res.status, details: body }, res.status, origin);

        const file = JSON.parse(body);
        const decoded = atob(file.content.replace(/\n/g, ""));
        const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
        const data = new TextDecoder().decode(bytes);

        return new Response(data, {
          status: 200,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            ...corsHeaders(origin)
          }
        });
      }

      if (request.method === "POST") {
        const data = await request.json();
        if (!Array.isArray(data)) return json({ ok: false, error: "Body must be an array" }, 400, origin);

        const currentRes = await githubFetch(API_BASE + "?ref=main&t=" + Date.now(), {}, env);
        const currentBody = await currentRes.text();
        if (!currentRes.ok) return json({ ok: false, error: "GitHub GET " + currentRes.status, details: currentBody }, currentRes.status, origin);

        const current = JSON.parse(currentBody);
        const bytes = new TextEncoder().encode(JSON.stringify(data, null, 2) + "\n");
        let binary = "";
        for (let i = 0; i < bytes.length; i += 0x8000) {
          binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        }

        const updateRes = await githubFetch(API_BASE, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            message: "Update text buffer",
            content: btoa(binary),
            sha: current.sha,
            branch: "main"
          })
        }, env);

        const updateBody = await updateRes.text();
        if (!updateRes.ok) return json({ ok: false, error: "GitHub PUT " + updateRes.status, details: updateBody }, updateRes.status, origin);

        return json({ ok: true }, 200, origin);
      }

      return json({ ok: false, error: "Method not allowed" }, 405, origin);
    } catch (e) {
      return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500, origin);
    }
  }
};
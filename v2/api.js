// Jira Helper V2 — one Cloudflare endpoint, no anonymous reachability probes.
// All requests are authenticated using the signed bearer token.
export const API_ORIGIN = "https://vibejira.t-bushueff.workers.dev";

export class ApiError extends Error {
  constructor(message, status = 0) { super(message); this.name = "ApiError"; this.status = status; }
}

function timeoutController(ms, signal) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Тайм-аут соединения")), ms);
  const abort = () => controller.abort(signal.reason);
  if (signal) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  return { controller, finish() { clearTimeout(timer); signal?.removeEventListener("abort", abort); } };
}

export class CloudApi {
  constructor() { this.token = ""; }
  setToken(token) { this.token = token || ""; }

  async request(path, { method = "GET", data, signal, timeoutMs = 30000 } = {}) {
    const timer = timeoutController(timeoutMs, signal);
    try {
      const headers = { Accept: "application/json" };
      if (this.token) headers.Authorization = "Bearer " + this.token;
      if (data !== undefined) headers["Content-Type"] = "text/plain;charset=UTF-8";
      const response = await fetch(API_ORIGIN + path, {
        method, headers, body: data === undefined ? undefined : JSON.stringify(data),
        credentials: "omit", cache: "no-store", signal: timer.controller.signal
      });
      const body = await response.text(); // includes download inside the timeout
      let parsed;
      try { parsed = body ? JSON.parse(body) : {}; }
      catch { throw new ApiError("Сервер прислал некорректный JSON", response.status); }
      if (!response.ok) throw new ApiError(parsed.error || "Cloudflare HTTP " + response.status, response.status);
      return parsed;
    } catch (error) {
      if (timer.controller.signal.aborted) throw new ApiError("Превышено время ожидания Cloudflare");
      if (error instanceof ApiError) throw error;
      throw new ApiError("Ошибка связи с Cloudflare: " + (error.message || String(error)));
    } finally {
      timer.finish();
    }
  }

  login(username, password) { return this.request("/auth/login", { method: "POST", data: { username, password }, timeoutMs: 45000 }); }
  register(username, password, crypto) { return this.request("/auth/register", { method: "POST", data: { username, password, crypto }, timeoutMs: 45000 }); }
  me() { return this.request("/auth/me"); }
  logout() { return this.request("/auth/logout", { method: "POST" }); }
  saveCrypto(crypto) { return this.request("/auth/crypto", { method: "POST", data: { crypto } }); }
  changePassword(currentPassword, newPassword, crypto) {
    return this.request("/auth/password", { method: "POST", data: { currentPassword, newPassword, crypto } });
  }
  saveProfile(displayName, avatar) { return this.request("/auth/profile", { method: "POST", data: { displayName, avatar } }); }

  async readBuffer({ signal, onProgress = () => {} } = {}) {
    // Worker retains the original v2 encrypted JSON in KV, but exposes a
    // read-only chunk view. Every chunk is small enough for restrictive proxies.
    for (let attempt = 1; attempt <= 3; attempt++) {
      const meta = await this.request("/?meta=1", { signal });
      if (meta.v !== 3 || !Number.isSafeInteger(meta.total) || meta.total < 0 ||
          meta.total > 32 * 1024 * 1024 || !Number.isSafeInteger(meta.revision) || meta.revision < 0) {
        throw new ApiError("Некорректный размер или версия облачного буфера");
      }
      let offset = 0;
      const result = [];
      let inconsistent = false;
      while (offset < meta.total) {
        const chunk = await this.request("/?chunk=" + offset, { signal });
        if (chunk.v !== 3 || chunk.revision !== meta.revision ||
            chunk.total !== meta.total || chunk.offset !== offset ||
            typeof chunk.chunk !== "string" || !chunk.chunk.length ||
            chunk.chunk.length > 2048) {
          inconsistent = true; break;
        }
        result.push(chunk.chunk);
        offset += chunk.chunk.length;
        onProgress(offset, meta.total);
      }
      if (inconsistent) continue; // KV changed while reading; retry from beginning
      if (offset !== meta.total) throw new ApiError("Ответ облака получен не полностью");
      let envelope;
      try { envelope = JSON.parse(result.join("")); }
      catch { throw new ApiError("Повреждённый JSON облачного буфера"); }
      if (!Array.isArray(envelope) && !(envelope && envelope.v === 2 && Array.isArray(envelope.items))) {
        throw new ApiError("Неподдерживаемый формат облачного буфера");
      }
      return { envelope, revision: meta.revision };
    }
    throw new ApiError("Облако менялось во время загрузки — повторите чтение");
  }

  async listLibrary() {
    const all = [];
    let cursor = null;
    let pages = 0;
    do {
      if (++pages > 250) throw new ApiError("Библиотека слишком большая для загрузки");
      const path = "/library" + (cursor ? "?cursor=" + encodeURIComponent(cursor) : "");
      const response = await this.request(path, { timeoutMs: 45000 });
      if (!Array.isArray(response.items)) throw new ApiError("Неверный ответ библиотеки");
      all.push(...response.items);
      if (all.length > 10000) throw new ApiError("Превышен лимит элементов библиотеки");
      cursor = response.nextCursor || null;
    } while (cursor);
    return all;
  }

  saveLibraryItem(encrypted) {
    return this.request("/library", { method: "POST", data: encrypted, timeoutMs: 45000 });
  }

  deleteLibraryItem(id, revision) {
    return this.request("/library/" + encodeURIComponent(id) + "?revision=" + revision,
      { method: "DELETE" });
  }

  writeBuffer(envelope, baseRevision) {
    if (!envelope || envelope.v !== 2 || !Array.isArray(envelope.items))
      throw new ApiError("Отправка неполного буфера запрещена");
    if (!Number.isSafeInteger(baseRevision) || baseRevision < 0)
      throw new ApiError("Запись без подтверждённой версии облака запрещена");
    // Existing production Worker validates numeric baseRevision and returns revision.
    return this.request("/", {
      method: "POST", data: { ...envelope, baseRevision }, timeoutMs: 90000
    });
  }
}

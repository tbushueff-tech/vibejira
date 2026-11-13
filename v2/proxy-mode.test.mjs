import test from "node:test";
import assert from "node:assert/strict";
import { CloudApi, API_ORIGIN, PROXY_ORIGIN, ApiError } from "./api.js";

test("direct Cloudflare is the default, manual proxy is opt-in", () => {
  const api = new CloudApi();
  assert.equal(api.useProxy, false);
  assert.equal(api.endpoint("/auth/me"), API_ORIGIN + "/auth/me");
  api.setProxyMode(true);
  assert.equal(api.endpoint("/auth/me"), PROXY_ORIGIN + "?route=%2Fauth%2Fme");
  assert.equal(api.endpoint("/?meta=1"), PROXY_ORIGIN + "?route=%2F&meta=1");
  assert.equal(api.endpoint("/?chunk=2048"), PROXY_ORIGIN + "?route=%2F&chunk=2048");
  assert.equal(api.endpoint("/library?cursor=abcd"), PROXY_ORIGIN + "?route=%2Flibrary&cursor=abcd");
  assert.equal(api.endpoint("/library/abc_123?revision=2"), PROXY_ORIGIN + "?route=%2Flibrary%2Fabc_123&revision=2");
  api.setProxyMode(false);
  assert.equal(api.endpoint("/auth/login"), API_ORIGIN + "/auth/login");
});

test("proxy mode routes credentials, bearer auth and library calls through selected endpoint", async () => {
  const oldFetch = globalThis.fetch, urls = [];
  globalThis.fetch = async (url, options) => {
    urls.push({url: String(url), method: options.method, headers: options.headers, body: options.body});
    return new Response(JSON.stringify({ok:true}), {status:200, headers:{"Content-Type":"application/json"}});
  };
  try {
    const api = new CloudApi({useProxy:true});
    api.setToken("example-token");
    await api.login("testuser", "pass123456");
    await api.listLibrary();
    await api.saveLibraryItem({v:2,id:"id_1",iv:"0123456789",ciphertext:"encrypted-data",revision:0});
    await api.deleteLibraryItem("id_1",2);
    assert.equal(urls.length, 4);
    assert.ok(urls.every(call => call.url.startsWith(PROXY_ORIGIN + "?route=")));
    assert.ok(urls.every(call => call.headers.Authorization === "Bearer example-token"));
    assert.match(urls[0].url, /route=%2Fauth%2Flogin/);
    assert.match(urls[1].url, /route=%2Flibrary$/);
    assert.equal(urls[3].method, "DELETE");
    assert.match(urls[3].url, /revision=2/);
    api.setProxyMode(false);
    await api.me();
    assert.equal(urls[4].url, API_ORIGIN + "/auth/me");
  } finally { globalThis.fetch = oldFetch; }
});

test("proxy failures never fall back to Cloudflare silently", async () => {
  const oldFetch = globalThis.fetch, urls = [];
  globalThis.fetch = async url => { urls.push(String(url)); throw new Error("offline"); };
  try {
    const api = new CloudApi({useProxy:true});
    await assert.rejects(() => api.me(), e => e instanceof ApiError && /российского прокси/.test(e.message));
    assert.equal(urls.length,1);
    assert.ok(urls[0].startsWith(PROXY_ORIGIN));
  } finally { globalThis.fetch = oldFetch; }
});

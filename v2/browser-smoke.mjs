// Browser smoke test for the NEW V2 frontend; no production API or KV access.
import assert from "node:assert/strict";
import { chromium } from "playwright";

const origin = "http://127.0.0.1:8099";
const apiOrigin = "https://vibejira.t-bushueff.workers.dev";
let encrypted = { v: 2, items: [] };
let signedToken = "browser-test-token";
let cloudRevision = 0;
let bundle = null;

function revision(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i); hash = Math.imul(hash, 16777619);
  }
  return text.length.toString(36) + "-" + (hash >>> 0).toString(36);
}
const cors = {
  "access-control-allow-origin": origin,
  "access-control-allow-headers": "Authorization, Content-Type, Accept",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "content-type": "application/json"
};

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const failures = [];
page.on("pageerror", err => failures.push(err.message));
await page.route(apiOrigin + "/**", async route => {
  const request = route.request(), url = new URL(request.url());
  if (request.method() === "OPTIONS") {
    return route.fulfill({ status: 204, headers: cors, body: "" });
  }
  const pathname = url.pathname;
  const body = request.postDataJSON() || {};
  const authorized = request.headers().authorization === "Bearer " + signedToken;
  let status = 200, response = {};
  if (pathname === "/auth/register") {
    bundle = body.crypto;
    response = { ok: true, username: body.username, token: signedToken, crypto: bundle };
  } else if (pathname === "/auth/me") {
    status = authorized ? 200 : 401;
    response = authorized ? { authenticated: true, username: "smoketest", profile: null } : { authenticated: false };
  } else if (pathname === "/auth/crypto") {
    bundle = body.crypto; response = { ok: true, crypto: bundle };
  } else if (pathname === "/auth/login") {
    response = { ok: true, username: body.username, token: signedToken, crypto: bundle, profile: null };
  } else if (!authorized) {
    status = 401; response = { ok: false, error: "Unauthorized" };
  } else if (pathname === "/" && request.method() === "POST") {
    const now = cloudRevision;
    if (body.baseRevision !== now) {
      status = 409; response = { error: "Stale snapshot" };
    } else {
      encrypted = { v: 2, items: body.items };
      cloudRevision++;
      response = { ok: true, revision: cloudRevision };
    }
  } else if (pathname === "/" && url.searchParams.get("meta") === "1") {
    const text = JSON.stringify(encrypted);
    response = { v: 3, revision: cloudRevision, total: text.length };
  } else if (pathname === "/" && url.searchParams.has("chunk")) {
    const text = JSON.stringify(encrypted);
    const offset = Number(url.searchParams.get("chunk"));
    const end = Math.min(text.length, offset + 2048);
    response = { v: 3, revision: cloudRevision, offset, total: text.length,
      chunk: text.slice(offset, end), next: end < text.length ? end : null };
  } else {
    status = 404; response = { error: "Unknown request" };
  }
  await route.fulfill({ status, headers: cors, body: JSON.stringify(response) });
});

try {
  await page.goto(origin + "/");
  await page.getByRole("button", { name: "Регистрация", exact: true }).click();
  await page.locator("#login-user").fill("smoketest");
  await page.locator("#login-password").fill("testing-password");
  await page.locator("#login-form").evaluate(form => form.requestSubmit());
  await page.getByText("Синхронизировано через Cloudflare").waitFor({ timeout: 30000 });

  await page.locator("#title").fill("Browser reload regression");
  await page.locator("#body").fill("Запись должна пережить обновление страницы");
  await page.locator("#composer").evaluate(form => form.requestSubmit());
  await page.getByText("Синхронизировано через Cloudflare").waitFor({ timeout: 30000 });
  assert.equal(encrypted.items.length, 1, "Cloudflare mock must receive ciphertext");

  await page.reload();
  await page.getByText("Синхронизировано через Cloudflare").waitFor({ timeout: 30000 });
  await page.getByText("Browser reload regression").waitFor({ timeout: 10000 });
  assert.equal(encrypted.items.length, 1);
  await page.locator("#search").fill("Browser reload");
  await page.getByText("Browser reload regression").waitFor();
  assert.deepEqual(failures, []);
  console.log("V2 browser smoke: register, write, reload, decrypt and search passed");
} finally {
  await browser.close();
}

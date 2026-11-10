// Browser smoke test for the NEW V2 frontend; no production API or KV access.
import assert from "node:assert/strict";
import { chromium } from "playwright";

const origin = "http://127.0.0.1:8099";
const apiOrigin = "https://vibejira.t-bushueff.workers.dev";
let encrypted = { v: 2, items: [] };
let signedToken = "browser-test-token";
let cloudRevision = 0;
const libraryRecords = new Map();
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
  } else if (pathname === "/library" && request.method() === "GET") {
    response = { ok: true, items: [...libraryRecords.keys()].map(id => ({id})), nextCursor: null };
  } else if (pathname === "/library" && request.method() === "POST") {
    const old = libraryRecords.get(body.id);
    const rev = old?.revision || 0;
    if (body.revision !== rev) {
      status = 409; response = { error: "stale library item" };
    } else {
      const record = {...body, revision: rev + 1};
      libraryRecords.set(body.id, record);
      response = { ok: true, revision: record.revision };
    }
  } else if (pathname.startsWith("/library/")) {
    const id = decodeURIComponent(pathname.slice("/library/".length));
    const entry = libraryRecords.get(id);
    if (!entry) {
      status = 404; response = { error: "missing library item" };
    } else if (request.method() === "DELETE") {
      if (Number(url.searchParams.get("revision")) !== entry.revision) {
        status = 409; response = { error: "conflict" };
      } else {
        libraryRecords.delete(id); response = { ok: true };
      }
    } else {
      const text = JSON.stringify(entry);
      if (url.searchParams.get("meta") === "1") {
        response = { v: 3, total: text.length, revision: entry.revision };
      } else {
        const at = Number(url.searchParams.get("chunk"));
        const end = Math.min(at + 2048, text.length);
        response = { v: 3, offset: at, total: text.length, revision: entry.revision,
          chunk: text.slice(at, end), next: end < text.length ? end : null };
      }
    }
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
  await page.locator("#search").fill("");
  await page.getByRole("button", { name: "☆ В библиотеку" }).first().click();
  await page.getByText("Код сохранён в постоянной библиотеке").waitFor();
  assert.equal(libraryRecords.size, 1, "Library must contain a permanent encrypted entry");
  assert.ok(!JSON.stringify([...libraryRecords.values()]).includes("Запись должна"),
    "Plaintext must not be stored in Cloudflare");
  assert.equal(encrypted.items.length, 1, "Clipboard must remain unchanged");
  await page.reload();
  await page.getByText("Синхронизировано через Cloudflare").waitFor({timeout:30000});
  await page.locator("#tab-library").click();
  await page.getByText("Библиотека синхронизирована", {exact:false}).waitFor({timeout:30000});
  await page.locator("#library-list").getByText("Browser reload regression").waitFor();
  await page.locator("#library-list").getByRole("button",{name:"Изменить"}).click();
  await page.locator("#library-notes").fill("Проверенный фрагмент");
  await page.locator("#library-form").evaluate(form => form.requestSubmit());
  await page.getByText("Код сохранён в постоянной библиотеке").waitFor();
  assert.equal(libraryRecords.size,1);
  assert.equal(encrypted.items.length,1);
  await page.reload();
  await page.locator("#tab-library").click();
  await page.getByText("Библиотека синхронизирована", {exact:false}).waitFor({timeout:30000});
  await page.locator("#library-list").getByText("Проверенный фрагмент").waitFor();
  await page.locator("#tab-buffer").click();
  await page.locator("#list").getByText("Browser reload regression").waitFor();
  await page.locator("#tab-demo-keygen").click();
  assert.equal(await page.locator("#demo-server-id").count(), 0, "Fixed Server ID must be hidden");
  assert.equal(await page.locator("#demo-organisation").inputValue(), "");
  assert.equal(await page.locator("#demo-product").inputValue(), "");
  assert.equal(await page.locator("#demo-email").evaluate(node => getComputedStyle(node).width),
    await page.locator("#demo-organisation").evaluate(node => getComputedStyle(node).width),
    "Email and Organisation inputs must have matching widths");
  await page.locator("#demo-email").fill("test@example.com");
  await page.locator("#demo-organisation").fill("Demo Organisation");
  await page.locator("#demo-product").fill("custom_plugin");
  await page.locator("#demo-name").fill("Demo User");
  await page.locator("#demo-datacenter").check();
  await page.locator("#demo-keygen-form").evaluate(form => form.requestSubmit());
  await page.locator("#demo-keygen-result").waitFor({state:"visible",timeout:15000});
  const keyText = await page.locator("#demo-key-output").inputValue();
  assert.ok(keyText.replace(/\s/g,"").includes("X02"), "demo output must include X02 format footer");
  assert.ok(keyText.length > 70, "demo output must contain a packed license payload");
  assert.match(await page.locator("#demo-properties-output").textContent(), /DemoProduct=custom_plugin/);
  assert.match(await page.locator("#demo-properties-output").textContent(), /ServerID=BLSA-YKF4-X270-D26O/);
  await page.locator("#tab-buffer").click();
  await page.locator("#list").getByText("Browser reload regression").waitFor();
  assert.deepEqual(failures, []);
  console.log("Browser smoke: clipboard, library and demo key generator passed");
} finally {
  await browser.close();
}

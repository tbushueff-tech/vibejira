import assert from "node:assert/strict";
import { chromium } from "playwright";
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const seen = [];
const origin = "http://127.0.0.1:8099";
const direct = "https://vibejira.t-bushueff.workers.dev";
const proxy = "https://tbhelper.h1n.ru";
try {
  for (const target of [direct, proxy]) {
    await page.route(target + "/**", async route => {
      const request = route.request();
      seen.push(request.url());
      const headers = {
        "access-control-allow-origin": origin,
        "access-control-allow-headers": "Authorization, Content-Type",
        "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
        "content-type": "application/json"
      };
      if (request.method() === "OPTIONS")
        await route.fulfill({status:204,headers,body:""});
      else
        await route.fulfill({status:401,headers,body:JSON.stringify({error:"Test login rejected"})});
    });
  }
  await page.goto(origin);
  const checkbox = page.locator("#login-russian-proxy");
  await checkbox.waitFor();
  assert.equal(await checkbox.isChecked(), false);
  assert.match(await page.locator("#login-proxy-route").textContent(), /напрямую · Cloudflare/);
  await page.locator("#login-user").fill("testuser");
  await page.locator("#login-password").fill("pass123456");
  await page.locator("#login-form").evaluate(form => form.requestSubmit());
  await page.waitForFunction(() => document.querySelector("#login-error")?.textContent.includes("Test login rejected"));
  assert.ok(seen.some(url => url.startsWith(direct + "/auth/login")));
  assert.ok(!seen.some(url => url.startsWith(proxy)));
  seen.length = 0;
  await checkbox.check();
  assert.match(await page.locator("#login-proxy-route").textContent(), /HostiMan · Россия/);
  await page.locator("#login-form").evaluate(form => form.requestSubmit());
  await page.waitForFunction(() => document.querySelector("#login-error")?.textContent.includes("Test login rejected"));
  assert.ok(seen.some(url => url.startsWith(proxy + "/api.php?route=%2Fauth%2Flogin")));
  assert.ok(!seen.some(url => url.startsWith(direct)));
  await page.reload();
  assert.equal(await page.locator("#login-russian-proxy").isChecked(), true);
  assert.match(await page.locator("#login-proxy-route").textContent(), /HostiMan · Россия/);
  await page.locator("#login-russian-proxy").uncheck();
  await page.reload();
  assert.equal(await page.locator("#login-russian-proxy").isChecked(), false);
  console.log("Browser proxy smoke: default direct, checkbox proxy, persistence, manual direct restore passed");
} finally {
  await browser.close();
}

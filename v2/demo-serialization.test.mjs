import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { buildReferenceDemoProperties, propertiesForDemoProduct, serializeForLicenseHash } from "./demo-reference-properties.js";

// Outputs of the ORIGINAL Java property classes, not of a second JS model.
// See fixtures metadata for the pinned source, runtime and normalization.
const fixture = JSON.parse(readFileSync(new URL("./fixtures/java-properties.json", import.meta.url), "utf8"));
for (const { fields, body, hashSource } of fixture.cases) {
  test(`Java properties: ${fields.product}, DC=${fields.datacenter}, ${fields.timeZone}, ${fields.now}, name=${JSON.stringify(fields.name)}`, async () => {
    const actual = await buildReferenceDemoProperties(fields, async () => Uint8Array.of(1, 2, 3));
    assert.equal(actual, body, "header, HashMap entry order, raw values and final LF must match Java");
    assert.equal(serializeForLicenseHash(propertiesForDemoProduct(fields).data), hashSource,
      "TreeSet order and escaped UTF-8 signing source must match Java");
  });
}

test("generation defaults to the host timezone, including the Java YEKT header", () => {
  const moduleUrl = new URL("./demo-reference-properties.js", import.meta.url).href;
  const source = `const {propertiesForDemoProduct}=await import(${JSON.stringify(moduleUrl)});
    const result=propertiesForDemoProduct({serverId:'DEMO-123',email:'demo@example.org',organisation:'Example',now:'2026-11-10T23:30:00.000Z'});
    console.log(JSON.stringify({header:result.header,purchase:result.data.get('PurchaseDate')}));`;
  const actual = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", source], {
    encoding: "utf8", env: { ...process.env, TZ: "Asia/Yekaterinburg" }
  }));
  assert.deepEqual(actual, { header: "#Wed Nov 11 04:30:00 YEKT 2026", purchase: "2026-11-11" });
});

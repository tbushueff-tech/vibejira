import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, verify } from "node:crypto";
import { inflateSync } from "node:zlib";
import { PRIVATE_KEY_STR } from "./demo-private-key.js";
import { propertiesForDemoProduct } from "./demo-reference-properties.js";
import { generateJiraDemoKey } from "./demo-keygen.js";
import { javaUtf8 } from "./java-utf8.js";
import { javaLocalDates } from "./java-local-date.js";

const fixture = name => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8"));
const referenceKey = fixture("reference-key");
const publicKey = createPublicKey(createPrivateKey({ key: Buffer.from(referenceKey.privateKeyPkcs8, "base64"), type: "pkcs8", format: "der" }));
function unpack(key) {
  const compact = key.replace(/\s/g, ""), suffix = compact.lastIndexOf("X02");
  const base64 = compact.slice(0, suffix);
  assert.equal(parseInt(compact.slice(suffix + 3), 31), base64.length);
  const bytes = Buffer.from(base64, "base64"), length = bytes.readUInt32BE();
  const body = bytes.subarray(4, 4 + length), signature = bytes.subarray(4 + length);
  assert.deepEqual([...body.subarray(0, 5)], [13, 14, 12, 10, 15]);
  assert.equal(verify("sha1", body, publicKey, signature), true);
  return inflateSync(body.subarray(5));
}
test("PKCS8 key matches the pinned original Encoder, not an independently generated pair", () => {
  assert.equal(PRIVATE_KEY_STR, referenceKey.privateKeyPkcs8);
  const source = readFileSync(new URL("./java/io/bushueff/jirahelper/demo/Encoder.java", import.meta.url), "utf8");
  assert.equal(source.match(/PRIVATE_KEY_STR\s*=\s*"([^"]+)"/)[1], referenceKey.privateKeyPkcs8);
});
test("container produced by the unmodified reference Java Encoder verifies and decodes", () => {
  const original = fixture("reference-envelope");
  assert.equal(unpack(original.key).toString("utf8"), original.properties);
});
test("malformed UTF-16 is encoded with Java UTF-8 replacement bytes", async () => {
  for (const { value, base64 } of fixture("java-utf8"))
    assert.equal(Buffer.from(javaUtf8(value)).toString("base64"), base64);
  const generated = await generateJiraDemoKey({ serverId: "S", email: "e", organisation: "O", name: "a\ud800b", now: 0, timeZone: "UTC", locale: "en-US" });
  assert.deepEqual(unpack(generated.key), Buffer.from(javaUtf8(generated.properties)));
});
test("constructor date and init ID use separate clock reads", () => {
  const values = [Date.parse("2026-11-10T23:59:59.999Z"), Date.parse("2026-11-11T00:00:00.123Z")];
  let reads = 0;
  const result = propertiesForDemoProduct({ serverId: "S", email: "e", organisation: "O", clock: () => values[reads++], timeZone: "UTC", locale: "en-US" });
  assert.equal(reads, 2);
  assert.equal(result.data.get("CreationDate"), "2026-11-10");
  assert.equal(result.data.get("SEN"), "SEN-L" + values[1]);
});
test("empty and null constructor values are distinct from omitted name", () => {
  const fields = { serverId: "", email: "", organisation: "", product: "", now: 0, timeZone: "UTC" };
  assert.equal(propertiesForDemoProduct({ ...fields, name: "" }).data.get("ContactName"), "");
  assert.equal(propertiesForDemoProduct({ ...fields, name: null }).data.get("ContactName"), null);
  assert.equal(propertiesForDemoProduct({ ...fields, email: "e" }).data.get("ContactName"), "e");
});
test("custom product schemas cannot require Java HashMap tree bins", () => {
  for (const datacenter of [false, true]) {
    const data = propertiesForDemoProduct({ serverId: "S", email: "e", organisation: "O", product: "custom", datacenter }).data;
    data.set("licenseHash", "AQID");
    const dynamic = [...data.keys()].filter(key => key.startsWith("custom."));
    for (const capacity of [32, 64]) {
      const buckets = new Uint8Array(capacity);
      for (const key of data.keys()) if (!dynamic.includes(key)) {
        let h = 0; for (let i = 0; i < key.length; i++) h = (Math.imul(h, 31) + key.charCodeAt(i)) | 0;
        buckets[(h ^ (h >>> 16)) & (capacity - 1)]++;
      }
      // Even if EVERY namespace-dependent key lands in the busiest fixed
      // bucket, the reference never reaches the nine-entry treeify trigger.
      assert.ok(Math.max(...buckets) + dynamic.length < 9);
    }
  }
});
test("dates match the Java 22 oracle across all zones, historical/future dates and locale cases", () => {
  const original = fixture("java-dates"), hash = createHash("sha256");
  const cases = original.zones.flatMap(zone => original.dates.map(date => ({ zone, date, locale: "en-US" }))).concat(original.extra);
  for (const { zone, date, locale } of cases) {
    const result = javaLocalDates(new Date(date), zone, locale);
    hash.update(result.dateTime + "\t" + result.dateOnly + "\n");
  }
  assert.equal(hash.digest("hex"), original.sha256, `${cases.length} original Java date outputs`);
});

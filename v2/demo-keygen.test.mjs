import test from "node:test";
import assert from "node:assert/strict";
import { inflateSync } from "node:zlib";
import { buildJiraDemoProperties, generateJiraDemoKey } from "./demo-keygen.js";

function inspect(key) {
  const clean = key.replace(/\s/g, "");
  const split = clean.lastIndexOf("X02");
  assert.ok(split > 0, "must end in original X02 marker");
  const base = clean.slice(0, split), footer = clean.slice(split + 3);
  assert.equal(parseInt(footer, 31), base.length);
  const encoded = Buffer.from(base, "base64");
  const length = encoded.readUInt32BE(0);
  const body = encoded.subarray(4, 4 + length);
  const sig = encoded.subarray(4 + length);
  assert.deepEqual([...body.subarray(0, 5)], [13,14,12,10,15]);
  assert.equal(sig[0], 0x30, "expect DER-encoded DSA signature");
  assert.equal(sig[1], sig.length - 2);
  assert.equal(sig[2], 0x02);
  const decoded = inflateSync(body.subarray(5)).toString("utf8");
  return { decoded, sig, length };
}
const fields = {serverId:"AAAA-BBBB-CCCC-DDDD",email:"a@example.com",
  organisation:"Example ltd",name:"Developer",datacenter:true};

test("demo generator uses agent-format zlib, prefix, DSA DER, base64 and X02/base31 trailer", async() => {
  const generated = await generateJiraDemoKey(fields);
  const info = inspect(generated.key);
  assert.equal(info.decoded, generated.properties);
  assert.match(info.decoded, /ServerID=AAAA-BBBB-CCCC-DDDD/);
  assert.match(info.decoded, /jira.DataCenter=true/);
  assert.match(info.decoded, /DEMONSTRATION ONLY/);
  assert.ok(info.sig.length >= 40 && info.sig.length <= 48);
  assert.match(generated.format, /DEMO/);
});
test("each demo output has a new non-Atlassian signature", async() => {
  const a = inspect((await generateJiraDemoKey(fields)).key);
  const b = inspect((await generateJiraDemoKey(fields)).key);
  assert.notDeepEqual(a.sig,b.sig);
});
test("generator validates required metadata", async() => {
  assert.throws(() => buildJiraDemoProperties({ serverId:"",email:"",organisation:"" }),/Server ID/);
});

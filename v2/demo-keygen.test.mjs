import test from "node:test";
import assert from "node:assert/strict";
import { inflateSync } from "node:zlib";
import { createPublicKey, verify as verifySignature } from "node:crypto";
import { DEMO_DSA } from "./demo-dsa-key.js";
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
  return { decoded, sig, length, body };
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
test("same fixed DSA key produces distinct valid signatures from random nonces", async() => {
  const a = inspect((await generateJiraDemoKey(fields)).key);
  const b = inspect((await generateJiraDemoKey(fields)).key);
  assert.notDeepEqual(a.sig,b.sig);
});
test("generator validates required metadata", async() => {
  assert.throws(() => buildJiraDemoProperties({ serverId:"",email:"",organisation:"" }),/Server ID/);
});

test("every browser-generated signature verifies against the fixed public DSA key", async () => {
  const pub = createPublicKey({ key: Buffer.from(DEMO_DSA.publicSpkiBase64, "base64"), format: "der", type: "spki" });
  assert.equal(pub.asymmetricKeyType, "dsa");
  for (let i = 0; i < 5; i++) {
    const {body, sig} = inspect((await generateJiraDemoKey(fields)).key);
    assert.equal(verifySignature("sha1", body, pub, sig), true, "signature must verify under the same public key");
  }
});

test("editable demo plugin Product, Server ID, Mail and Organisation are in the decoded payload", async () => {
  const fields = {
    product: "test_test",
    serverId: "BLSA-YKF4-X270-D26O",
    email: "admin@example.com",
    organisation: "JH",
    datacenter: true
  };
  const result = await generateJiraDemoKey(fields);
  const { decoded } = inspect(result.key);
  assert.match(decoded, /DemoProduct=test_test/);
  assert.match(decoded, /ServerID=BLSA-YKF4-X270-D26O/);
  assert.match(decoded, /ContactEMail=admin@example\.com/);
  assert.match(decoded, /Organisation=JH/);
  assert.match(decoded, /test_test\.DataCenter=true/);
  assert.match(decoded, /DEMONSTRATION ONLY/);
  const server = buildJiraDemoProperties({ ...fields, datacenter: false });
  assert.doesNotMatch(server, /test_test\.DataCenter=true/);
  assert.throws(() => buildJiraDemoProperties({ ...fields, product: "invalid\nproperty" }), /Product:/);
});

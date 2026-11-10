import test from "node:test";
import assert from "node:assert/strict";
import { inflateSync } from "node:zlib";
import { createPrivateKey, createPublicKey, verify as verifySignature } from "node:crypto";
import { PRIVATE_KEY_STR, readDemoDsaPrivateKey } from "./demo-private-key.js";
import { buildJiraDemoProperties, generateJiraDemoKey } from "./demo-keygen.js";
import { serializeForLicenseHash, escapeJavaProperty, propertiesForDemoProduct } from "./demo-reference-properties.js";

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
  assert.match(info.decoded, /^Description=License for Example ltd$/m);
  assert.ok(info.sig.length >= 40 && info.sig.length <= 48);
  assert.match(generated.format, /DEMO/);
});
test("same fixed DSA key produces distinct valid signatures from random nonces", async() => {
  const a = inspect((await generateJiraDemoKey(fields)).key);
  const b = inspect((await generateJiraDemoKey(fields)).key);
  assert.notDeepEqual(a.sig,b.sig);
});
test("generator validates required metadata", async() => {
  await assert.rejects(() => buildJiraDemoProperties({ serverId:"",email:"",organisation:"" }),/Server ID/);
});

test("every browser-generated signature verifies against the fixed public DSA key", async () => {
  const pub = createPublicKey(createPrivateKey({key: Buffer.from(PRIVATE_KEY_STR,"base64"), format:"der",type:"pkcs8"}));
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
  assert.match(decoded, /test_test.active=true/);
  assert.match(decoded, /test_test.enterprise=true/);
  assert.doesNotMatch(decoded, /DemoProduct=/);
  assert.doesNotMatch(decoded, /jira.product.jira-software.active=/);
  assert.doesNotMatch(decoded, /LicenseID=/);
  assert.match(decoded, /ServerID=BLSA-YKF4-X270-D26O/);
  assert.match(decoded, /ContactEMail=admin@example\.com/);
  assert.match(decoded, /Organisation=JH/);
  assert.match(decoded, /test_test\.DataCenter=true/);
  const server = await buildJiraDemoProperties({ ...fields, datacenter: false });
  assert.doesNotMatch(server, /test_test\.DataCenter=true/);
  await assert.rejects(() => buildJiraDemoProperties({ ...fields, product: "invalid\nproperty" }), /Product:/);
});

test("inner licenseHash and outer envelope both verify with OUR own DSA public key", async () => {
  const publicKey = createPublicKey(createPrivateKey({key: Buffer.from(PRIVATE_KEY_STR,"base64"), format:"der",type:"pkcs8"}));
  const fixed = {...fields, product:"test_test", now:new Date("2026-11-10T11:20:05Z")};
  const original = propertiesForDemoProduct(fixed);
  const payload = serializeForLicenseHash(original.data);
  const generated = await generateJiraDemoKey(fixed);
  const unpacked = inspect(generated.key);
  const match = unpacked.decoded.match(/^licenseHash=([^\n]+)/m);
  assert.ok(match, "must include reference-style inner hash");
  assert.equal(verifySignature("sha1", Buffer.from(payload, "utf8"), publicKey,
    Buffer.from(match[1], "base64")), true, "inner licenseHash invalid");
  assert.equal(verifySignature("sha1", unpacked.body, publicKey, unpacked.sig), true,
    "outer signature invalid");
  assert.match(unpacked.decoded, /^keyVersion=1600708331$/m);
  assert.match(unpacked.decoded, /^licenseVersion=2$/m);
});
test("reference product property models differ between Jira Software, Core, Service Desk and ThirdPlugin", () => {
  const common={serverId:"BLSA-YKF4-X270-D26O",email:"demo@example.test",
    organisation:"JH",datacenter:true,now:new Date("2026-11-10T09:12:00Z")};
  const plugin=propertiesForDemoProduct({...common,product:"test_test"}).data;
  assert.equal(plugin.get("test_test.active"),"true");
  assert.equal(plugin.get("test_test.enterprise"),"true");
  assert.equal(plugin.get("LicenseID"),null);
  assert.equal(plugin.get("LicenseTypeName"),"COMMERCIAL");
  assert.equal(plugin.get("test_test.DataCenter"),"true");
  const jira=propertiesForDemoProduct({...common,product:"jira"}).data;
  assert.equal(jira.get("jira.product.jira-software.active"),"true");
  assert.equal(jira.get("jira.LicenseEdition"),"UNLIMITED");
  assert.equal(jira.has("test_test.enterprise"),false);
  const core=propertiesForDemoProduct({...common,product:"jc"}).data;
  assert.equal(core.get("jira.product.jira-core.active"),"true");
  assert.equal(core.get("jira.LicenseEdition"),"UNLIMITED");
  const desk=propertiesForDemoProduct({...common,product:"jsm"}).data;
  assert.equal(desk.get("com.atlassian.servicedesk.numRoleCount"),"-1");
  assert.equal(desk.get("jira.DataCenter"),"true");
  const bamboo=propertiesForDemoProduct({...common,product:"bamboo"}).data;
  assert.equal(bamboo.get("bamboo.NumberOfBambooRemoteAgents"),"1000");
  assert.equal(bamboo.has("NumberOfUsers"),false);
});
test("reference sorted and escaped licenseHash source", () => {
  const data = new Map([["z"," value"],["a.b","a=b:c"],["licenseHash","old"]]);
  assert.equal(serializeForLicenseHash(data),"a.b=a\\=b\\:c\nz=\\ value\n");
  assert.equal(escapeJavaProperty("A B",true),"A\\ B");
});

test("single PKCS8 demo private key yields valid DSA parameters", () => {
  const params = readDemoDsaPrivateKey();
  const privateKey = createPrivateKey({ key: Buffer.from(PRIVATE_KEY_STR, "base64"), format:"der",type:"pkcs8" });
  const dsa = privateKey.asymmetricKeyType;
  assert.equal(dsa, "dsa");
  assert.ok(params.p > params.q);
  assert.ok(params.g > 1n);
  assert.ok(params.x > 0n && params.x < params.q);
});


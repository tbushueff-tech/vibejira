// Compare the Java Encoder's hard-coded PKCS#8 private key against the
// browser's fixed DSA public key (and the same agent-style packaging).
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { inflateSync } from "node:zlib";
import assert from "node:assert/strict";
import { DEMO_DSA } from "./demo-dsa-key.js";
import { generateJiraDemoKey } from "./demo-keygen.js";

const folder = mkdtempSync(join(tmpdir(), "jira-demo-"));
const javaClass = "io.bushueff.jirahelper.demo.Encoder";
const source = "v2/java/io/bushueff/jirahelper/demo/Encoder.java";
const publicKey = createPublicKey({key:Buffer.from(DEMO_DSA.publicSpkiBase64,"base64"),format:"der",type:"spki"});

function unpack(license) {
  const compact = license.replace(/\s/g, "");
  const i = compact.lastIndexOf("X02");
  assert.ok(i > 0, "expected X02 suffix");
  const encoded = compact.slice(0,i);
  assert.equal(parseInt(compact.slice(i+3),31), encoded.length);
  const data = Buffer.from(encoded,"base64");
  const length = data.readUInt32BE(0);
  const content = data.subarray(4,4+length);
  const signature = data.subarray(4+length);
  assert.deepEqual([...content.subarray(0,5)],[13,14,12,10,15]);
  assert.equal(verify("sha1",content,publicKey,signature),true);
  return { properties: inflateSync(content.subarray(5)).toString("utf8"), compressed: content.subarray(5), content };
}
try {
  execFileSync("javac",["-d",folder,source],{stdio:"pipe"});
  const properties = "#DEMONSTRATION ONLY\nServerID=DEMO-123\nDescription=Not an Atlassian license\n";
  const input = join(folder,"properties.txt");
  writeFileSync(input,properties,"utf8");
  const output = execFileSync("java",["-cp",folder,javaClass,input],{encoding:"utf8"});
  assert.equal(unpack(output).properties,properties);
  const fromBrowser = await generateJiraDemoKey({
    serverId:"DEMO-123", email:"demo@example.org", organisation:"Example"
  });
  assert.equal(unpack(fromBrowser.key).properties,fromBrowser.properties);

  // Verify that both implementations recover precisely the same input.
  // DEFLATE streams and DSA signatures need not match byte-for-byte.
  const browserPropertiesFile = join(folder,"browser-properties.txt");
  writeFileSync(browserPropertiesFile,fromBrowser.properties,"utf8");
  const javaFromBrowser = execFileSync("java",
    ["-cp",folder,javaClass,browserPropertiesFile],{encoding:"utf8"});
  const javaEnvelope = unpack(javaFromBrowser);
  const browserEnvelope = unpack(fromBrowser.key);
  // Different valid DEFLATE implementations may produce different compressed
  // bytes. Compare the canonical UTF-8 text, container header and signature
  // validity without incorrectly requiring identical compressed bytes.
  assert.deepEqual(javaEnvelope.content.subarray(0, 5),
    browserEnvelope.content.subarray(0, 5));
  assert.equal(javaEnvelope.properties,browserEnvelope.properties);
  console.log("Java and JS independently encode the same DEMO properties, share container fields, and verify against our own DSA public key");
} finally {
  rmSync(folder,{recursive:true,force:true});
}

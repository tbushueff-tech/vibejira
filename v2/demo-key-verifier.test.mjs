import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateJiraDemoKey } from "./demo-keygen.js";

const folder = mkdtempSync(join(tmpdir(), "helper-verifier-"));
const java = "io.bushueff.jirahelper.demo.KeyTransformer";
try {
  execFileSync("javac", [
    "-d", folder,
    "v2/java/io/bushueff/jirahelper/demo/Encoder.java",
    "v2/java/io/bushueff/jirahelper/demo/KeyTransformer.java"
  ], {stdio:"pipe"});
  const generated = await generateJiraDemoKey({
    serverId:"BLSA-YKF4-X270-D26O",
    email:"test@example.com", organisation:"Test company",
    product:"demo_plugin", datacenter:true
  });
  const keyfile = join(folder, "key.txt");
  writeFileSync(keyfile, generated.key, "utf8");
  const success = execFileSync("java", ["-cp",folder,java,keyfile], {encoding:"utf8"});
  assert.match(success,/outer DSA signature: true/);
  assert.match(success,/inner licenseHash: true/);
  assert.match(success,/Marked DEMO: true/);
  const flat = generated.key.replace(/\s/g,"");
  const marker = flat.lastIndexOf("X02");
  const b64 = flat.slice(0,marker);
  const bytes = Buffer.from(b64,"base64");
  bytes[bytes.length-5] ^= 1;
  writeFileSync(keyfile,bytes.toString("base64")+"X02"+b64.length.toString(31));
  assert.throws(() => execFileSync("java", ["-cp",folder,java,keyfile], {stdio:"pipe"}),
    /Command failed/);
  console.log("Own Java demo key verification and tampered signature rejection passed");
} finally {
  rmSync(folder,{recursive:true,force:true});
}

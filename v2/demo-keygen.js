import { DEMO_DSA } from "./demo-dsa-key.js";

// Original agent-style packaging with a NEW, fixed Jira Helper DSA keypair.
// Corresponds to the PKCS#8 constant in v2/java/.../Encoder.java.
// Public and intentionally non-Atlassian; only for DEMO signatures.
const P = BigInt(DEMO_DSA.p);
const Q = BigInt(DEMO_DSA.q);
const G = BigInt(DEMO_DSA.g);
const PRIVATE_SCALAR = BigInt(DEMO_DSA.x);
const encoder = new TextEncoder();

function bigintFromBytes(bytes) {
  return bytes.reduce((value, byte) => (value << 8n) + BigInt(byte), 0n);
}
function bytesFromBigint(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}
function powMod(base, exponent, modulo) {
  let result = 1n;
  for (base %= modulo; exponent > 0n; exponent >>= 1n, base = (base * base) % modulo) {
    if (exponent & 1n) result = (result * base) % modulo;
  }
  return result;
}
function invert(value, modulo) { return powMod(value, modulo - 2n, modulo); }
function randomScalar() {
  for (;;) {
    const raw = crypto.getRandomValues(new Uint8Array(20));
    const scalar = bigintFromBytes(raw);
    if (scalar > 0n && scalar < Q) return scalar;
  }
}
function derInteger(n) {
  let buf = bytesFromBigint(n);
  if (buf[0] & 0x80) buf = Uint8Array.of(0, ...buf);
  return Uint8Array.of(2, buf.length, ...buf);
}
function dsaDerSignature(r, s) {
  const left = derInteger(r), right = derInteger(s);
  return Uint8Array.of(0x30, left.length + right.length, ...left, ...right);
}
async function demoDsaSign(message) {
  const secret = PRIVATE_SCALAR; // fixed demo-only private scalar (publicly visible)
  const hash = bigintFromBytes(new Uint8Array(await crypto.subtle.digest("SHA-1", message)));
  for (;;) {
    const k = randomScalar();
    const r = powMod(G, k, P) % Q;
    if (!r) continue;
    const s = (invert(k, Q) * (hash + secret * r)) % Q;
    if (s) return dsaDerSignature(r, s);
  }
}
function concat(...arrays) {
  const result = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const part of arrays) { result.set(part, offset); offset += part.length; }
  return result;
}
function base64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(text);
}
function formatBase31(num) {
  if (!num) return "0";
  const digits = "0123456789abcdefghijklmnopqrstu";
  let output = "";
  for (; num > 0; num = Math.floor(num / 31)) output = digits[num % 31] + output;
  return output;
}
async function zlibCompress(bytes) {
  if (typeof CompressionStream !== "function")
    throw new Error("Браузер не поддерживает CompressionStream (deflate)");
  const source = new Blob([bytes]).stream();
  const stream = source.pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
const padDate = dt => new Date(dt).toISOString().slice(0, 10);
export function buildJiraDemoProperties({
  serverId, email, organisation, product = "jira", name, datacenter = false
}) {
  if (!serverId?.trim() || !email?.trim() || !organisation?.trim() || !product?.trim())
    throw new Error("Укажите Server ID, email, организацию и продукт");
  if (!/^[A-Za-z0-9_.-]{1,120}$/.test(product.trim()))
    throw new Error("Product: допустимы буквы A–Z, цифры, _, - и точка");
  const now = new Date();
  const today = padDate(now);
  const expiry = "2090-01-01"; // informational DEMO value only
  const sid = "L" + now.getTime();
  const jiraProduct = "jira.product.jira-software";
  const entries = [
    ["CreationDate", today], ["ContactName", name?.trim() || email.trim()],
    ["ContactEMail", email.trim()], ["ServerID", serverId.trim()],
    ["DemoProduct", product.trim()],
    ["Organisation", organisation.trim()], ["SEN", "SEN-" + sid],
    ["LicenseID", "LIDSEN-" + sid],
    ["PurchaseDate", today], ["LicenseExpiryDate", expiry],
    ["MaintenanceExpiryDate", expiry], ["licenseVersion", "2"],
    ["Description", "DEMONSTRATION ONLY - NOT A VALID JIRA LICENSE"],
    ["Evaluation", "false"], ["LicenseTypeName", "COMMERCIAL"],
    ["jira.active", "true"], ["greenhopper.active", "true"],
    [jiraProduct + ".active", "true"], [jiraProduct + ".Starter", "false"],
    [jiraProduct + ".NumberOfUsers", "-1"], ["jira.NumberOfUsers", "-1"],
    ["NumberOfUsers", "-1"], ["jira.LicenseEdition", "UNLIMITED"],
    ["greenhopper.LicenseEdition", "UNLIMITED"],
    ["greenhopper.enterprise", "true"]
  ];
  // Product is informational metadata in this DEMO encoder; it does not
  // attempt to produce an activation license for a plugin.
  if (datacenter) entries.push([product + ".DataCenter", "true"],
    ["jira.DataCenter", "true"], ["Subscription", "true"]);
  return "#DEMONSTRATION ONLY\n" + entries.map(([key,value]) => key+"="+String(value).replace(/[\r\n]/g," ")).join("\n");
}
export async function generateJiraDemoKey(fields) {
  const properties = buildJiraDemoProperties(fields);
  const compressed = await zlibCompress(encoder.encode(properties));
  const payload = concat(Uint8Array.of(13,14,12,10,15), compressed);
  const signature = await demoDsaSign(payload);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, payload.length, false);
  const encoded = base64(concat(len, payload, signature));
  const full = encoded + "X02" + formatBase31(encoded.length);
  // Match Encoder.split(): insert newline after index 76, 152, ...
  const result = [...full].map((char,i) => char + (i > 0 && i % 76 === 0 ? "\n" : "")).join("");
  return { key: result, properties, format: "Atlassian Agent-shaped DEMO (fixed own DSA key; not an Atlassian license)" };
}

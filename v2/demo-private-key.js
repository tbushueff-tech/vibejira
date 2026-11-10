// Jira Helper's existing demo PKCS#8 DSA private key.
// This value matches Encoder.java's PRIVATE_KEY_STR and is publicly visible.
// DEMO ONLY: do not use for production security or actual licensing.
export const PRIVATE_KEY_STR = "MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUNYsbkapILzW8VhfGrU4eHo6/Dqw=";
// Small, strict DER reader for the fixed PKCS#8 DSA format. No new keypair is
// generated: p, q, g and x are extracted from the supplied encoded private key.
export function readDemoDsaPrivateKey(base64 = PRIVATE_KEY_STR) {
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  function tlv(offset, expectedTag) {
    if (offset + 2 > bytes.length) throw new Error("Invalid DER: truncated tag");
    const tag = bytes[offset++];
    if (tag !== expectedTag) throw new Error("Invalid DER tag for DSA PKCS#8");
    let length = bytes[offset++];
    if (length & 0x80) {
      const count = length & 0x7f;
      if (!count || count > 3 || offset + count > bytes.length)
        throw new Error("Invalid DER length");
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
    }
    const end = offset + length;
    if (end > bytes.length) throw new Error("Invalid DER: truncated value");
    return { start: offset, end };
  }
  function integer(start) {
    const part = tlv(start, 0x02);
    if (part.start === part.end) throw new Error("Empty DSA integer");
    let out = 0n;
    for (let i = part.start; i < part.end; i++)
      out = (out << 8n) | BigInt(bytes[i]);
    return { value: out, next: part.end };
  }
  const envelope = tlv(0, 0x30);
  if (envelope.end !== bytes.length) throw new Error("Invalid PKCS#8 envelope");
  const version = integer(envelope.start);
  if (version.value !== 0n) throw new Error("Unsupported PKCS#8 version");
  const algorithm = tlv(version.next, 0x30);
  const oid = tlv(algorithm.start, 0x06);
  // 1.2.840.10040.4.1 = id-dsa
  if (Array.from(bytes.subarray(oid.start,oid.end)).join(",") !==
      "42,134,72,206,56,4,1") throw new Error("Expected DSA private key");
  const parameters = tlv(oid.end, 0x30);
  const p = integer(parameters.start);
  const q = integer(p.next);
  const g = integer(q.next);
  if (g.next !== parameters.end || parameters.end !== algorithm.end)
    throw new Error("Invalid DSA parameters");
  const octets = tlv(algorithm.end, 0x04);
  const x = integer(octets.start);
  if (x.next !== octets.end || octets.end !== envelope.end)
    throw new Error("Invalid DSA private scalar");
  if (p.value <= 0n || q.value <= 0n || g.value <= 0n ||
      x.value <= 0n || x.value >= q.value)
    throw new Error("Invalid DSA private parameters");
  return { p: p.value, q: q.value, g: g.value, x: x.value };
}

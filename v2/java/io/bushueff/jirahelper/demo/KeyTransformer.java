package io.bushueff.jirahelper.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.InflaterInputStream;

/**
 * Safe demo verifier corresponding to our Encoder.java and demo-keygen.js.
 * This class does NOT implement ClassFileTransformer or patch any JVM class.
 *
 * The reference project's interception is deliberately disabled:
 *
 * // public byte[] transform(... originalClassBytes) {
 * //     // No JVM class interception or Atlassian public-key replacement.
 * //     return originalClassBytes;
 * // }
 *
 * Only checks signatures against Jira Helper's own public demo DSA key.
 */
public final class KeyTransformer {
    private static final String PUBLIC_KEY_STR =
        "MIIBtjCCASsGByqGSM44BAEwggEeAoGBANPMMT1MJ0BQS8to4L0mkn/axc+uyX8outLtcwm1fk1d57QXqzaiRPiQ4Em7mf9UnjFqZ2UsgnQxwkDNacjpERz2DR683SpzyW4TpZeW/icj5Jv1AGlsM/5+XQ75gEhm71nh+kWzTHS1nI5Hr4cHvHlL3Lq+ApXkHI3VgwTNn4CFAhUA5fiYMZp1UOWbOU+3VF6L7JrfelUCgYA4d8GTJkReq0cyYDSF3Y7FzWbWe2JfWyottKWJknPCpfPFUkPGYphtrZI/0EgHnsCtj+hF5O/PulTHnCuHKJHUODtIcxQNkPpVC0u9JiHD9kgNmPJofoRxATtWDV60OW9IUnOf5dSjhh5YqPDu/SFcSDDJv0bqqwMP/lWLNcbUewOBhAACgYBs/WrrtMC4Q2Vz2CDq44+h7JeaoeHWMV9OCctUNTYaOgGFy9Pu+T9k6t6v2k/RYAQdmqzWja+mU59HFl4zv6PSH3ydy8LIws/why8RtbrHLBchOy5tI6nsxKfq7JnaaBP5N9OuTgmPf3L6hWUQOygvKnZoxopAFOIxmXHYyqSQ2A==";
    private static final byte[] PREFIX = {13, 14, 12, 10, 15};
    private static final int MAX_COMPRESSED = 1024 * 1024;
    private static final int MAX_UNCOMPRESSED = 1024 * 1024;

    private static final PublicKey PUBLIC_KEY = loadPublicKey();
    private KeyTransformer() {}

    private static PublicKey loadPublicKey() {
        try {
            byte[] der = Base64.getDecoder().decode(PUBLIC_KEY_STR);
            return KeyFactory.getInstance("DSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Invalid own demo DSA public key", e);
        }
    }

    public static boolean verifySignature(byte[] message, byte[] signatureBytes) {
        try {
            Signature verifier = Signature.getInstance("SHA1withDSA");
            verifier.initVerify(PUBLIC_KEY);
            verifier.update(message);
            return verifier.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    public static Result inspect(String formattedKey) throws Exception {
        if (formattedKey == null || formattedKey.isBlank())
            throw new IllegalArgumentException("Demo key is empty");
        String clean = formattedKey.replaceAll("\\s+", "");
        if (clean.length() > 2 * MAX_COMPRESSED)
            throw new IllegalArgumentException("Demo key exceeds size limit");
        int suffix = clean.lastIndexOf("X02");
        if (suffix < 1) throw new IllegalArgumentException("Missing X02 footer");
        String raw = clean.substring(0, suffix);
        int length;
        try { length = Integer.parseInt(clean.substring(suffix + 3), 31); }
        catch (NumberFormatException e) { throw new IllegalArgumentException("Invalid base31 footer", e); }
        if (length != raw.length()) throw new IllegalArgumentException("Invalid footer length");
        byte[] all = Base64.getDecoder().decode(raw);
        if (all.length < 4 + PREFIX.length + 40) throw new IllegalArgumentException("Truncated demo key");
        int payloadLength = java.nio.ByteBuffer.wrap(all, 0, 4).getInt();
        if (payloadLength < PREFIX.length || payloadLength > MAX_COMPRESSED ||
            4 + payloadLength >= all.length)
            throw new IllegalArgumentException("Invalid payload length");
        byte[] payload = Arrays.copyOfRange(all, 4, 4 + payloadLength);
        byte[] signature = Arrays.copyOfRange(all, 4 + payloadLength, all.length);
        if (!Arrays.equals(Arrays.copyOf(payload, PREFIX.length), PREFIX))
            throw new IllegalArgumentException("Invalid demo prefix");
        boolean outerValid = verifySignature(payload, signature);
        String properties = unzip(payload, PREFIX.length, payload.length - PREFIX.length);
        boolean isDemo = properties.contains("DEMONSTRATION ONLY");
        boolean innerValid = verifyInnerHash(properties);
        return new Result(outerValid, innerValid, isDemo, properties);
    }

    private static String unzip(byte[] payload, int offset, int length) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InflaterInputStream zip =
                 new InflaterInputStream(new ByteArrayInputStream(payload, offset, length))) {
            byte[] buffer = new byte[4096];
            for (int n; (n = zip.read(buffer)) != -1; ) {
                if (out.size() + n > MAX_UNCOMPRESSED)
                    throw new IllegalArgumentException("Decompressed properties exceed limit");
                out.write(buffer, 0, n);
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static boolean verifyInnerHash(String properties) {
        try {
            Map<String, String> sorted = new TreeMap<>();
            String hash = null;
            for (String row : properties.split("\n")) {
                if (row.startsWith("#") || row.isBlank()) continue;
                int eq = row.indexOf('=');
                if (eq <= 0) return false;
                String key = row.substring(0, eq);
                String value = row.substring(eq + 1).replace("\r", "");
                if (key.equals("licenseHash")) { hash = value; continue; }
                if (sorted.putIfAbsent(key, value) != null) return false;
            }
            if (hash == null || !properties.contains("DEMONSTRATION ONLY")) return false;
            StringBuilder data = new StringBuilder();
            for (var entry : sorted.entrySet())
                data.append(escape(entry.getKey(), true)).append("=")
                    .append(escape(entry.getValue(), false)).append("\n");
            return verifySignature(data.toString().getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(hash));
        } catch (Exception e) {
            return false;
        }
    }

    // Mirrors the reference LicenseProperty.escape() for its hash input.
    private static String escape(String input, boolean key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\t': result.append("\\t"); break;
                case '\n': result.append("\\n"); break;
                case '\f': result.append("\\f"); break;
                case '\r': result.append("\\r"); break;
                case ' ': if (i == 0 || key) result.append('\\');
                    result.append(' '); break;
                case '\\': result.append("\\\\"); break;
                default:
                    if ("=: \t\r\n\f#!".indexOf(c) != -1) result.append('\\');
                    result.append(c);
            }
        }
        return result.toString();
    }

    public record Result(boolean outerValid, boolean innerValid,
                         boolean demo, String properties) {
        public boolean valid() { return outerValid && innerValid && demo; }
    }

    /** CLI: java io.bushueff.jirahelper.demo.KeyTransformer demo-key.txt */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: KeyTransformer <demo-key-file>");
            System.exit(2);
        }
        Result result = inspect(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8));
        System.out.println("Own demo outer DSA signature: " + result.outerValid());
        System.out.println("Own demo inner licenseHash: " + result.innerValid());
        System.out.println("Marked DEMO: " + result.demo());
        if (!result.valid()) System.exit(1);
    }
}

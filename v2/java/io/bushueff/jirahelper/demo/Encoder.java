package io.bushueff.jirahelper.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterInputStream;

/**
 * Demonstration format encoder analogous to Atlassian-Agent's Encoder.java.
 *
 * PRIVATE_KEY_STR contains a newly generated, Jira Helper-specific DSA
 * PKCS#8 key. It is deliberately PUBLIC: DO NOT use for real licenses,
 * authentication or security. These signatures are NOT Atlassian licenses.
 *
 * No Java Agent, patching code or third-party dependencies.
 */
public final class Encoder {
    private static final String PRIVATE_KEY_STR = "MIIBSwIBADCCASsGByqGSM44BAEwggEeAoGBANPMMT1MJ0BQS8to4L0mkn/axc+uyX8outLtcwm1fk1d57QXqzaiRPiQ4Em7mf9UnjFqZ2UsgnQxwkDNacjpERz2DR683SpzyW4TpZeW/icj5Jv1AGlsM/5+XQ75gEhm71nh+kWzTHS1nI5Hr4cHvHlL3Lq+ApXkHI3VgwTNn4CFAhUA5fiYMZp1UOWbOU+3VF6L7JrfelUCgYA4d8GTJkReq0cyYDSF3Y7FzWbWe2JfWyottKWJknPCpfPFUkPGYphtrZI/0EgHnsCtj+hF5O/PulTHnCuHKJHUODtIcxQNkPpVC0u9JiHD9kgNmPJofoRxATtWDV60OW9IUnOf5dSjhh5YqPDu/SFcSDDJv0bqqwMP/lWLNcbUewQXAhUAxlG4MTJYTi8nIkRuXfLdrOHgHR4=";

    private static final PrivateKey PRIVATE_KEY = importKey();

    private Encoder() {}

    private static PrivateKey importKey() {
        try {
            byte[] der = Base64.getDecoder().decode(PRIVATE_KEY_STR);
            return KeyFactory.getInstance("DSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Could not load demo DSA key", e);
        }
    }

    public static String encode(String licenseText) throws Exception {
        byte[] compressed = zipText(licenseText.getBytes(StandardCharsets.UTF_8));
        byte[] payload = new byte[compressed.length + 5];
        payload[0] = 13;
        payload[1] = 14;
        payload[2] = 12;
        payload[3] = 10;
        payload[4] = 15;
        System.arraycopy(compressed, 0, payload, 5, compressed.length);
        return packLicense(payload, sign(payload));
    }

    // Same SHA1withDSA operation and PKCS#8 key loading as reference Encoder.
    public static byte[] sign(byte[] bytes) throws Exception {
        Signature signer = Signature.getInstance("SHA1withDSA");
        signer.initSign(PRIVATE_KEY);
        signer.update(bytes);
        return signer.sign();
    }

    // Mirror the reference's DeflaterInputStream form, not a different codec.
    private static byte[] zipText(byte[] bytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ByteArrayInputStream in = new ByteArrayInputStream(bytes);
             DeflaterInputStream deflater = new DeflaterInputStream(in, new Deflater())) {
            byte[] buffer = new byte[64];
            int len;
            while ((len = deflater.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
        }
        return out.toByteArray();
    }

    private static String packLicense(byte[] payload, byte[] signature) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(output)) {
            data.writeInt(payload.length);
            data.write(payload);
            data.write(signature);
        }
        String encoded = Base64.getEncoder().encodeToString(output.toByteArray());
        String full = encoded + "X02" + Integer.toString(encoded.length(), 31);
        StringBuilder formatted = new StringBuilder(full.length() + full.length() / 76);
        for (int i = 0; i < full.length(); i++) {
            formatted.append(full.charAt(i));
            if (i > 0 && i % 76 == 0) formatted.append('\n');
        }
        return formatted.toString();
    }

    /**
     * Usage: java io.bushueff.jirahelper.demo.Encoder path/to/properties.txt
     * Only demo-formatted output is generated.
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: Encoder <demo-properties-file>");
            System.exit(2);
        }
        String text = java.nio.file.Files.readString(java.nio.file.Path.of(args[0]), StandardCharsets.UTF_8);
        System.out.println(encode(text));
    }
}

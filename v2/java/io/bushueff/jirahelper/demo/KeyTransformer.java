package io.bushueff.jirahelper.demo;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

/**
 * Structural counterpart of the reference KeyTransformer.
 *
 * Unlike the reference, this class does NOT modify EncodedKeySpec,
 * replace public keys or alter any license validation mechanisms.
 * It has no premain/agent registration: it is not installed in the JVM.
 *
 * A no-op Java ClassFileTransformer must return null (unchanged bytes).
 * Actual demo-key signature validation belongs to KeyVerifier.java.
 */
public final class KeyTransformer implements ClassFileTransformer {
    // Restrict any diagnostic matching to our own demonstration classes.
    private static final String CN_DEMO_ENCODER =
        "io/bushueff/jirahelper/demo/Encoder";

    @Override
    public byte[] transform(
            ClassLoader loader,
            String className,
            Class<?> classBeingRedefined,
            ProtectionDomain protectionDomain,
            byte[] classfileBuffer
    ) throws IllegalClassFormatException {
        if (className == null || !className.equals(CN_DEMO_ENCODER)) {
            return null;
        }
        // Only a demonstration class is recognized. No bytecode rewriting.
        // No Atlassian or JDK class is intercepted or altered.
        return null;
    }

    // The reference uses handleKeySpec() to alter a JVM security class.
    // That mechanism is intentionally absent, not merely hidden by a flag.

    /** Retain the previous command-line entry point for compatibility. */
    public static void main(String[] args) throws Exception {
        KeyVerifier.main(args);
    }
}

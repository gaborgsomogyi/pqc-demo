package dev.gaborsomogyi.pqcdemo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.nio.charset.StandardCharsets;

/**
 * Compares classical ECDSA (P-256) with ML-DSA-65 (FIPS 204) for signing the
 * same message, and prints key/signature sizes.
 *
 * The forgery angle: an ECDSA public key encodes a point on an elliptic
 * curve. A large enough quantum computer solves the underlying discrete-log
 * problem with Shor's algorithm and recovers the private key straight from
 * that public key - at which point the attacker can forge signatures under
 * that identity indistinguishably from the real signer. ML-DSA's public key
 * does not expose an equivalent quantum-solvable structure; recovering its
 * private key means attacking a lattice (Module-LWE / Module-SIS) problem
 * instead.
 *
 * This demo does not (cannot) actually break ECDSA - no such quantum
 * computer exists yet. It signs and verifies with both schemes so the sizes
 * and mechanics are concrete, and states the forgery consequence in
 * comments/output rather than simulating it.
 */
final class SignatureComparisonDemo {

    private static final byte[] MESSAGE =
            "Flink checkpoint metadata v1: gs://bucket/chk-42/_metadata".getBytes(StandardCharsets.UTF_8);

    static void run() throws Exception {
        System.out.println();
        System.out.println("-- Classical ECDSA (P-256) --");
        signAndVerify("ECDSA", "SHA256withECDSA", ecdsaKeyPair());

        System.out.println();
        System.out.println("-- ML-DSA-65 (FIPS 204) --");
        signAndVerify("ML-DSA-65", "ML-DSA", mlDsaKeyPair());

        System.out.println();
        System.out.println("Forgery consequence: if the ECDSA private key above is ever");
        System.out.println("recovered from its public key via Shor's algorithm, every past");
        System.out.println("and future signature made with it becomes forgeable - including,");
        System.out.println("for example, signed checkpoint/savepoint metadata or artifact");
        System.out.println("signatures a Flink deployment pipeline trusts. ML-DSA has no known");
        System.out.println("quantum shortcut from public key to private key.");
    }

    private static void signAndVerify(String label, String sigAlgorithm, KeyPair keyPair) throws Exception {
        Signature signer = "ML-DSA".equals(sigAlgorithm)
                ? Signature.getInstance(sigAlgorithm, "BC")
                : Signature.getInstance(sigAlgorithm);
        signer.initSign(keyPair.getPrivate());
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = "ML-DSA".equals(sigAlgorithm)
                ? Signature.getInstance(sigAlgorithm, "BC")
                : Signature.getInstance(sigAlgorithm);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(MESSAGE);
        boolean valid = verifier.verify(signature);

        System.out.println(label + " public key:  " + keyPair.getPublic().getEncoded().length + " bytes (X.509 encoded)");
        System.out.println(label + " signature:   " + signature.length + " bytes, valid=" + valid);
    }

    private static KeyPair ecdsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static KeyPair mlDsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        return kpg.generateKeyPair();
    }

    private SignatureComparisonDemo() {
    }
}

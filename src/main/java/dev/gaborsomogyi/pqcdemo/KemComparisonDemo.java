package dev.gaborsomogyi.pqcdemo;

import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Compares three ways two parties can agree on a shared secret:
 *
 *   A) Classical ECDH (X25519)       - fast, tiny, broken outright by Shor's
 *                                      algorithm on a cryptographically
 *                                      relevant quantum computer.
 *   B) Pure ML-KEM-768 (FIPS 203)    - believed quantum-resistant. Finalized
 *                                      as a standard in August 2024, though
 *                                      the underlying Kyber design was a
 *                                      public NIST PQC competition candidate
 *                                      for years before that.
 *   C) Hybrid X25519 + ML-KEM-768    - the combiner defined for TLS 1.3 in
 *                                      RFC 10024. The session stays safe as
 *                                      long as EITHER half holds.
 *
 * This illustrates "harvest now, decrypt later": traffic captured today under
 * scheme (A) can be decrypted retroactively the day a large enough quantum
 * computer exists, because the recorded ciphertext and the math needed to
 * break it don't change - only the attacker's compute does. Schemes (B) and
 * (C) remove that risk for the PQC half of the exchange.
 */
final class KemComparisonDemo {

    static void run() throws Exception {
        System.out.println();
        System.out.println("-- A) Classical ECDH (X25519) --");
        byte[] classicalSecret = classicalEcdh();
        System.out.println("Shared secret (32 bytes, recoverable today by recording");
        System.out.println("the transcript and later factoring/solving the discrete log");
        System.out.println("with a quantum computer running Shor's algorithm):");
        System.out.println(HexFormat.of().formatHex(classicalSecret));

        System.out.println();
        System.out.println("-- B) Pure ML-KEM-768 (FIPS 203) --");
        byte[] pqcSecret = mlKem768();
        System.out.println("Shared secret (no known quantum algorithm breaks the");
        System.out.println("underlying Module-LWE problem):");
        System.out.println(HexFormat.of().formatHex(pqcSecret));

        System.out.println();
        System.out.println("-- C) Hybrid X25519 + ML-KEM-768 (RFC 10024 style) --");
        byte[] hybridSecret = hybrid(classicalSecret, pqcSecret);
        System.out.println("Combined secret. Even a total break of X25519 leaves an");
        System.out.println("attacker needing to also break ML-KEM-768 to recover this:");
        System.out.println(HexFormat.of().formatHex(hybridSecret));
    }

    /** Textbook X25519 ECDH, entirely broken by a large quantum computer via Shor's algorithm. */
    private static byte[] classicalEcdh() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();
        System.out.println("Public key: " + alice.getPublic().getEncoded().length + " bytes (X.509 encoded)");

        KeyAgreement aliceAgreement = KeyAgreement.getInstance("X25519");
        aliceAgreement.init(alice.getPrivate());
        aliceAgreement.doPhase(bob.getPublic(), true);
        byte[] aliceSecret = aliceAgreement.generateSecret();

        KeyAgreement bobAgreement = KeyAgreement.getInstance("X25519");
        bobAgreement.init(bob.getPrivate());
        bobAgreement.doPhase(alice.getPublic(), true);
        byte[] bobSecret = bobAgreement.generateSecret();

        if (!MessageDigest.isEqual(aliceSecret, bobSecret)) {
            throw new IllegalStateException("X25519 agreement mismatch");
        }
        return aliceSecret;
    }

    /**
     * ML-KEM-768 key encapsulation via Bouncy Castle's JCA KEM wrapper
     * (KeyGenerator + KEMGenerateSpec/KEMExtractSpec), the same pattern BC
     * uses for RSA-KEM. Bob generates a key pair; Alice encapsulates a
     * secret against Bob's public key; Bob decapsulates it with his private
     * key. No network round trip beyond the single encapsulation blob.
     */
    private static byte[] mlKem768() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BC");
        KeyPair bob = kpg.generateKeyPair();
        System.out.println("Public key: " + bob.getPublic().getEncoded().length + " bytes (X.509 encoded)");

        KeyGenerator senderKem = KeyGenerator.getInstance("ML-KEM-768", "BC");
        senderKem.init(new KEMGenerateSpec(bob.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation aliceSide = (SecretKeyWithEncapsulation) senderKem.generateKey();
        byte[] encapsulation = aliceSide.getEncapsulation();

        KeyGenerator receiverKem = KeyGenerator.getInstance("ML-KEM-768", "BC");
        receiverKem.init(new KEMExtractSpec(bob.getPrivate(), encapsulation, "AES"), new SecureRandom());
        SecretKeyWithEncapsulation bobSide = (SecretKeyWithEncapsulation) receiverKem.generateKey();

        if (!MessageDigest.isEqual(aliceSide.getEncoded(), bobSide.getEncoded())) {
            throw new IllegalStateException("ML-KEM-768 encapsulation mismatch");
        }
        System.out.println("Encapsulation blob sent over the wire: " + encapsulation.length + " bytes");
        return aliceSide.getEncoded();
    }

    /**
     * Simplified stand-in for the RFC 10024 X25519MLKEM768 combiner: the real
     * RFC concatenates the ML-KEM and X25519 shared secrets in a specific
     * order and feeds the result straight into the TLS 1.3 key schedule
     * (itself a hash-based construction). We reproduce the same
     * concatenate-then-hash shape with SHA-256 to keep this demo
     * dependency-free; it is illustrative, not a byte-for-byte RFC
     * implementation.
     */
    private static byte[] hybrid(byte[] classicalSecret, byte[] pqcSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(pqcSecret);
        sha256.update(classicalSecret);
        return sha256.digest();
    }

    private KemComparisonDemo() {
    }
}

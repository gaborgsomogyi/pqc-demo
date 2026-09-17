package dev.gaborsomogyi.pqcdemo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Minimal, from-scratch demonstrations for the blog post
 * "Post-Quantum Cryptography and Apache Flink: What Harvest-Now-Decrypt-Later
 * Actually Means For Your Cluster".
 *
 * Two independent demos:
 *   1. KemComparisonDemo   - classical ECDH vs. ML-KEM-768 vs. a hybrid of both,
 *                            illustrating "harvest-now, decrypt-later".
 *   2. SignatureComparisonDemo - classical ECDSA vs. ML-DSA-65, illustrating the
 *                            signature-forgery angle.
 *
 * Neither demo talks to a network or to Flink. They run entirely in-process to
 * keep the example bare-minimal and auditable in one sitting.
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=================================================================");
        System.out.println(" Demo 1: Key exchange - classical ECDH vs. ML-KEM-768 vs. hybrid");
        System.out.println("=================================================================");
        KemComparisonDemo.run();

        System.out.println();
        System.out.println("=================================================================");
        System.out.println(" Demo 2: Signatures - classical ECDSA vs. ML-DSA-65");
        System.out.println("=================================================================");
        SignatureComparisonDemo.run();
    }

    private Main() {
    }
}

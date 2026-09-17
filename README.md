# pqc-demo

Minimal, from-scratch Java demos accompanying the blog post
[*Post-Quantum Cryptography: Harvest Now, Decrypt Later*](https://gaborsomogyi.com/blog/2026-09-25-post-quantum-cryptography-apache-flink).

Two self-contained demos, no network calls, no Flink dependency, just the JDK's
own `java.security` APIs plus [Bouncy Castle](https://www.bouncycastle.org/) for
the algorithms the JDK doesn't ship yet on versions before 24.

## What's here

- **`KemComparisonDemo`** establishes a shared secret three ways:
  classical X25519 ECDH, pure ML-KEM-768 ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)),
  and a hybrid of both (the shape used by [RFC 10024](https://datatracker.ietf.org/doc/rfc10024/)'s
  `X25519MLKEM768` TLS 1.3 group, this demo's combiner is a simplified
  concatenate-then-SHA-256 stand-in, not a byte-for-byte RFC implementation).
  Illustrates *harvest-now-decrypt-later*: a transcript of (A) recorded today
  is decryptable retroactively the day a cryptographically relevant quantum
  computer exists; (B) and (C) are not, under current cryptanalysis.

- **`SignatureComparisonDemo`** signs and verifies the same payload with
  classical ECDSA (P-256) and ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)),
  and prints key/signature sizes. Illustrates the *signature-forgery* angle:
  an ECDSA private key is recoverable from its public key with Shor's
  algorithm on a large enough quantum computer, which would make every past
  and future signature under that key forgeable. ML-DSA has no known
  equivalent shortcut. This demo does not (cannot) actually break ECDSA, no
  such quantum computer exists, it only makes the sizes and mechanics
  concrete.

## Running it

Requires JDK 17+ and Maven.

```console
$ mvn -q package
$ java -jar target/pqc-demo-jar-with-dependencies.jar
```

Sample output (your key material will differ, sizes will not):

```
-- A) Classical ECDH (X25519) --
Public key: 44 bytes (X.509 encoded)
Shared secret (32 bytes, ...)

-- B) Pure ML-KEM-768 (FIPS 203) --
Public key: 1206 bytes (X.509 encoded)
Encapsulation blob sent over the wire: 1088 bytes
Shared secret (32 bytes, ...)

-- Classical ECDSA (P-256) --
ECDSA public key:  91 bytes (X.509 encoded)
ECDSA signature:   70 bytes, valid=true

-- ML-DSA-65 (FIPS 204) --
ML-DSA-65 public key:  1974 bytes (X.509 encoded)
ML-DSA-65 signature:   3309 bytes, valid=true
```

## Why Bouncy Castle instead of the JDK's own `ML-KEM`/`ML-DSA`

JDK 24 added these algorithms natively via
[JEP 496](https://openjdk.org/jeps/496) and [JEP 497](https://openjdk.org/jeps/497),
as final (non-preview) `java.security` algorithm names (`ML-KEM-768`,
`ML-DSA-65`, ...). Most production JVMs today are still on an LTS release
older than 24, so this demo uses [Bouncy Castle](https://www.bouncycastle.org/)
(`bcprov-jdk18on`), which implements the same JCA algorithm names and works
back to JDK 8, the same code runs unmodified once you upgrade past JDK 24
and could drop the dependency entirely.

## License

MIT. See [LICENSE](LICENSE).

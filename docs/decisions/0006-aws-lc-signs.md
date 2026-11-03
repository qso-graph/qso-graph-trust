# 0006: AWS-LC signs, through one binding

Decided 2026-11-03 by KI7MT, after Codex (gpt-6-astra, high) and Watson each recommended it. Amends
decision 0002, and replaces RustCrypto's `rsa` as what signs.

## What was decided

- **AWS-LC makes LoTW's signature:** RSA PKCS#1 v1.5 over SHA-1, through AWS-LC's `RSA_sign` with
  `NID_sha1`. It is the library QSO Graph Desktop already ships, through `aws-lc-sys` 0.45.0, the
  version aws-lc-rs 1.18.1 uses. KI7MT: the signing step must be the strongest link, not the weakest.
- **One binding, `qso-graph-trust-awslc`, is the only crate with unsafe code.** aws-lc-rs's safe API
  signs RSA only with SHA-2, so the binding calls AWS-LC's C functions itself: parse the key, check its
  shape and primality, compare its public key, and sign. Each unsafe block is allowed on its own and
  carries its SAFETY reason, with one unsafe operation per block (the crate's own lints, checked
  exactly by `cargo xtask policy`). Its interface is safe: the key cannot be read back out.
- **`aws-lc-sys` is the one cryptographic provider** whose C the library may build, and only the
  binding may depend on it. Its build tools (`cc`, `cmake` and theirs) run only while AWS-LC is built.
- **The library keeps the rest in safe Rust:** reading key files, and decrypting a protected key
  (PBKDF2, 3DES or AES-CBC) with every buffer wiped. AWS-LC receives only the decrypted key.
- **RustCrypto's `rsa` is a test tool only:** it builds the crafted keys the tests refuse.

## Why

AWS-LC's RSA is constant-time and overwrites every block it frees (`OPENSSL_free`, `crypto/mem.c`), so
the key's numbers and their temporaries do not stay in memory. `rsa` 0.9.10 carries an unpatched timing
advisory (RUSTSEC-2023-0071) and wipes its own temporaries only in part. AWS-LC's FIPS validation does
not cover this operation (SHA-1 signing with 1024-bit keys is outside FIPS's approved parameters), and
is not a reason here.

**The non-FIPS build,** `aws-lc-sys`: its licence is ISC, Apache-2.0, MIT, BSD-3-Clause and MIT-0, all
compatible with GPL-3.0-only. `aws-lc-fips-sys` also lists the OpenSSL licence, which is not.

## What stays true

The checks prove each part: AWS-LC's signatures match tqsllib's byte for byte across the corpus; a
crafted key (unequal, equal or composite factors) never signs; any crate but the binding depending on
`aws-lc-sys` fails the policy, as does the binding with weaker lints. The key is in memory only while it
signs, as in every signer; the OS credential store protects it at rest. A wiping global allocator and
the custody test (qso-graph-desktop#172, Gate C) still apply to every QG Trust program.

## Amended 2026-11-03: certificate signatures through aws-lc-rs

Importing a TQSL backup checks each callsign certificate's chain to LoTW's pinned root, which needs RSA
signature verification. AWS-LC's safe Rust API, `aws-lc-rs` 1.18.1 (QSO Graph Desktop's, over the same
`aws-lc-sys` 0.45.0), offers that, so the binding calls it (`verify_rsa`) with no unsafe code of its own,
as AGENTS.md requires for every operation the safe API offers. `aws-lc-rs` is named as part of the
provider in the policy checks: it may depend on `aws-lc-sys`, and any crate but the binding depending on
either fails, proved by a planted case. Only LoTW's SHA-1 signing, which `aws-lc-rs` does not make, still
calls `aws-lc-sys` directly.

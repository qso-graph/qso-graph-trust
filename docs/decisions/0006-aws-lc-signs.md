# 0006: AWS-LC signs, through one binding

Decided 2026-11-03 by KI7MT, after two independent reviews each recommended it. Amends
decision 0002, and replaces RustCrypto's `rsa` as what signs.

## What was decided

- **AWS-LC makes LoTW's signature:** RSA PKCS#1 v1.5 over SHA-1, through AWS-LC's `RSA_sign` with
  `NID_sha1`. It is the library QSO Graph Desktop already ships, through `aws-lc-sys` 0.45.0, the
  version aws-lc-rs 1.18.1 uses. The signing step must be the strongest link, not the weakest.
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
the key's numbers and their temporaries do not stay in memory. At the time of this decision, `rsa`
0.9.10 carried the timing advisory RUSTSEC-2023-0071 and wiped its temporaries only in part. The
test-only dependency is now 0.10.0, which fixes that advisory. AWS-LC's FIPS validation does
not cover this operation (SHA-1 signing with 1024-bit keys is outside FIPS's approved parameters), and
is not a reason here.

**The non-FIPS build,** `aws-lc-sys`: its licence is ISC, Apache-2.0, MIT, BSD-3-Clause and MIT-0, all
compatible with GPL-3.0-or-later. `aws-lc-fips-sys` also lists the OpenSSL licence, which is not.

## What stays true

The checks prove each part: AWS-LC's signatures match tqsllib's byte for byte across the corpus; a
crafted key (unequal, equal or composite factors) never signs; any crate but the binding depending on
`aws-lc-sys` fails the policy, as does the binding with weaker lints. The key is in memory only while it
signs, as in every signer; the OS credential store protects it at rest. A wiping global allocator and
the custody test (qso-graph-desktop#172, Gate C) still apply to every QG Trust program.

## Amended 2026-11-03: certificate signatures through aws-lc-rs

Reading a TQSL `.tbk` file checks each callsign certificate's chain to LoTW's pinned root, which needs RSA
signature verification. AWS-LC's safe Rust API, `aws-lc-rs` 1.18.1 (QSO Graph Desktop's, over the same
`aws-lc-sys` 0.45.0), offers that, so the binding calls it (`verify_rsa`) with no unsafe code of its own,
as AGENTS.md requires for every operation the safe API offers. `aws-lc-rs` is named as part of the
provider in the policy checks: it may depend on `aws-lc-sys`, and any crate but the binding depending on
either fails, proved by a planted case. Only LoTW's SHA-1 signing, which `aws-lc-rs` does not make, still
calls `aws-lc-sys` directly.

## Certificate requests (2026-11-05)

Accepted 2026-11-05: it does what TQSL 2.8.7 does.

TQSL 2.8.7's `tqsl_createCertRequest` generates RSA-1024 with exponent 65537 and signs the
PKCS#10 request with SHA-256. aws-lc-rs 1.18.1's `rsa/key.rs::validate_rsa_key` rejects signing
keys below 2048 bits, and its generator starts at 2048. These two RSA operations therefore use
the same binding: `RSA_generate_key_ex` and the existing `RSA_sign` operation with `NID_sha256`.
SHA-256 hashing uses aws-lc-rs's safe API. No additional provider or dependency package is added;
the binding shares the workspace's existing pinned `zeroize` for generated secrets.

The binding hands generated private PKCS#8 to the library only in `Zeroizing`; a fixed wiped
buffer receives DER directly from AWS-LC. RSA, exponent and EVP allocations are released on
success and every error path. Each of the twelve new unsafe blocks has one operation and its
own allowance and safety explanation: RSA allocation; exponent allocation, assignment and free;
key generation; EVP allocation, RSA reference assignment and free; fixed CBB initialization,
marshalling, length read (only after successful flush), and cleanup. SHA-256 signing shares the
existing checked RSA signature operation.

The public library returns an opaque generated request. Only its `.tq5` and SPKI are readable;
`Store::store_request` hands its key to the library-owned backend and records its pending call,
DXCC, SPKI, creation time and key name in `store.xml`. No backend handle is exposed. Applications
verify the response chain and call `Store::add_requested_certificate`, which matches SPKI, call
and DXCC, validates the private key, attaches the certificate and removes the pending record in
one replacement under the lock. Pending credentials are accounted for in the open report;
`pending_requests` lists them and `abandon_request` removes the file entry before the credential.
No pending secret is written to the public store file. CLI commands and Desktop screens remain
to be built; the backends are the OS credential store ([0002](0002-no-c-in-the-library.md)) and volatile memory for tests.

Format decisions were read from TQSL's source, not inferred: request field order and framing,
CSR subject order (AROcallsign, commonName, emailAddress), empty attributes, SHA-256 algorithm
with NULL parameters, and signed-request SHA-1 over the whole decoded CSR DER. The request kind
is NEW, ADDITIONAL or RENEWAL. `TQSL_CERT_REQ` does not carry a call-kind field;
`apps/crqwiz.cpp::CRQ_TypePage::TransferDataFromWindow` maps club, DXpedition, special event,
former, replacing and QSL manager choices to signer-selection guidance. `apps/tqsl.cpp` passes
the selected signer and renewal flag to the library, with no kind-specific wire field.
QGT exposes that intent as `CallKind` and requires explicit signer selection, independently of
TQSL's UI.

The differential tests reproduce five complete corpus requests, including the deterministic
CSR signature, using their test keys, except for the identification field, which names QG Trust.
Fresh requests verify independently with the test-only RSA implementation, as do additional/renewal signatures with the old key. Input refusal cases
are paired with valid controls; an issued test response exercises the credential handoff,
certificate-chain verification, attachment and signing after reopening the store.

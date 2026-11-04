<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE. -->

# 0011: Authenticate certificate imports before publishing them

**Status: proposed**, 2026-11-04, for KI7MT to decide.

The library imports ARRL's `.tq6` response and password-authenticated PKCS#12 `.p12` files through
`Store::import_tq6` and `Store::import_pkcs12`. It verifies every supplied certificate, including
unused authorities, against caller trust before changing storage. Supplied roots establish no
trust. A `.tq6` attaches pending requests by actual SPKI, callsign and DXCC; attachment validates the
stored private key and publishes pending removal with certificate addition in one replacement.
Other certificates are explicitly reported as keyless. A missing pending key is an error.

PKCS#12 import accepts definite DER, password-integrity PFX version 3, data/encryptedData content,
X.509 certificate bags, private/shrouded key bags and bounded nested SafeContents. A required SHA-1
or SHA-256 MAC uses RFC 7292 Appendix B's PKCS#12 KDF and HMAC's constant-time verification before
any bags are decrypted. Encryption is PBES2 with PBKDF2-HMAC-SHA-1/SHA-256 and AES-128/256-CBC or
3DES-CBC, or PKCS#12 SHA-1/three-key-3DES PBE. Other algorithms, including RC2-40, are refused.
Only one user certificate and one key are accepted; the library checks the key's LoTW shape and
actual match before private credential handoff. No public API returns private DER.

The corpus's `QG0TEST-weak.p12` uses RC2-40 for certificates and SHA-1/3DES for its key. Thus the
original weak file is refused, following the explicit RC2 refusal requirement. The conflicting
request that it also load cannot be met under that requirement. A test reuses its exact encrypted
3DES keybag with plaintext certificate bags and recomputes the MAC to exercise supported legacy
import without enabling RC2.

Limits are checked while parsing: 4 MiB input/decompressed XML, 128 certificates/bags/content
records, eight nested SafeContents or constructed attribute levels, 64-byte salts, 1,024-byte
passwords and one million iterations per derivation. An aggregate budget allows four million
hash rounds (PBKDF2 conservatively charged two per iteration; legacy PBE three). XML also uses the
existing reader's element, depth and attribute bounds. Passwords are borrowed UTF-8 BMP text;
conversion for the PKCS#12 KDF, every plaintext and derived-key allocation use wiped storage.

The release custody test caught CRT-value fragments in RustCrypto CBC's stack temporaries after
AES decryption: `cbc` 0.1.2 `src/decrypt.rs:174–193`, `Backend::proc_par_blocks` copies the resulting
blocks into output without wiping its local `t`. Its `zeroize` feature wipes the IV; AES/DES wipe
owned schedules, but neither wipes that plaintext copy. A wiping allocator cannot wipe stack
storage. CBC decryption therefore stays on the existing binding's safe AWS-LC API, with
`aws-lc-rs` 1.18.1's `legacy-des` feature for existing 3DES files. No dependency packages are added.
Both PKCS#12 import and existing PKCS#8 unlocking share this provider.

Hash, HMAC and PBKDF2 work involving passwords or key material also goes through this binding's
safe `aws_lc_rs::{digest, hmac, pbkdf2}` APIs. RustCrypto digest state and HMAC's key-XOR-pad stack
buffer were not covered by wiping only the final output. Every derived key, KDF A/B/I buffer and
returned digest now owns wiped heap storage; no binding helper returns an inline secret array.
The provider's digest API itself returns inline temporary output, so changing providers alone does
not establish stack erasure. Unused direct `pbkdf2`, `cbc`, `aes` and `des` dependencies are removed;
`sha2` is now a direct test dependency only. `pkcs8`/`pkcs5` only parse parameters in shipped code.
Their `3des` feature exposes the legacy parameter variant and transitively enables crypto code;
none of those derivation/decryption functions is called. Independent test oracles still use it.
`Cargo.lock` reflects these changes; the existing vet audits/exemptions still cover the graph.

AWS-LC has a remaining source-level fallback temporary: `aws-lc-sys` 0.45.0's
`aws-lc/crypto/fipsmodule/aes/mode_wrappers.c:92–102` selects `CRYPTO_cbc128_decrypt` for VPAES
without AES-NI. `crypto/fipsmodule/modes/cbc.c:65–115` leaves its local `tmp[16]` unwiped. With
in-place decryption this contains AES-decrypted ciphertext **before** CBC's XOR. XOR with the
known preceding ciphertext block recovers the corresponding plaintext, potentially including
private CRT bytes in a PKCS#8 final block. The provider source is not changed by this decision.

As an additional mitigation, `memory.rs` invokes a non-inlined operation frame, waits for it to
return (success or typed error), then calls a separate `#[inline(never)]` function that zero-fills
64 KiB of stack, `zeroize`s it and passes it to `black_box`. This runs at operation boundaries:
key unlocking/private DER handoff, stored-key validation, PKCS#12 import, signing, request
creation, and export sealing/opening. It does not run in the KDF iteration loop. Nested internal
validation shares the enclosing operation's scrub. Owned buffers and provider contexts are dropped
before that scrub, except results deliberately kept live in wiped heap storage.

This is best-effort overwrite of returned frames on the current thread, not a safe-Rust guarantee
of exact frame overlap or universal stack erasure. It does not erase registers, live caller
frames/results, other threads, frames deeper than the overwrite, or memory after an abort; an
unwinding panic can skip the post-operation scrub. It cannot replace provider-owned wiping or the
wiping allocator. The provider's fallback `tmp` therefore remains a limitation for different
builds, layouts and CPUs, and while an operation is in progress.

The Linux custody test scans readable process memory in debug and release after successful and
failed imports, signing and export restoration. On x86_64 it repeats with
`OPENSSL_ia32cap=~0x200000000000000:~0x20000000000`, set only in the child before provider startup.
AWS-LC's `cpucap/internal.h:85–86` tests AES-NI at word 1 bit 25 (bit 57 of the first environment
word pair); `cpucap/cpu_intel.c:285–302` applies the inverted mask. SSSE3 remains available for
VPAES; the second mask also clears VAES (word 3 bit 9) to prevent wider AES dispatch.

The search includes UTF-8 and UTF-16BE-plus-NUL import passwords, successful/failed import MAC
keys, both import AES keys, the protected TQSL key's PBKDF2 output, fragments, little-endian hash
word forms, HMAC ipad/opad forms, and the final CBC pre-XOR key block. An independent Python
hashlib oracle derives the needles and verifies its successful MAC key against the corpus MAC;
a test-only RustCrypto decoder computes the exact CBC intermediate. Separate runs plant every
needle and require it to be found, including on the masked path. Neither the debug nor release
completed-operation scan found a residual on the tested x86_64 host with the scrub enabled. A
local release experiment disabling the scrub also found no residual at that final snapshot; later
operations can overwrite earlier frames, so this is not evidence that AWS-LC wipes `tmp`, or proof
that the scrub alone removed it. Existing signing differential tests still compare signatures to
tqsllib byte for byte.

`Store::expiring_certificates(now, days)` compares UTC calendar dates of X.509 `notAfter`, with
strict `days_left < days`, and returns public IDs, calls, expiry timestamps and expired status.
The validity-end date itself is not yet expired; a zero threshold lists only expired records.
It also lists keyless and expired certificates, as requested, without TQSL's startup UI filters.

TQSL 2.8.7's `apps/tqsl.cpp:3995` describes the default 60 days; lines 4092–4095 call
`tqsl_getCertificateNotAfterDate`, subtract today's UTC date and test `days_left < expireDays`.
`openssl_cert.cpp:2042–2063` obtains `X509_get_notAfter`, and lines 899–901 compare expiry dates
strictly before today. It uses validity-end, not QSO-end. The provided read-only library source
is `/var/tmp/qgt-sol3/tqsl-src/openssl_cert.cpp`; the application source was available locally at
`/tmp/claude-1000/-home-ki7mt-workspace-qso-graph/27400915-e24a-4149-b6d8-538456c3536b/scratchpad/src/tqsl/apps/tqsl.cpp`,
whose adjacent `tqslversion.ver` says `2.8.7`.

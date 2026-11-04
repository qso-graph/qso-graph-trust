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
AES decryption: `cbc` 0.1.2 `decrypt.rs`, `Backend::proc_par_blocks` copies the resulting blocks into
output without wiping its local `t`. CBC decryption therefore uses the existing binding's safe
AWS-LC API, with `aws-lc-rs` 1.18.1's `legacy-des` feature enabled for existing 3DES files. No dependency
packages are added. Both the PKCS#12 path and existing PKCS#8 decryption share this provider. The
custody test exercises successful and failed PKCS#12 authentication in debug and release and adds
a searched import password with a planted-copy positive control. Existing signing differential
tests continue to compare the resulting signatures to tqsllib.

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

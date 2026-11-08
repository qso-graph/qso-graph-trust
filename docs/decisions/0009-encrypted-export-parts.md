<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE. -->

# 0009: Encrypt the LoTW backup part inside the library

**Status: accepted**, 2026-11-05: it does what TQSL 2.8.7 does.

QGD-LTW-0010 and QGD-LTW-0011 require LoTW's certificates, keys, station locations and signed-QSO
section to leave the store only encrypted, with restore checking the whole part before replacement.
No API returns private key bytes (decision 0007). Only the LoTW part is encrypted; assembling a larger
backup belongs to the application.

`export::Password::generate()` uses AWS-LC random bytes and rejection sampling below 248 to choose
20 characters from `A-Z`, `a-z`, `0-9`, uniformly: about 119 bits. `expose_secret()` lets the application
display the password for the operator to save separately. The library never persists it. A typed
password requires at least 20 ASCII alphanumeric characters and can only open, never seal. There is
no export without a library-generated password and no recovery without the saved password.

## Encrypted format, version 1

All offsets are zero-based; integer lengths and counts are unsigned, big endian.

| Bytes | Contents |
| --- | --- |
| 0–7 | ASCII `QGT-PART` |
| 8 | Version, `1` |
| 9–12 | PBKDF2 iteration count, `600000` |
| 13–28 | Random 16-byte salt |
| 29–40 | Random 12-byte nonce |
| 41 onward | AES-256-GCM ciphertext, followed by its 16-byte authentication tag |

PBKDF2-HMAC-SHA-256 derives a 32-byte key. The iteration count follows the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2),
checked 2026-11-04. Version 1 accepts exactly 600,000 iterations, before deriving anything; this both
bounds CPU use and refuses weaker counts. A future count needs an explicit format decision.

AAD is `QGT-PART || version || UTF-8 part name || iteration bytes || salt`. The store part name is
`lotw`. GCM authenticates its nonce too. Every input, length, version and authentication failure on
opening returns the same fixed error as a wrong password. Plaintext is bounded to 40 MiB.

## Plaintext and replacement

The private plaintext format is `QGT-STORE` (9 ASCII bytes), a version byte (`2`), then a u32 length
and the complete versioned store XML. It includes the store's signed-QSO section (version 1; store
root version 2 carries the bounded records defined in decision 0010). Following that are
u32-length-prefixed PKCS#8 DER keys, one per certificate whose XML record names a key, in certificate
order, followed by one per pending
certificate request in request order. The XML includes each pending request's identity, SPKI and
creation time. Version 2 adds these pending keys; version 1 plaintext is refused rather than silently
losing pending requests. The outer authenticated encryption envelope remains version 1. No extra
records or trailing bytes are accepted. Certificate, request and location identifiers survive restore;
credential names are fresh.

Export reads XML and all referenced keys under the store lock and refuses missing or mismatched
keys. Restore decrypts and authenticates, parses through the existing strict store reader (including
`StationLocation::new`), verifies every certificate against caller-supplied `Trust`, and checks every
private key against its certificate or pending request's recorded SPKI, before acquiring the
destination lock or changing anything.
Production callers use `Trust::lotw()`, which pins ARRL's roots and production CAs; the part
supplies only the roots the operator's store had accepted, under decision 0011's rules (below).
Custom test trust must include the issuers needed by its certificates.

Under the lock, restore reloads the destination, generates fresh credential names, stages the new
keys, atomically replaces the file, then deletes the old file's keys. Any staging or pre-replacement
write failure attempts removal of every staged key. Cleanup failures are reported and leave orphans
for the store's existing open report. After a successful rename a durability-sync failure must retain
both old and new keys, report `StoreError::Durability`, and stop: deleting the new keys would break
the visible file. A later old-key deletion failure likewise leaves a usable new store and reports the
credential error. This is the store's existing safe ordering, not a cross-service atomic transaction.

Passwords, derived keys, raw DER and plaintext use heap-backed `Zeroizing` storage; PBKDF2 writes
directly into its final allocation so returning it cannot leave inline stack copies. Secret buffers
reserve their full size before copying, to avoid unwiped reallocations. Cryptography uses only aws-lc-rs's safe APIs inside
the existing binding; its owned cipher contexts are freed by AWS-LC. Programs must still install the
wiping global allocator required by decision 0002. No new dependency package is added; the binding
uses the workspace's existing, pinned `zeroize` version.

The public operations are `Store::export_part` and `Store::restore_part`, plus password generation,
entry and explicit disclosure. Generic seal/open helpers and plaintext serialization stay crate-private
so the library has no API that hands the decrypted keys to a caller.

The unpublished custody crate records its generated export passwords and the part's salt in an
owner-only test directory. After scanning the child's whole memory, the harness reads that file and
independently derives both AES keys with Python 3's PBKDF2, including the deliberately failed open's
key. It searches for all four secrets, with planted password and AES-key controls in debug and
release. This instrumentation exists only in the custody test tool; no library API or feature
exposes these secrets. The test directory is removed when the harness finishes.

The store XML inside the part is whatever version the store writes; at store version 3 it carries
the accepted roots and their CAs (decision 0008). The plaintext framing is unchanged, so its version
byte stays `2`, and a part holding store version 2 XML still restores. On restore a part's roots are
trusted by decision 0011's rules, as a backup's are: kept beside the destination's accepted roots
and reported in `RestoreReport::roots`; a root no certificate in the part chains to is left out.

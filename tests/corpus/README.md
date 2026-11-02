# Test corpus

Files QGT's tests read. **Everything here is test data made from test keys.** Nothing is ARRL's, no
real ham's certificate or key is here, and LoTW would refuse all of it. Never add a real certificate,
key, backup or log.

## pki

Made by [`scripts/make-test-pki.sh`](../../scripts/make-test-pki.sh) with OpenSSL 3, shaped the way
TQSL 2.8.7 reads LoTW's certificates. Keys are random, so the files were made once and committed; the
script is run again only to change them.

| File | What it is |
| --- | --- |
| `root.pem` | A test root, "QGT Test Root" (O=QSO Graph Trust TEST ONLY, OU=Not ARRL) |
| `ca.pem` | A test issuing CA, signed by the root |
| `user-1024.pem`, `user-2048.pem` | Operator certificates for `QG0TEST` (Q prefixes are never issued), DXCC 291, QSO dates 2020-01-01 to 2099-12-31, with 1024- and 2048-bit keys |
| `user-*.key.pem` | Their private keys, unencrypted PKCS#8 |
| `user-*.tq6` | The certificate response ARRL would send: gzipped XML holding the root, CA and operator certificates |
| `user-*-aes.p12` | PKCS#12 backups as TQSL makes them by default (AES-256, PBES2) |
| `user-*-legacy.p12` | PKCS#12 backups as TQSL's weak-crypto option makes them (RC2-40 and 3DES, SHA-1 MAC) |

The `.p12` password is `qgt-test`: a test password for test keys.

## Coming with the tqsllib harness (phase 2, qso-graph-desktop#171)

TQSL's own file formats are made by tqsllib itself, so they are exact: its key files (`keys/<call>`,
plain and password-protected), `station_data`, `.tbk` backups, `uploaded.db`, and signed `.tq8` logs.

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
| `user-1024.pem` | The operator certificate for `QG0TEST` (Q prefixes are never issued), DXCC 291, QSO dates 2020-01-01 to 2099-12-31, with a 1024-bit key, as LoTW's are |
| `user-1024-pbkdf2-sha1.key.pem` | The same key, encrypted as older OpenSSL wrote TQSL's keys (PBES2, PBKDF2 with HMAC-SHA1, 2,048 iterations, 3DES), password `qgt-key`; made in the same run |
| `user-*.key.pem` | Their private keys, unencrypted PKCS#8 |
| `user-*.tq6` | The certificate response ARRL would send: gzipped XML holding the root, CA and operator certificates |
| `user-*-aes.p12` | PKCS#12 made by OpenSSL with TQSL's default encryption (AES-256, PBES2), holding the key and the chain to the root |
| `user-*-legacy.p12` | The same with TQSL's weak-crypto option (RC2-40 and 3DES, SHA-1 MAC) |

The `.p12` files test reading the encryptions TQSL uses. They are not TQSL's own backups: TQSL also
adds bag attributes (callsign, QSO dates, DXCC), so those come from tqsllib in phase 2.

The `.p12` password is `qgt-test`: a test password for test keys. The key and `.p12` files are
named one by one in `.github/secret_scanning.yml`, so GitHub's secret scanning passes over these
and still catches a real key committed anywhere else.

## Coming with the tqsllib harness (phase 2, qso-graph-desktop#171)

TQSL's own file formats are made by tqsllib itself, so they are exact: its key files (`keys/<call>`,
plain and password-protected), `.p12` exports with TQSL's bag attributes, `station_data`, `.tbk` backups, `uploaded.db`, and signed `.tq8` logs.

## The test log

`adif/qg0test-small.adi` is six QSOs from QG0TEST, for TQSL to sign into the reference `.tq8` and
for QGT's mapping from ADIF to LoTW's signed fields. The station is the test call QG0TEST; the contacted calls are KI7MT's own former calls,
KC4QPQ, KN4YU, M0EHA and KE1HA, used at his choice (2026-11-03), so no stranger's call is in a test.
The station call can start with Q, but a contacted call can't: tqsllib refuses one starting with Q
or 0, or with 1 before anything but A, M or S (TQSL 2.8.7 `src/tqslconvert.cpp`,
`hasValidCallSignChars`). The records cover ADIF MODE and SUBMODE (FT8 and
FT4 as MFSK), a six-digit time, a lowercase call, a satellite QSO with split bands and frequencies, a
frequency outside its band (left out of the signature), and no frequency at all.

## Made by tqsllib: `tqsl/`

`scripts/make-tqsl-corpus.sh` makes these with tqsllib 2.8.7 itself, inside the harness container
(`tests/tqsllib`), with no network. A test CA plays ARRL's part: tqsllib makes the key and the request,
the test CA issues the certificate as a `.tq6`, and tqsllib loads it, as a ham's TQSL does.

| Path | What |
| --- | --- |
| `pki/root.pem`, `pki/ca.pem` and their `.key` files | The test root and CA ("QSO Graph Trust TEST ONLY", "Not ARRL"), with their keys: test keys that nothing trusts |
| `<case>/tqsl/` | tqsllib's own folder after the run: `keys/QG0TEST`, `certs/root`, `certs/authorities`, `certs/user`, `station_data`, `uploaded.db`, `dberr.log` |
| `<case>/QG0TEST.tq5` | The request tqsllib made |
| `<case>/QG0TEST.tq6` | The certificate, as ARRL would send it |
| `<case>/QG0TEST.p12`, `QG0TEST-weak.p12` | tqsllib's exports: AES-256 with PBKDF2, and its weak-crypto option (RC2-40, 3DES), password `qgt-test` |
| `<case>/qg0test-small.tq7` | The test log signed: `tCERT`, `tSTATION` and six `tCONTACT` records |
| `<case>/key-password` | The key's password, exactly, empty for none: the tests read it from here |

The cases:

| Case | Key |
| --- | --- |
| `1024` | Made by tqsllib, no password |
| `1024-password` | Made by tqsllib, password `qgt-key` (3DES-encrypted PKCS#8). The script proves it does not sign without it |

Both are 1024-bit: LoTW's keys are, and tqsllib 2.8.7 makes no other size (`src/openssl_cert.cpp:653`).

The station location is `QG0TEST Home`: Kansas, Sedgwick County, EM17, CQ zone 4, ITU zone 7.

## `standard/`: the standard test set

KI7MT's standard test set (2026-11-03, qso-graph-desktop#172): what a ham's TQSL 2.8.7 holds, made by
`scripts/make-standard-set.sh` in the harness container with no network. tqsllib makes each key and
request and loads each certificate; then TQSL's app itself runs in a virtual display and, as it closes,
writes its own automatic backup, `standard.tbk`. The calls are KI7MT's former ones, his choice; every
key, certificate and password is a test one, from the same kind of test CA ("TEST ONLY", "Not ARRL").

| Call | Certificate | Key password | Locations |
| --- | --- | --- | --- |
| KC4QPQ | QSOs 2000-01-01 to 2099-12-31, in force 3 years | set | KC4QPQ-HOME (Charleston, FM02); parks KC4QPQ-MN35 Fort Sumter and KC4QPQ-NS09 Charles Pinckney (Charleston, FM02), KC4QPQ-NP12 Congaree (Richland, EM93), KC4QPQ-TR10-MP06 Overmountain Victory NHT + Kings Mountain (York, EM95) |
| KN4YU | the club call; the same dates | none | KN4YU-CLUB (Charleston, FM02) |
| W4W | the special-event call: QSOs and validity for one month from the day it was made | set | W4W-EVENT (Charleston, FM02) |

All are South Carolina, DXCC 291, ITU zone 8, CQ zone 5. The certificates' serials are 10001, 10002 and
10003, small numbers as ARRL's are, so TQSL records each (it reads a serial into a `long`, and writes `-1`
for one that does not fit). `MANIFEST` says when it was made.

| Path | What |
| --- | --- |
| `pki/` | The test root and CA, with their keys |
| `requests/<call>.tq5` | The request tqsllib made |
| `certs/<call>.tq6` | The certificate, as ARRL would send it |
| `keys/<call>.password` | The key's password, exactly, empty for none |
| `adif/<location>.adi` | A test log of three QSOs for each location, its own (tqsllib signs a QSO once) |
| `signed/<location>.tq7` | That log, signed by tqsllib at that location |
| `tqsl/` | tqsllib's own folder: all three keys and certificates, `station_data`, `uploaded.db` |
| `standard.tbk` | TQSL's backup of all of it: 3 certificates with their keys, 7 locations, the 21 QSOs it has signed, its settings |

W4W's certificate is in force for a month only, so tests sign at a time inside each certificate,
never at the time they run.

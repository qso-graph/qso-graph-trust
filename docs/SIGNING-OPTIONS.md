<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE. -->
# Signing with TQSL's log handling preferences

`options::SigningOptions` is local to a conversion. Build it by hand, or with
`SigningOptions::from(&backup.preferences)`. Reading a backup does not change signing settings.
Cabrillo contest definitions stay in the backup's preferences; they do not affect ADIF signing.

Pass the same options to `Qso::from_adif_with_options` and
`signed_log::sign_log_with_options`. For duplicate checking and recording, use
`Store::prepare_signing_with_options`, inspect the plan, choose the QSOs, sign the selection, and
write it with `SignedLog::write_to`. The plan keeps the normalized QSOs and the resolved location of
each one. A location inherited from an earlier QSO survives even when that earlier QSO is skipped
as already signed. Signing and the saved record use the same snapshots.

The existing `Qso::from_adif`, `sign_log`, and `Store::prepare_signing` entry points keep their
behavior. Default options produce the existing differential corpus's signed logs byte for byte.
The explicit report option also implements TQSL's filling of empty location fields; the existing
`sign_log` entry point retains its strict station comparison.

The behavior comes from TQSL 2.8.7, commit `d9e01726e54887f8241e86e789c5b91f02043ebd`:

| Option | Behavior | Source lines |
|---|---|---|
| `adif_modes` | Overlay ARRL's ADIF map; try mode/submode, bare submode, then mode. Native LoTW mode redefinitions are ignored, as in the app. | `apps/tqsl.cpp:684–713`; `src/location.cpp:1487–1598`; `src/tqslconvert.cpp:1404–1441` |
| `ignore_seconds` | Set seconds to zero before signing and building the duplicate key. | `src/tqslconvert.cpp:1017–1023, 1312–1318, 1819–1839`; app passes it at `apps/tqsl.cpp:2290–2291` |
| `ignore_log_callsigns` | Disregard STATION_CALLSIGN and OPERATOR. The selected certificate and station still have to agree. | `src/tqslconvert.cpp:1076–1100, 1275–1287`; `apps/tqsl.cpp:2292–2293` |
| `allow_bad_calls` | Bypass the contacted CALL's amateur-call plausibility check, including prefix, letters/digits, and slash checks. Dates, bands, modes and other validation still apply. | `src/tqslconvert.cpp:1390–1402, 2232–2287`; `apps/tqsl.cpp:2286–2288` |
| `qth` | Ignore log location details; report populated-field differences and fill empty fields; or update from the log, carrying changes forward. Updating the primary subdivision clears county/zone selections absent from the new lists, before later log fields are applied. Codes and labels come from ARRL's generated tables. | `src/tqslconvert.cpp:1116–1187, 1499–1530, 1582–1811`; label normalization in `src/location.cpp:4076–4200`; `apps/tqsl.cpp:2295`; preference labels in `apps/tqsl_prefs.cpp:556–563` |

These APIs accept one explicitly selected certificate. A log that needs another call's or DXCC
entity's certificate is refused. The caller must select that certificate and location explicitly.
No preference permits signing with a key that does not match the certificate.

`tests/tqsllib/make-options.py` drives the reference library with the existing generated standard
set's test keys and certificates. `tests/corpus/signing-options` contains successful signed logs,
their exact duplicate database keys and station descriptions, and planted refusal cases.
`crates/qso-graph-trust/tests/signing_options.rs` compares complete signed records and signatures,
then writes and checks the saved duplicate records. The existing differential and standard-set
suites also exercise explicit default options.

The custom-map corpus includes a MODE/SUBMODE case where TQSL revisits its lookup after producing
certificate and station records and unlocking the key (`tqslconvert.cpp:1404–1435, 1563–1579,
1806–1821`). SUBMODE remains present after MODE is mapped; the first QSO can consequently receive
a different final mode from a later QSO with the same input mode. Both the signature and duplicate
record are checked against this case. The OPERATOR refusal case puts the differing operator on
the second QSO: TQSL emits its identification record before the first QSO's operator normalization
(`tqslconvert.cpp:1228–1230, 1275–1287`).
The VUCC case also checks the first-record normalization order and TQSL's treatment of equal-size
grid lists (`tqslconvert.cpp:1271–1274, 1651–1694`). Non-amateur calls still have the converter's
20-byte field limit; printable Unicode calls and their duplicate keys are included in the corpus.

To regenerate, build `tests/tqsllib/qgt-tqsllib.cpp` against tqsllib 2.8.7, then run:

```sh
python3 tests/tqsllib/make-options.py /path/to/qgt-tqsllib
```

This uses no network and no new Rust dependency. Passwords for the generated test keys are read
from the standard set's files and passed in the child environment.
Generated reference files carry a license preamble, removed before comparing tqsllib's bytes.

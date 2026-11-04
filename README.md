# QSO Graph Trust (QGT)

Sign your logs and upload them to ARRL's Logbook of The World (LoTW), with your private key kept by
your computer's own credential store (macOS Keychain, Windows Credential Manager, the Linux Secret
Service) rather than in a file.

QGT is an alternative to TQSL, built on enterprise engineering practice: a memory-safe
implementation, keys held by the OS, and every behaviour proved by tests against TQSL itself. It
reads the certificates and files TQSL uses, and the loggers that call `tqsl` today can call QGT the
same way.

> **Status: in development, not yet usable.** QGT signs nothing yet. It is planned to ship with QSO
> Graph Desktop 0.7.0; the work and its gates are tracked in
> [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169).

## What it is

| Part | What it does | Where |
| --- | --- | --- |
| The library | Certificates, station locations, signing, upload and duplicate tracking. Shared by everything below | [`crates/qso-graph-trust`](crates/qso-graph-trust) |
| `qg-trust`, the command line | tqsl-compatible options, exit codes and status line, for loggers and scripts | [`crates/qso-graph-trust-cli`](crates/qso-graph-trust-cli) |
| QSO Graph Desktop | QG Trust's interface: an extension, using the library ([decision 0005](docs/decisions/0005-qso-graph-desktop-is-the-interface.md)) | [qso-graph-desktop](https://github.com/qso-graph/qso-graph-desktop) |

## How it is built

| Phase | Done when | Issue |
| --- | --- | --- |
| 1 Foundation | CI green on Windows, macOS and Linux; the no-C and no-unsafe checks proved by planted cases | [#170](https://github.com/qso-graph/qso-graph-desktop/issues/170) |
| 2 Signing core | Byte-identical to tqsllib on LoTW's 1024-bit keys, with and without a password | [#171](https://github.com/qso-graph/qso-graph-desktop/issues/171) |
| 3 The library | All 220 tqsllib functions mapped and tested; fuzzing clean; the key found nowhere it shouldn't be | [#172](https://github.com/qso-graph/qso-graph-desktop/issues/172) |
| 4 CLI tools | Loggers' real calls behave the same; LoTW processes the uploads | [#173](https://github.com/qso-graph/qso-graph-desktop/issues/173) |
| 5 QSO Graph Desktop extension and packaging | Signed packages on three platforms | [#174](https://github.com/qso-graph/qso-graph-desktop/issues/174) |

## Building

With Rust installed ([rustup](https://rustup.rs) installs the version `rust-toolchain.toml` names):

```sh
cargo test --workspace
cargo xtask policy      # no C in the library, no unsafe code
cargo run -p qso-graph-trust-cli -- --version
```

## Credits

QSO Graph Trust stands on other people's work.

**TrustedQSL (TQSL)** and the people who built it and keep it running. TQSL's contributors, as its
`AUTHORS.txt` lists them, are **WA1GON, K1MK, KE3Z, K1MU, KC2YWE and AA6YQ**, with ARRL. Since 2003 their
work has carried the signature on every QSO confirmed through Logbook of The World: a signing format, a
certificate system and a program that hams on every platform rely on, kept current through two decades of
operating systems, library changes and new modes, as volunteers. Thank you.

**ARRL**, for LoTW itself and for documenting it for developers.

**rfrht's [qso-web](https://github.com/rfrht/qso-web)**, which showed, with a shell script and OpenSSL, that
a `.tq8` built without TQSL is one LoTW accepts.

## Sources

QG Trust is a ground-up rewrite in Rust, not a method-by-method port of TQSL. What it does was decided
from these, and how is QG Trust's own:

- **ARRL's LoTW developer documentation:** [developer information](https://lotw.arrl.org/lotw-help/developer-information/),
  [the signed log, `.tq8`](https://lotw.arrl.org/lotw-help/developer-tq8/),
  [submitting QSOs](https://lotw.arrl.org/lotw-help/developer-submit-qsos/),
  [LoTW's PKI](https://lotw.arrl.org/lotw-help/developer-pki/),
  [certificate security](https://lotw.arrl.org/lotw-help/certificatesecurity/),
  [station locations](https://lotw.arrl.org/lotw-help/stnloc/),
  [TQSL's command line](https://lotw.arrl.org/lotw-help/cmdline/), and the
  [LoTW Trusted Partners guidelines](https://www.arrl.org/files/file/LoTW_Developer/LoTW%20Trusted%20Partners-1_0.pdf).
- **TrustedQSL:** [its source](https://git.code.sf.net/p/trustedqsl/tqsl) at v2.8.7, read for what LoTW
  receives; [tqsllib's API documentation](https://www.rickmurphy.net/lotw/doxygen/); and
  [TQSL's change log](https://lotw.arrl.org/lotw-help/tqslchangelog/). QG Trust carries two things of
  TQSL's, both ARRL's, under ARRL's terms: the TQSL configuration (`config.xml`), from which the LoTW
  tables are generated, and ARRL's root and CA certificates as TQSL embeds them. TQSL 2.8.7, built from
  its own source, is the reference every signature QG Trust makes is tested against, byte for byte.
- **Other open-source projects:** qso-web, above, and a survey of 126 ham-radio Rust crates on crates.io
  (qso-graph-devel#112), which found no other LoTW signing crate.
- **Standards:** [ADIF 3.1.7](https://adif.org/317/ADIF_317.htm); RFC 5280 (X.509 certificates),
  RFC 4055 and RFC 8017 (RSA), RFC 1952 (gzip); W3C XML 1.0.

How QG Trust compares with TQSL, feature by feature, and what it will and won't do:
[`docs/FEATURE-PARITY.md`](https://github.com/qso-graph/qso-graph-trust/blob/main/docs/FEATURE-PARITY.md).

## Licence

GPL-3.0-only ([LICENSE](LICENSE)); see [NOTICE](NOTICE). QGT is not made or endorsed by ARRL.
"Logbook of The World", "LoTW" and "TQSL" are ARRL's names, used here only to say what QGT works with.

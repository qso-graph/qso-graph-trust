# QSO Graph Trust (QGT)

Sign ADIF logs for ARRL's Logbook of The World (LoTW). The goal: your private key kept by your
computer's own credential store (macOS Keychain, Windows Credential Manager, the Linux Secret Service)
rather than in a file, and the logs you sign uploaded to LoTW.

QGT is an alternative to TQSL, built on enterprise engineering practice: a memory-safe
implementation, keys held by the OS, and every behaviour proved by tests against TQSL itself. It reads
the certificates and files TQSL uses, and its command line is to take the options loggers give `tqsl`
today.

> **Status: beta.** The library is on crates.io as
> [`qso-graph-trust`](https://crates.io/crates/qso-graph-trust). It signs an ADIF log into the `.tq8`
> LoTW accepts, identical byte for byte to TQSL's, with the certificate and key read from a TQSL
> backup (`.tbk`). Keeping keys in the credential store, uploading, requesting certificates, the
> command line and QSO Graph Desktop's extension are still to come, for QSO Graph Desktop 0.7.0; the
> work and its gates are tracked in
> [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169).

## What it is

| Part | What it does | Where |
| --- | --- | --- |
| The library | Certificates, station locations, TQSL backups and signing today; the credential store, upload and duplicate tracking to come. Shared by everything below | [`crates/qso-graph-trust`](crates/qso-graph-trust), on crates.io |
| The binding | LoTW's signature from AWS-LC, the one crate with `unsafe` code ([decision 0006](docs/decisions/0006-aws-lc-signs.md)) | [`crates/qso-graph-trust-awslc`](crates/qso-graph-trust-awslc), on crates.io |
| `qg-trust`, the command line | To come: tqsl-compatible options, exit codes and status line, for loggers and scripts | [`crates/qso-graph-trust-cli`](crates/qso-graph-trust-cli) |
| QSO Graph Desktop | QG Trust's interface: an extension, using the library ([decisions 0005](docs/decisions/0005-qso-graph-desktop-is-the-interface.md) and [0007](docs/decisions/0007-inside-the-credential-core.md)) | [qso-graph-desktop](https://github.com/qso-graph/qso-graph-desktop) |

## How it is built

| Phase | Done when | Status | Issue |
| --- | --- | --- | --- |
| 1 Foundation | CI green on Windows, macOS and Linux; the no-C and no-unsafe checks proved by planted cases | Done | [#170](https://github.com/qso-graph/qso-graph-desktop/issues/170) |
| 2 Signing core | Byte-identical to tqsllib on LoTW's 1024-bit keys, with and without a password | Gate met: signing matches tqsllib byte for byte (issue still open) | [#171](https://github.com/qso-graph/qso-graph-desktop/issues/171) |
| 3 The library | All 220 tqsllib functions mapped and tested; fuzzing clean; the key found nowhere it shouldn't be | In progress: TQSL backups read, keys wiped from freed memory | [#172](https://github.com/qso-graph/qso-graph-desktop/issues/172) |
| 4 CLI tools | Loggers' real calls behave the same; LoTW processes the uploads | Not started | [#173](https://github.com/qso-graph/qso-graph-desktop/issues/173) |
| 5 QSO Graph Desktop extension and packaging | Signed packages on three platforms | Not started | [#174](https://github.com/qso-graph/qso-graph-desktop/issues/174) |

What is done, planned and left out, feature by feature against TQSL:
[`docs/FEATURE-PARITY.md`](docs/FEATURE-PARITY.md).

## Using the library

```sh
cargo add qso-graph-trust@0.1.0-beta.2
```

The library's [README](crates/qso-graph-trust/README.md) shows reading a TQSL backup and signing a log.

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
- **Other open-source projects:** qso-web, above, and a survey of 126 ham-radio Rust crates on crates.io,
  which found no other LoTW signing crate.
- **Standards:** [ADIF 3.1.7](https://adif.org/317/ADIF_317.htm); RFC 5280 (X.509 certificates),
  RFC 4055 and RFC 8017 (RSA), RFC 1952 (gzip); W3C XML 1.0.

## Licence

GPL-3.0-only ([LICENSE](LICENSE)); see [NOTICE](NOTICE). QGT is not made or endorsed by ARRL.
"Logbook of The World", "LoTW" and "TQSL" are ARRL's names, used here only to say what QGT works with.

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
| `qgt`, the command line | tqsl-compatible options, exit codes and status line, for loggers and scripts | [`crates/qgt`](crates/qgt) |
| QSO Graph Trust, the app | For hams who don't use a command line; arrives in phase 5 | not yet |
| QSO Graph Desktop | Uses the library through its own Rust core | [qso-graph-desktop](https://github.com/qso-graph/qso-graph-desktop) |

## How it is built

| Phase | Done when | Issue |
| --- | --- | --- |
| 1 Foundation | CI green on Windows, macOS and Linux; the no-C and no-unsafe checks proved by planted cases | [#170](https://github.com/qso-graph/qso-graph-desktop/issues/170) |
| 2 Signing core | Byte-identical to tqsllib on 1024- and 2048-bit keys | [#171](https://github.com/qso-graph/qso-graph-desktop/issues/171) |
| 3 The library | All 220 tqsllib functions mapped and tested; fuzzing clean; the key found nowhere it shouldn't be | [#172](https://github.com/qso-graph/qso-graph-desktop/issues/172) |
| 4 CLI tools | Loggers' real calls behave the same; LoTW processes the uploads | [#173](https://github.com/qso-graph/qso-graph-desktop/issues/173) |
| 5 QSO Graph Desktop and the app | Signed packages on three platforms | [#174](https://github.com/qso-graph/qso-graph-desktop/issues/174) |

## Building

With Rust installed ([rustup](https://rustup.rs) installs the version `rust-toolchain.toml` names):

```sh
cargo test --workspace
cargo xtask policy      # no C in the library, no unsafe code
cargo run -p qgt -- --version
```

## Licence

GPL-3.0-only ([LICENSE](LICENSE)); see [NOTICE](NOTICE). QGT is not made or endorsed by ARRL.
"Logbook of The World", "LoTW" and "TQSL" are ARRL's names, used here only to say what QGT works with.

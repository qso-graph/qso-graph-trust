# Working on QSO Graph Trust

Instructions for anyone, human or AI agent, changing this repository. The hard rules first, then how to
build and check. When a rule here and your task disagree, stop and ask.

## What this is

**QSO Graph Trust (QGT) signs logs for ARRL's Logbook of The World (LoTW) with the operator's key held by
the OS credential store.** One Rust library, shared by QSO Graph Desktop, the QGT app, the `qgt`
command line and other people's tools. It is an alternative to TQSL: described as an alternative, never
as replacing or fixing TQSL, and TQSL's behaviour is stated as facts with their source, never as faults.

The core requirement: **the ham's key stays theirs, and only the QSOs they mean to sign get signed,
exactly as LoTW accepts them.** ARRL revokes everything a ham has in LoTW if their key is compromised.

## Rules (each one has a test you can apply)

- **No C or C++ in the library.** Nothing in `qso-graph-trust`'s dependency tree, on any platform or feature,
  links a native library or builds C, C++ or assembly, and every crate it takes from outside the
  workspace comes from crates.io and is reviewed by exact name and version before it is added
  (`REVIEWED` in `xtask/src/lib.rs`). *Test: `cargo xtask policy`.* An exemption names one exact
  crate with a decision record in `docs/decisions/`, never a pattern.
- **No unsafe code.** Every crate root says `#![forbid(unsafe_code)]` and every crate takes the
  workspace's lints. *Test: `cargo xtask policy`.*
- **The key never leaves the OS credential store** except as a signature, or as a backup QGT encrypts
  itself. No API returns it, and it is never in a file, log, trace, error, IPC message or crash dump.
- **Signatures match tqsllib's byte for byte.** A change to signing comes with a differential test
  against tqsllib. *Test: the differential suite (phase 2).*
- **TLS verification is never turned off,** the user agent names QGT truthfully, and a password never
  appears on a command line, in a URL, a trace or a log.
- **Test data only.** Never commit or attach a real certificate, private key, `.p12`, `.tbk`, password or
  real QSO log. The corpus in `tests/corpus` is generated from test keys.
- **A new check is proved by a planted case** that fails it, then passes without it.
- **Pin, don't float.** Exact versions for anything in the key, crypto, signing or packaging path;
  `Cargo.lock` is committed and CI builds `--locked`.
- **House rules:** every new file starts with the SPDX header (`GPL-3.0-only`, see `CONTRIBUTING.md`);
  changes go in by pull request; branches are `feat-…`, `fix-…` or `docs-…`; match the code around you,
  and don't rename or reformat what your task doesn't need.

## Build and check

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask policy
```

**What CI checks:** formatting, clippy and the tests on Windows, macOS and Linux; the policy checks;
and `cargo audit` of `Cargo.lock`, on every pull request and weekly. `ci-all-green` is the one result a
merge waits for.

## Where the real documents are

- **Decisions and why:** [`docs/decisions/`](docs/decisions/).
- **The plan and its gates:** [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169)
  and its phase issues, #170 to #174.
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md). **Security:** [`SECURITY.md`](SECURITY.md).

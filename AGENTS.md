# Working on QSO Graph Trust

Instructions for anyone, human or AI agent, changing this repository. The hard rules first, then how to
build and check. When a rule here and your task disagree, stop and ask.

## What this is

**QSO Graph Trust (QGT) signs logs for ARRL's Logbook of The World (LoTW) with the operator's key held by
the OS credential store.** One Rust library, shared by QSO Graph Desktop (QG Trust's interface, as an
extension), the `qg-trust` command line and other people's tools. It is an alternative to TQSL: described
as an alternative, never as replacing or fixing TQSL, and TQSL's behaviour is stated as facts with their source, never as faults.

The core requirement: **the ham's key stays theirs, and only the QSOs they mean to sign get signed,
exactly as LoTW accepts them.** ARRL revokes everything a ham has in LoTW if their key is compromised.

## Rules (each one has a test you can apply)

- **No C or C++ in the library.** Nothing in `qso-graph-trust`'s dependency tree, on the platforms
  QGT ships and with every feature, compiles or ships C, C++ or assembly source, uses a crate that
  builds native code, or links anything but the operating system. Crates that only bind the OS
  (`OS_BINDINGS`) and Rust's own `asm!` in a reviewed outside crate are allowed (decision 0002).
  **Cryptographic primitives come from vetted providers, each named in the policy checks:**
  `aws-lc-rs` (QSO Graph Desktop's) for TLS and every operation it offers, and RustCrypto's `rsa` for
  LoTW's RSA-SHA-1 signature, which aws-lc-rs does not sign. The library never signs for a remote
  caller (decision 0002, amended 2026-11-03). *Test: `cargo xtask policy` and `cargo deny`.*
- **Every outside crate a shipped crate uses is reviewed,** by exact name and version, through
  cargo-vet: an imported audit, a trusted publisher, or our own (`supply-chain/`, decision 0004).
  It comes from crates.io only. *Test: `cargo vet` and `cargo deny`.* The no-C rule is the
  library's alone; the command line carries the TLS stack, which is C.
- **No unsafe code.** Every crate is edition 2024, every crate root says `#![forbid(unsafe_code)]`,
  and every crate takes the workspace's lints, which forbid it too. Together these make rustc refuse
  every `extern` block and all assembly in our own code. Every source file is also read as tokens,
  whatever its `cfg`, and no workspace crate defines a macro (`macro_rules!` or procedural).
  *Test: `cargo xtask policy`.*
- **No key data is left in freed memory, whichever library allocated it.** Every QG Trust program
  (`qg-trust`, QSO Graph Desktop's native code) installs a wiping global allocator, so every freed block
  is overwritten; libraries such as `rsa` and `num-bigint-dig` wipe their own temporaries only in part
  (decision 0002). *Test: `cargo xtask policy` refuses a program without it (with the allocator, phase
  3, qso-graph-desktop#172), and the custody test finds no key data in memory or a crash dump.*
- **The key never leaves the OS credential store** except as a signature, or as a backup QGT encrypts
  itself. No API returns it, and it is never in a file, log, trace, error, IPC message or crash dump.
- **Signatures match tqsllib's byte for byte.** A change to signing comes with a differential test
  against tqsllib. *Test: the differential suite (phase 2).*
- **What LoTW receives is the same as TQSL's; how QGT gets there is its own design.** The signed
  string, signature and `.tq8` records match tqsllib's exactly. QGT's errors, storage and interface
  follow its own requirements, not tqsllib's internal behaviour (KI7MT, 2026-11-03). Code written to
  drive tqsllib lives only in `tests/tqsllib/`.
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

**What CI checks:** formatting, clippy and the tests on Windows, macOS and Linux; the policy checks
and the canary; `cargo vet`, `cargo deny` and `cargo audit`, on every pull request and weekly. `ci-all-green` is the one result a
merge waits for.

## Where the real documents are

- **Decisions and why:** [`docs/decisions/`](docs/decisions/).
- **The plan and its gates:** [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169)
  and its phase issues, #170 to #174.
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md). **Security:** [`SECURITY.md`](SECURITY.md).

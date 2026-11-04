# Working on QSO Graph Trust

Instructions for anyone, human or AI agent, changing this repository. The hard rules first, then how to
build and check. When a rule here and your task disagree, stop and ask.

## What this is

**QSO Graph Trust (QGT) signs logs for ARRL's Logbook of The World (LoTW), and is built to keep the
operator's key in the OS credential store.** One Rust library, shared by QSO Graph Desktop (QG Trust's interface, as an
extension), the `qg-trust` command line and other people's tools. It is an alternative to TQSL: described
as an alternative, never as replacing or fixing TQSL, and TQSL's behaviour is stated as facts with their source, never as faults.

The core requirement: **the ham's key stays theirs, and only the QSOs they mean to sign get signed,
exactly as LoTW accepts them.** A compromised key signs QSOs in the ham's name: ARRL revokes its
certificate, and the QSOs submitted with it, and the confirmations and credit they earned, can be
removed (ARRL's [certificate security](https://lotw.arrl.org/lotw-help/certificatesecurity/)).

## Rules (each one has a test you can apply)

- **No C or C++ in the library but its named providers.** Nothing in `qso-graph-trust`'s dependency tree, on the platforms
  QGT ships and with every feature, compiles or ships C, C++ or assembly source, uses a crate that
  builds native code, or links anything but the operating system. Crates that only bind the OS
  (`OS_BINDINGS`), Rust's own `asm!` in a reviewed outside crate, and one cryptographic provider,
  `aws-lc-sys`, reached only through the binding, are allowed (decisions 0002 and 0006).
  **Cryptographic primitives come from vetted providers, each named in the policy checks:**
  `aws-lc-rs` (QSO Graph Desktop's) for TLS and every operation it offers, certificate signature
  checks included, and AWS-LC, through QG Trust's one binding, for LoTW's RSA-SHA-1 signature, which
  aws-lc-rs does not sign (decision 0006); in QG Trust both are reached only through the binding;
  RustCrypto's `rsa` is a test tool only, never shipped. The library never signs for a remote
  caller (decision 0002, amended 2026-11-03). *Test: `cargo xtask policy` and `cargo deny`.*
- **Every outside crate a shipped crate uses is reviewed, or listed as not reviewed yet,** by exact
  name and version, through cargo-vet: an imported audit, a trusted publisher, our own, or an
  exemption, which cargo-vet means as "not audited yet", listed in the open in
  `supply-chain/config.toml` (decision 0004).
  It comes from crates.io only. *Test: `cargo vet` and `cargo deny`.* The no-C rule is the
  library's alone; the command line carries the TLS stack, which is C.
- **No unsafe code, but in one named binding.** `qso-graph-trust-awslc`, which calls AWS-LC to sign
  (decision 0006), is the only crate allowed unsafe code, with its own strict lints. Every other crate is edition 2024, every crate root says `#![forbid(unsafe_code)]`,
  and every crate takes the workspace's lints, which forbid it too. Together these make rustc refuse
  every `extern` block and all assembly in our own code. Every source file is also read as tokens,
  whatever its `cfg`, and no workspace crate defines a macro (`macro_rules!` or procedural).
  *Test: `cargo xtask policy`.*
- **No key data is left in freed memory, whichever library allocated it.** Every QG Trust program
  (`qg-trust`, QSO Graph Desktop's native code) installs a wiping global allocator, so every freed block
  is overwritten; libraries wipe their own temporaries only in part (decision 0002). The allocator is
  1Password's `zeroizing-alloc`, installed as exactly `#[global_allocator] static …:
  zeroizing_alloc::ZeroAlloc<std::alloc::System>`; the custody test's control
  (`qgt-custody-unwiped`) is the one program without it. *Test: `cargo xtask policy` refuses a
  program without it, and the custody test (`crates/qso-graph-trust-custody`, Linux, debug and
  release) reads a signing program's whole memory, as a crash dump holds it, and finds no key data
  or password.*
- **The OS credential store holds the key at rest,** once QGT keeps keys (the store is still to
  come; until then the library holds no key at rest), and it leaves the store only to sign, as a
  signature, or in an export QGT encrypts itself. While it signs, it is in memory, as in every signer,
  so a crash dump taken then can hold it; freed memory never does. No API returns it, and nothing QGT
  writes, logs, traces, reports in an error or sends over IPC holds it.
- **LoTW's tables are ARRL's, never typed in.** Bands, modes, the ADIF mode map, satellites, DXCC
  entities, station-location fields and the signature specification come from ARRL's TQSL
  configuration (`data/tqsl-config/config.xml`, under ARRL's licence beside it), generated into
  `src/lotw/tables.rs` by `scripts/gen-lotw-tables.py`. A new configuration is a regenerated file.
  *Test: `scripts/gen-lotw-tables.py --check`.*
- **Signatures match tqsllib's byte for byte.** A change to signing comes with a differential test
  against tqsllib. *Test: the differential suite (phase 2).*
- **What LoTW receives is the same as TQSL's; how QGT gets there is its own design.** The signed
  string, signature and `.tq8` records match tqsllib's exactly. QGT's errors, storage and interface
  follow its own requirements, not tqsllib's internal behaviour. Code written to
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

## What an agent doesn't change unless its task names it

- **`AUTHORS` lists people.** Never add a tool, a model or an agent to it, or to a copyright line.
- **The READMEs are product pages:** the top-level one and each crate's, which crates.io shows. They say
  what QG Trust is, who it is for and why it is better; they carry no design notes, caveats, test
  counts or work in progress. That writing goes in `docs/decisions/`, `SECURITY.md` or this file.
- **tqsllib and TQSL run only in the harness container**, started by `scripts/make-tqsl-corpus.sh`
  (`podman run --network=none`). Never build or run them on the host, from a copy of the image's
  files or any other way; a corpus made outside the container is not evidence.
- **Nothing calls ARRL.** No test, tool or script connects to `lotw.arrl.org` or uploads anything.
- **cargo-vet entries say why.** Prefer an audit the repo already imports; an exemption is at an exact
  version. Adding a trusted publisher or an audit source is a decision: name it in your summary.
- **A new decision takes the number your task gives it.** If the task gives none, use the next free
  number and say so in your summary, because work on other branches may be using it.

## Build and check

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask policy
python3 scripts/gen-lotw-tables.py --check
python3 scripts/package-files.py --check
python3 scripts/test_release_check.py
```

**What CI checks:** formatting, clippy and the tests on Windows, macOS and Linux; the policy checks
and the canary; `cargo vet`, `cargo deny` and `cargo audit`; and `cargo package` for the binding and the
library, as crates.io would receive them; on every pull request and weekly. `ci-all-green` is the one result a
merge waits for.

## Releasing

A release is KI7MT's, never an agent's: **Actions → Release → Run workflow** from main, with the version
main already says (`X.Y.Z` or `X.Y.Z-beta.N`). It publishes `qso-graph-trust-awslc`, then
`qso-graph-trust`, then `qso-graph-trust-cli`, on crates.io with Trusted Publishing, attests the
packages, and tags the commit
(`.github/workflows/release.yml`; its decisions are `scripts/release_check.py`'s). To prepare one:
set the workspace version in `Cargo.toml` and the `=` pins on the internal dependencies, move the
CHANGELOG's Unreleased section under the version, and merge that by pull request. A crate new to
crates.io publishes once with a token scoped to it alone, `CRATES_IO_FIRST_PUBLISH` in the `crates-io`
Environment; afterwards Trusted Publishing is set up on it, "require trusted publishing" turned on,
and the token deleted and revoked.

## Where the real documents are

- **Decisions and why:** [`docs/decisions/`](docs/decisions/).
- **The plan and its gates:** [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169)
  and its phase issues, #170 to #174.
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md). **Security:** [`SECURITY.md`](SECURITY.md).

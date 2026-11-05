# 0004: Outside crates are reviewed with cargo-vet, and their sources held by cargo-deny

Decided 2026-11-03 by KI7MT, after review of qso-graph-trust#1.

## What was decided

- **cargo-vet** records that every outside crate is reviewed, by exact name and version
  (`supply-chain/`). Reviews come from three places:
  - **audits imported** from Mozilla, Google, the Bytecode Alliance and the Zcash Foundation;
  - **trusted publishers**, whose published crates are accepted without reading every line;
  - **our own audits**, recorded with `cargo vet certify`.

  A crate none of these covers is an **exemption**, which in cargo-vet means "not audited yet",
  listed in the open.
- **cargo-deny** (`deny.toml`) holds the mechanical rules: crates.io only, no git dependency, no
  crate whose job is building C (`cc`, `cmake`, `bindgen` and the like), and licences compatible
  with GPL-3.0-only. Advisories stay with `cargo audit`.
- Both run in CI, pinned (cargo-vet 0.10.3, cargo-deny 0.20.2), beside `cargo xtask policy`.
  `xtask` keeps the checks only it can make: what consumers of the published crates build
  (`[patch]`, path-and-version), our own build scripts, and the no-C and no-unsafe rules.

## The trusted publishers

| Publisher | Crates | Why |
| --- | --- | --- |
| The Rust project (`rust-lang-owner`, `github:rust-lang/*`) | `libc`, `cfg-if`, `lazy_static`, … | Part of Rust itself |
| RustCrypto (`tarcieri`, `newpavlov`, `baloo`, and the `RustCrypto` team) | `rsa`, `sha1`, `pkcs8`, `der`, `digest`, … | The standard pure-Rust cryptography project; using its crypto is already trusting it |
| rust-random (`github:rust-random/*`) | `rand`, `rand_core` | Rust's standard randomness crates |
| David Tolnay (`dtolnay`) | `syn`, `proc-macro2`, `serde`, … | Among the most-used crates in Rust |
| Google (`github:google/zerocopy`) | `zerocopy` | Maintained by Google's Fuchsia team |
| Microsoft (`kennykerr`), added 2026-11-04 | `windows-sys` | Microsoft's own Windows bindings (`microsoft/windows-rs`), led by Kenny Kerr; generated declarations, trusted by Mozilla, the Bytecode Alliance and Zcash. The command line's password prompt needs them on Windows |
| Ed Page (`epage`), added 2026-11-04 | `clap`, `clap_builder`, `clap_derive`, `clap_lex`, `clap_complete`, `anstream`, `anstyle` and its parts, `colorchoice`, two polyfills | Maintainer of clap, Rust's standard command-line parser, and of Cargo's own terminal output; trusted by Mozilla and the Bytecode Alliance. The command line's options, help, completions and styled output; none of it is in the library |

cargo-vet records trust per crate as each crate enters the dependency graph, so the list above
is applied as phase 2 adds them. Today it covers David Tolnay's crates, which are in `xtask`'s
tooling.

**Trust is not a review of the signing code.** The path that signs a ham's QSO (`rsa`'s signing
and `sha1`) is read by us whatever its publisher, and the byte-for-byte tests against tqsllib
are the proof it does what it should. Trust does not mean free of bugs: `rsa` carries the open
Marvin advisory (RUSTSEC-2023-0071).

**Not trusted blindly:** single-maintainer crates (`typenum`, `generic-array`, `spin`,
`ppv-lite86` and the like) are audited, usually as a small difference from an audited
version, or avoided by turning off optional features.

## Why

The rule before this listed every outside crate by name and version in `xtask`'s source,
marked "reviewed". Phase 2's first two crates bring about 37 crates per shipping platform. No one
can honestly claim to have read them all, and a list in source records no reviewer and no
criteria. cargo-vet records both, reuses reviews others have published, and reviews a security
update as a difference, not the whole crate again.

What protects QGT whoever is trusted: every version is pinned in `Cargo.lock`, a published
version on crates.io never changes, a new version arrives only in a pull request KI7MT merges,
and `cargo audit` flags known vulnerabilities.

## What `xtask`'s own tooling is held to

`xtask` never ships, so its dependencies are held to cargo-vet's `safe-to-run`, not
`safe-to-deploy`. Ten of them are exemptions today, not yet audited.

# 0002: No C or C++ in the library; TLS is the one place C is allowed

Decided 2026-11-02 by KI7MT.

## What was decided

Nothing in the dependency tree of `qso-graph-trust`, the crate that holds the key, the signing and
every file parser, may link a native library or build C, C++ or assembly, on any platform.

`cargo xtask policy` enforces it on every pull request, over that tree with every feature on and on
every platform:

- no crate in it declares a native link (`links`);
- no crate in it depends on a crate whose job is building native code (`cc`, `cmake`, `bindgen` and
  the like);
- every crate in it from outside the workspace comes from crates.io, where a published version can
  never change, and is on a reviewed list by **exact name and version**. Reading it is the review:
  no `#[link]` or `extern` block, no assembly, and a build script or procedural macro, if any, that
  compiles nothing. A build script can run a compiler, and an `extern` block can link a library,
  without declaring `links`, so no metadata check can stand in for reading. A new version is a new
  review. The list is empty today;
- every build script or procedural macro in it, a workspace crate's included, is on that list;
- every crate in it keeps its sources inside its own directory, compared after resolving `..` and
  links, and holds no symbolic links;
- as a second line, every file of every crate in it is searched: a `#[link]`, `#[link_name]` or
  `#[link_section]` attribute, an `extern` block, inline or global assembly, or a native source or
  object file (`.c`, `.h`, `.s`, `.o`, `.a`, `.so`, `.dll` and the like) fails the check, even in a
  comment.

**Nothing may weaken those lints.** `--cap-lints` overrides even `forbid(unsafe_code)`, and it can
reach the compiler many ways, so the check works from allowlists rather than lists of refused flags:
the one Cargo configuration file is `.cargo/config.toml`, holding only the `xtask` alias, exactly; no
other Cargo configuration file exists; the environment's rustflags may hold only lint levels (`-D`,
`-W`, `-A` naming a lint other than `unsafe_code`), so no cap, response file (`@path`), native library
or codegen flag; no other compiler, wrapper or linker may be selected; and no workflow may mention a
lint cap, `--config`, `RUSTC`, `cargo rustc`, `CARGO_BUILD`, `CARGO_TARGET` or a link argument, or set
`RUSTFLAGS` other than the one workflow-wide `-D warnings`. CI builds and tests with every feature on.

**And a canary measures the result.** In every CI job, after the tests, `cargo xtask canary` copies
the repository (its manifests and profiles, its Cargo configuration, its toolchain file), adds an
`unsafe` block to the real library in the copy, and builds it in that job's own environment. The
compiler must refuse it with an `unsafe_code` error, read from its JSON diagnostics. A way to weaken
the lints that nobody listed still fails the canary: planted, a compiler wrapper that adds
`--cap-lints=allow` made it fail. The toolchain must be an exact stable release, which refuses
`cargo-features`, and no profile may set `rustflags`.

**The limit.** A commit could change these checks themselves. No check inside the repository can stop
that, so the control for it is that every change to `.github/`, `.cargo/` and `xtask/` reaches `main`
only in a pull request KI7MT merges, where it is read.

**Code no build compiles is still read.** CI builds debug, and a consumer's release build caps this
crate's lints, which overrides `forbid`, so code behind `#[cfg(not(debug_assertions))]` would never
meet the compiler's refusal. Every source file of every workspace crate is therefore read as Rust
tokens, whatever its `cfg`: the identifiers `unsafe`, `include`, `asm`, `global_asm` and `naked_asm`
(raw identifiers and import aliases included), `path =` anywhere in an attribute, and an attribute
named by a macro variable fail the check. **The workspace's crates define no macros**: no
`macro_rules!` and no procedural-macro crate, because a macro can assemble code from pieces no scan
sees whole (review found five such constructions before this rule replaced chasing them). So that nothing compiles from a file the scan does not
read, every crate root is a `.rs` file and a crate's directory holds only `.rs`, `.toml` and `.md`
files. A directory is left out only when it is another workspace crate, or Cargo's output directory
or a workspace exclusion lying outside every crate; inside one, `mod` could still load it. The
planted fixtures therefore live at the repository root, in `tests/policy-fixtures`.

**For the workspace's own crates the compiler is the enforcer.** Each is edition 2024 and forbids
unsafe code (both checked by `cargo xtask policy`), and under those two rules rustc refuses every
`extern` block, `#[link]`ed or not, all inline and global assembly, and `no_mangle`: checked against
rustc 1.99.1. Edition 2021 is not enough: it compiles `extern "C" {}` without `unsafe`, even under
forbid.

What a reviewed crate does is a judgement made by reading it; the check guarantees that judgement is
made for every one, and made again when its version changes. Planted cases prove each rule fails when
broken (`xtask/tests/planted.rs`).

The HTTPS connection to LoTW is the one exception. No production-grade pure-Rust TLS provider exists
(`rustls-rustcrypto` is 0.0.2-alpha and says not to use it in production), so the upload uses rustls
with aws-lc-rs, as QSO Graph Desktop's core already does. It lives in its own crate, outside
`qso-graph-trust`'s tree, so the check still covers everything that touches the key.

## Why the line is there

The core requirement is that the ham's key stays theirs. TLS carries a log that is already signed:
the signature protects its integrity whatever the transport does, and the connection never sees the
key. The key, the signing and the parsers of files from outside are where memory errors would matter.

## What the check allows

Calling the operating system's own interfaces (Keychain, Windows Credential Manager, the Secret
Service over D-Bus) is not a C library linked by QGT. If a crate that reaches them declares a native
link, it is exempted by its exact name in `xtask/src/lib.rs`, with a line here saying why.

Exemptions today: none.

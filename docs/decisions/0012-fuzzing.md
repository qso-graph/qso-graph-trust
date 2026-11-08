# 0012: The file readers are fuzzed with cargo-fuzz and libFuzzer, on a pinned nightly

Decided 2026-11-07 by KI7MT. A named exception to the no-C rule and the pinned-compiler rule of
[0002](0002-no-c-in-the-library.md), for the fuzzers alone.

## What was decided

QG Trust holds the operator's signing key, and its readers take files from outside: logs, ARRL's
`.tq6`, `.p12` files and TQSL's `.tbk` backups. Hardening them adds trust, so they get real
coverage-guided fuzzing, with the established tools rather than our own: **cargo-fuzz 0.13.2 and
libFuzzer (`libfuzzer-sys` 0.4.13), on `nightly-2026-10-30`**, in the standard cargo-fuzz layout. It is
the fuzzing item of Gate C (qso-graph-desktop#172): the readers find no crash and no signature.

## The exception, exactly

libFuzzer is C++, and coverage instrumentation needs a nightly compiler. Both are allowed **in
`fuzz/` only**, and nowhere else:

- `fuzz/` is a Cargo workspace of its own (`[workspace] members = ["."]`), not a member of the
  repository's, with its own `Cargo.lock`. It is `publish = false`, is never shipped, and is never in
  a published crate or in what QSO Graph Desktop links: the library's dependency tree does not
  change, and `cargo xtask policy`'s no-C check of it is untouched.
- libFuzzer links only into the fuzz binaries.
- `fuzz/rust-toolchain.toml` names the dated nightly, and selects it only for builds run in `fuzz/`.
  The root's `rust-toolchain.toml`, an exact stable, still builds everything that ships, and
  `cargo xtask policy` still requires it.
- Every dependency of the fuzz crate is pinned with `=`, or is the library by its path here.

`cargo xtask policy` holds the exception to this and no further ("the fuzzers"): the toolchain file
is allowed at exactly `fuzz/rust-toolchain.toml` and must name a dated nightly; the manifest must
be its own workspace, unpublished, a cargo-fuzz crate, with pinned dependencies; and the fuzzers'
own Rust, `fuzz/src` and `fuzz/fuzz_targets`, is read as tokens as the workspace's crates are, with
no `unsafe`, `include!` or `#[path]`, and every crate root says `#![forbid(unsafe_code)]`. The
tree-walking check leaves out exactly `fuzz/target`, Cargo's output for that workspace, as it leaves
out the root's `target`; the canary's copy leaves out what cargo fuzz writes (`fuzz/.gitignore`).
Planted cases prove each: a toolchain file in `fuzzx/`, `fuzz/sub/`, `crates/lib/fuzz/` or
`fuzzx/target/`, an extensionless `fuzz/rust-toolchain`, a Cargo configuration in `fuzz/`, a floating
nightly, a published or floating manifest, and unsafe code or a missing `forbid` in a target are each
caught (`xtask/tests/planted.rs`).

The fuzz binaries do not install the wiping allocator that every QG Trust program must
([0002](0002-no-c-in-the-library.md)): they are not QG Trust programs, are never distributed, and hold
the test corpus's keys only.

## What the targets check

One target per reader, each driving the library's public entry points the way `qg-trust` does, with
inputs bounded below the library's own limits (`MAX_INPUT`, 256 KiB; CI passes 16 KiB for logs and
64 KiB for the rest):

- **`adif`** and **`adx`**: the log is read as records; every record the library accepts becomes a QSO, every one it
  refuses is left out; QSOs outside the certificate's dates are left out; then the store prepares the
  log, the new QSOs are chosen and signed with the store's key, and each QSO the signer names is left
  out and the rest tried again, as `qg-trust sign` does. The signer is the standard set's KC4QPQ
  certificate and key, in a store with the memory key backend, at its home location, with the log
  handling settings chosen by the input's length so all of them are reached. **No signature for an
  invalid record:** whatever is signed must pass QG Trust's own upload check; every signed QSO must
  read back from its signed record as an ADIF record the library accepts again, be one the library
  accepted from the log, and lie within the certificate's dates; every station location in it must be
  one the library accepts, for the certificate's call and entity; and every signature must be the
  key's over exactly the station's and the QSO's fields.
- **`tq6`** and **`p12`**: imported into a fresh store as `qg-trust import` imports them, and when the
  file brings a root not trusted yet, imported again confirming that root, as an operator would. A
  `.p12` is opened with the corpus's test password. Whatever is imported must be in the store and
  verify under the store's trust; a `.tq6` brings no key, and a `.p12`'s key must be its certificate's
  and sign.
- **`tbk`**: read with `tbk::read` and with `tbk::read_trusting_roots`. Whatever is accepted must hang
  together: every certificate chains to the trust used and is for its entry's call and entity; every
  key is its certificate's, for that call and entity, and one with no password unlocks and signs;
  every station location reads again as itself.

Every target also fails on a panic, a hang (20 seconds an input) and memory use past libFuzzer's
limit. Seeds are copied from `tests/corpus` or generated as synthetic ADX by `fuzz/seed.sh` (a gzipped `.tq6` or `.tbk` also
decompressed, since a mutated gzip stream mostly fails its checksum before the XML), so the test
corpus stays the one copy of each file.

**Readers not fuzzed yet, because QG Trust has none:** Cabrillo, which Gate C names, is not
read by QG Trust today ([FEATURE-PARITY](../FEATURE-PARITY.md): "Later"). It comes with its target
when it is written.

**What a fuzzer cannot reach:** a `.p12`'s contents past its MAC, which a mutated file fails before
anything is decrypted, and a `.tbk`'s password-protected keys, which are checked without their
password. The parsers before them, and every unprotected path, are fuzzed.

## How a finding becomes a test

A crash, hang or broken invariant is fixed in the library, with a regression test in the library's
own tests on the pinned stable, named for what it checks and holding the input's shape (written
out, not a fuzzer's file). The fuzzer's files (`fuzz/artifacts`, `fuzz/corpus`) are never
committed; CI keeps them as a run's artifact when it fails. So every finding stays checked by the
stable build, on every platform, whether or not the fuzzers run.

## CI

The `fuzz` job installs the nightly from `fuzz/rust-toolchain.toml` and cargo-fuzz at its exact
version (`cargo install --locked`), builds every target, and runs each for 60 seconds on a pull
request and 10 minutes on the weekly run. `ci-all-green` needs it.

## What was weighed

- **A mutation fuzzer of our own on the pinned stable,** keeping the rules unexcepted: rejected. It
  would reinvent what libFuzzer already does well (coverage feedback, comparison tracing,
  minimisation, dictionaries), and a fuzzer nobody else uses is one nobody else checks.
- **AFL++ or honggfuzz:** equally C, and no better established for Rust than cargo-fuzz (the rust-fuzz
  project's), which is what OSS-Fuzz builds Rust projects with.
- **OSS-Fuzz:** possible later. It runs these same cargo-fuzz targets continuously; it needs Google's
  acceptance of the project.

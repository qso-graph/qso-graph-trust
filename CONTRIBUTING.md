# Contributing to QSO Graph Trust

Thank you for helping. QGT exists so that a ham's LoTW key is held as carefully as their bank's, so the
most useful contributions make it safer, more exact, or work on one more machine.

**The short version, and the hard rules:** [AGENTS.md](AGENTS.md). Written for AI coding agents, and the
quickest start for anyone.

## How a change gets in

1. Open an issue describing the problem or idea, unless it's a small fix.
2. Make a branch named for the change: `fix-...`, `feat-...` or `docs-...`.
3. Open a pull request. CI runs formatting, clippy and the tests on Windows, macOS and Linux; the
   policy checks; `cargo vet`, `cargo deny` and `cargo audit`; and packages the published crates as
   crates.io would receive them.
4. KI7MT merges. Releases are KI7MT's too: the Release workflow, run by hand (AGENTS.md).

## Building

With Rust installed ([rustup](https://rustup.rs) installs the version `rust-toolchain.toml` names):

```sh
cargo test --workspace
cargo xtask policy      # no C but AWS-LC, no unsafe code outside the binding
cargo run -p qso-graph-trust-cli -- --version
```

The full list of checks CI runs is in [AGENTS.md](AGENTS.md); the plan and its phases are tracked in
[qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169).

### Fuzzing

The file readers are fuzzed with cargo-fuzz and libFuzzer, on the nightly `fuzz/rust-toolchain.toml`
names, in `fuzz/` only ([decision 0012](docs/decisions/0012-fuzzing.md)). rustup installs that nightly
when you run cargo there:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
fuzz/seed.sh                      # seeds fuzz/corpus/<target>/ from tests/corpus
cd fuzz
cargo fuzz list                   # adif, tq6, p12, tbk
cargo fuzz run adif -- -max_total_time=300 -max_len=16384 -timeout=20
```

A crash is saved in `fuzz/artifacts/<target>/`; replay it with `cargo fuzz run <target> <file>`. Fix it
in the library with a regression test there, named for what it checks, never by committing the file.

## Ground rules

- **Test data only.** No real certificate, key, password or QSO log, ever, in code, tests, issues or
  logs. Use `tests/corpus`.
- **Prove it.** A new behaviour has a test; a new check has a planted case it catches; a change to
  signing has a differential test against tqsllib.
- **Record decisions.** A choice someone might later question gets a short record in `docs/decisions/`:
  what was decided, and why.
- **Write for the next maintainer.** Plain language; say why, not only what.

## Licence

QGT is **GPL-3.0-only** ([LICENSE](LICENSE)), as QSO Graph Desktop is. By contributing, you agree your
contribution is licensed the same way, and you keep the copyright in what you wrote. New files start
with the licence header in that file's comment style:

```rust
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) <year> the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
```

Add yourself to [AUTHORS](AUTHORS) with your first contribution.

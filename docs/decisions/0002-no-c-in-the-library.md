# 0002: No C or C++ in the library; TLS is the one place C is allowed

> The signing provider is decided again in [0006](0006-aws-lc-signs.md): AWS-LC signs through one binding, and RustCrypto's `rsa` is a test tool only.

Decided 2026-11-02 by KI7MT.

## What was decided

Nothing in the dependency tree of `qso-graph-trust`, the crate that holds the key, the signing and
every file parser, may link a native library or build C, C++ or assembly, on any platform.

`cargo xtask policy` enforces it on every pull request, over that tree with every feature on and on
every platform:

- no crate in it declares a native link (`links`);
- no crate in it depends on a crate whose job is building native code (`cc`, `cmake`, `bindgen` and
  the like);
- every crate in it from outside the workspace comes from crates.io and is reviewed by exact name
  and version, through cargo-vet (decision 0004). A build script can run a compiler, and an
  `extern` block can link a library, without declaring `links`, so no metadata check can stand in
  for that review;
- every build script or procedural macro of our own crates is on `xtask`'s reviewed list (empty);
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
sees whole (review found five such constructions before this rule replaced chasing them). The
cost, named so the rule is not relaxed quietly later (Watson's review): tables of OIDs and fields,
per-record test cases and error enums, where a signing library would usually use `macro_rules!`,
are written out longhand. The canary already catches a macro that expands to `unsafe` in any
build that compiles it; this rule adds coverage for macros behind a `cfg` no build compiles. Nor do
they have shebangs: a file beginning `#!` must begin `#![`, because Rust's rules for telling a
shebang from an attribute (Unicode whitespace, comments, doc comments) were misread twice. So that nothing compiles from a file the scan does not
read, every crate root is a `.rs` file and a crate's directory holds only `.rs`, `.toml` and `.md`
files. A directory is left out only when it is another workspace crate, or Cargo's output directory
or a workspace exclusion lying outside every crate; inside one, `mod` could still load it. The
planted fixtures therefore live at the repository root, in `tests/policy-fixtures`.

**Every shipped crate's dependencies are reviewed.** A dependency's macro (`paste!`, for one) can
build `unsafe` code inside our crate from pieces, so every crate outside the workspace that the
library or the command line needs, not only the library's tree, comes from crates.io and is reviewed by exact
name and version. The no-C rules stay the library's: the command line may link the TLS stack's C. The library's
root may not switch itself off with a crate-level `#![cfg]`, which would also switch off the canary.

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

Decided by KI7MT, 2026-11-03, after Watson's review measured that phase 2's first dependencies
(`rsa`, `sha1`) would otherwise fail it 181 times, none of them C:

- **Bindings to the operating system, as a named category** (`OS_BINDINGS` in
  `xtask/src/lib.rs`): crates that only declare the OS's own interfaces, the C library, the
  Windows API and its import libraries, Apple's frameworks and the OS's random-number source
  (`libc`, `windows-sys` and `windows-targets` with its import-library crates,
  `core-foundation-sys`, `security-framework-sys`, `getrandom`). Every program calls the OS this
  way; these crates compile and ship no C, C++ or assembly. They are still reviewed by exact
  version, through cargo-vet.
- **Rust's own `asm!` in a reviewed outside crate.** It is written in Rust and compiled by rustc,
  not a C toolchain; `zeroize`'s empty barrier, which keeps a key's wiping from being optimized
  away, is one. In our own crates it stays refused.
- **Only the platforms QGT ships** (`SHIPPING_TARGETS`: Windows, macOS and Linux, x86-64 and
  ARM64): the check reads each one's dependency tree, not code for platforms QGT never builds.

Still forbidden: C, C++ or assembly source a crate compiles or ships, a crate whose job is
building native code, and a native link to anything but the operating system.

## Proposed 2026-11-04, for KI7MT: OS credential store shared with Desktop

Use Desktop's `keyring = "=4.2.0"` with its default backends: Keychain on macOS,
Credential Manager on Windows and Secret Service on Linux. `Os` selects the fixed test service
when `QG_DESKTOP_TEST_KEYCHAIN` is present, as Desktop does (QGD-LTW-0007); its value never supplies
a service name. `OsTest` always selects the test service. Select once per backend so changing the
environment cannot split an operation between services.

KI7MT approved direct, target-gated `security-framework = "=3.7.0"` on macOS and
`secret-service = "=5.2.0"` with `features = ["crypto-rust"]` on other Unix systems, exactly as
Desktop's `packages/callsign-core` uses them. Both already existed in the locked tree and have
exact-version cargo-vet exemptions explicitly marked not audited yet. `keyring-core` 1.0.1 remains
only a transitive dependency of keyring, with its exemption retained; its direct Windows dependency
has been removed. No new audit source or publisher trust was added.

**Decided by KI7MT, 2026-11-04: Secret Service session transport provider.** RustCrypto is a named
provider only inside `secret-service` 5.2.0's Desktop-default `crypto-rust` D-Bus session transport:
its DH arithmetic, HKDF/SHA-256 and AES-CBC. It is never an exception for signing, certificate
operations, TLS or other uses. The session exchanges encrypt the key in transit to the local OS
credential service. This exception grants no native-code exemption: the provider and its dependency
sources are still scanned. Policy pins the transport version/features, constrains incoming edges to
its resolved algorithms/arithmetic, and confines QGT's Secret Service API use to the credential
backend's connection, encryption-mode and error types. Planted cases reject direct use from other
crates, signing/certificate files, different provider/algorithm versions, other features and public
session encrypt/decrypt imports, then pass again when each plant is removed.

Linux discovery uses Secret Service's SearchItems and attributes, including locked items without
unlocking them. macOS searches request generic-password attributes without secret data, explicitly
restricted to `SecKeychain::default_for_domain(SecPreferencesDomain::User)`, the same keychain as
apple-native-keyring-store's default reads/writes. Neither searches the entire macOS search list.

**Decided by KI7MT, 2026-11-04: Windows never enumerates.** Credential Manager enumeration returns
all credential blobs before keyring filters them, including other services' secrets. QGT must not
call `keyring_core::Entry::search` or `CredEnumerate`. Its backend reports the typed capability
`OrphanDetection::Unavailable`; `names()` returns `EnumerationUnavailable`, never a misleading empty
list. `OpenReport::orphan_detection` carries that capability to callers. Windows checks only the
QGT credentials named by certificates/pending requests in the file; `exists()` uses the default
backend's CredReadW of that one entry, whose native blob the provider wipes. Missing keys are still
reported; orphan detection is unavailable. The Windows capability and no-enumeration path also
compile in Linux unit tests. No global credential-count limit can be enforced there by enumeration;
the store's public record limits still apply.

**Limits at QGT's API boundaries.** Providers allocate/copy complete secrets and metadata batches
before returning them; QGT cannot bound those allocations. It wraps returned secret bytes in
`Zeroizing` immediately, then applies `MAX_KEY_LEN` before use or further QGT copies. Oversized
responses are wiped and refused too. Linux applies `MAX_KEYS` to both presence and enumeration
responses as soon as SearchItems returns, before requesting attributes or collecting QGT's names.
macOS additionally requests at most `MAX_KEYS + 1` items and checks the returned count. These bounds
limit what QGT accepts and subsequently processes, not the provider's preceding memory use.

Keys are random `key:<uuid v4>` entries. Reads use `get_secret`, immediately wrapped in `Zeroizing`,
including malformed-secret error payloads; writes use `set_secret`, with existing names refused
under the owning store's file lock. All provider errors become fixed store categories. The shared
Store operations continue to put a key before publishing its name, and remove a record before
deleting its key. The opt-in OS test uses only `TEST_SERVICE`, tracks attempted writes for cleanup
on unwinding, and exercises binary replacement, persistence, whole-store replacement, deletion,
missing credential reports on every platform, and orphan reports or the explicit unavailable
capability as appropriate. Run it on a host with a working credential service:
`QGT_OS_KEYSTORE_TEST=1 cargo test -p qso-graph-trust os_round_trip -- --ignored`.

Extend the named OS-binding category for that dependency tree, after reading the packaged sources
and manifests. None carries C, C++ or assembly source files or a native-build dependency:

- `security-framework` 3.7.0 wraps Apple's Security framework. `src/authorization.rs` declares
  `SMJobBless` and `kSMDomainSystemLaunchd`, linking the OS's ServiceManagement framework;
  `src/os/macos/code_signing.rs` declares Mach `mach_task_self` and `task_info` in a test.
- `core-foundation` 0.10.1 wraps Apple's Core Foundation through `core-foundation-sys`.
  The finding in `tests/use_macro_outside_crate.rs` is a test-only mock declaration of
  `CFFooBarGetTypeID` and `fake_compare`, exercising its wrapper macros, not shipped native code.
- `rustix` 1.1.6 wraps libc and Linux syscalls. Read `build.rs` (rustc-only feature probes),
  `src/backend/libc/`, `src/backend/linux_raw/param/libc_auxv.rs` (`getauxval`, `sysconf`),
  `src/backend/linux_raw/vdso_wrappers.rs` and `src/weak.rs`. Syscall assembly is Rust inline/global
  assembly, covered by the existing reviewed-outside-crate category; no assembler is invoked.
  `src/msan.rs` declares a sanitizer hook, unused in QGT's shipping builds.
- `linux-raw-sys` 0.12.1 contains generated Linux UAPI types and constants, with no build script;
  `src/hexagon/general.rs` declares kernel signal trampoline symbols for an unshipped architecture.
- `errno` 0.3.14 wraps the OS error slot: `src/unix.rs` binds `errno_location` to the platform's
  libc symbol; `src/wasi.rs` declares `__errno_location` for an unshipped platform. No build script.

`zbus` and `uuid` are **not** OS bindings. A separate `FOREIGN_DECLARATIONS` list allows only a
foreign-declaration finding in each of these individually read files at the exact version:

- `zbus` 5.19.0, `src/fdo/peer.rs`: macOS's `gethostuuid` supplies the D-Bus machine ID.
- `uuid` 1.29.0, `src/rng.rs`: wasm-bindgen imports JavaScript `crypto.getRandomValues`.
- `uuid` 1.29.0, `src/timestamp.rs`: wasm-bindgen imports JavaScript `Date.now`.

Neither JavaScript import is compiled for QGT's shipping targets. Another crate, version or file
still fails; a native link or native source fails even within an allowed file. Planted cases beside
the existing OS-binding test prove these limits and pass again when the planted changes are removed.
All of these dependencies still require cargo-vet coverage by exact version.

## Amended 2026-11-03: cryptographic primitives

Decided by KI7MT after measuring the options. QG Trust's own code and every parser stay safe Rust with
no C: the parsers read untrusted input, where memory errors are found. Cryptographic primitives come
from vetted providers, each named in the policy checks:

- **`aws-lc-rs`,** the provider QSO Graph Desktop already uses (`=1.18.1`, FIPS), for TLS and for every
  operation it offers. Its safe API signs RSA only with SHA-256, SHA-384 and SHA-512, and verifies
  SHA-1 for legacy use only (`src/rsa/signature.rs`, `RsaSigningAlgorithmId`); it has no raw RSA
  operation. The independent check of each signature is tqsllib's own, made by OpenSSL: the
  differential tests compare QG Trust's with it byte for byte.
- **RustCrypto's `rsa`, for LoTW's signature only:** RSA PKCS#1 v1.5 with SHA-1, `SIGN_LOTW_V2.0`, the
  one LoTW accepts and the one aws-lc-rs does not sign. Pure Rust, so no C and no unsafe code in QG
  Trust. Its timing advisory, RUSTSEC-2023-0071 (Marvin), has no fixed release; the advisory itself
  says "local use on a non-compromised computer is fine". QG Trust signs only on the ham's own
  machine, for that ham, and the library never signs for a remote caller. `cargo audit` ignores that
  one advisory, pointing here; any other, and a fixed release of `rsa`, fails CI.
- **What QG Trust adds around `rsa`** (Codex reviews of qso-graph-trust#3): a key signs only if it is
  LoTW-shaped (1024-bit modulus, exponent 65537, two different 512-bit primes, each passing
  Baillie-PSW and 32 Miller-Rabin rounds with random bases) and matches its stated public key; a
  protected key is decrypted by QG Trust itself (PBKDF2, then 3DES- or AES-CBC), every buffer wiped.
  **Known and outside QG Trust's code:** `rsa` 0.9.10's `validate()` multiplies e by a clone of d that
  it drops unwiped (`src/key.rs:408-409`), and `num-bigint-dig` wipes its arithmetic temporaries only
  in part. Closed for the whole class, not line by line: every program that signs uses a wiping global allocator, so every freed block
  is overwritten whichever library allocated it, and the custody test (qso-graph-desktop#172, Gate C)
  proves no key data remains in memory or a crash dump. The fix is also offered to `rsa` upstream.
- **SHA-1 is ARRL's choice, not QG Trust's.** Its weakness is collisions, which need the victim to sign
  attacker-made binary blocks. QG Trust signs only strings built from fields it has validated (calls,
  bands, modes, dates, location values), which leaves such blocks no place; that is a tested rule.
  The hash is fixed in TQSL's code (`tqsl_signDataBlock`, `EVP_sha1()`, `src/openssl_cert.cpp:2215`)
  and `config.xml`'s sigspec names no hash, so a stronger one would take a code change and an ARRL
  decision. ARRL already uses SHA-256 for the certificate request (`EVP_sha256()`, line 679); whether
  LoTW accepts a SHA-256 QSO signature is a question for lotw-devel.

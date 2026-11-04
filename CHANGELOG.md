# Changelog

All notable changes to QSO Graph Trust. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Library `.tq6` import with chain validation and atomic pending-request attachment or keyless
  storage; MAC-authenticated `.p12` import with PBES2/AES and PKCS#12 SHA-1/3DES, bounded parsing and
  derivation work, and private credential handoff. RC2-40 is explicitly refused, including TQSL's
  weak export certificate bags. No dependency packages added; the pinned aws-lc-rs enables `legacy-des` for import decryption.
- Certificate expiry lists from caller-supplied time and threshold, using X.509 validity-end UTC
  dates and TQSL's strict warning threshold, with dates and already-expired certificates included.

- Library certificate requests: new, signed additional and renewal `.tq5` files, with TQSL 2.8.7's
  CSR subject, attributes, signatures and field order; DXCC, date and bounded text validation.
  New RSA-1024 keys pass through an opaque request into the library-owned store, with pending
  metadata in store.xml, response matching and abandonment. Requests identify QG Trust.
  Desktop and CLI integration remains.
- Library-side encrypted LoTW store exports: a generated 20-character password, AES-256-GCM and
  PBKDF2-HMAC-SHA-256 at 600,000 iterations. Restore authenticates and checks every certificate, key
  and station location before replacing the store; private key bytes stay inside the library.

### Fixed

- CBC import decryption uses the binding's safe AWS-LC API. The release custody scan caught
  private-key fragments in RustCrypto CBC's temporary stack blocks; `.p12` imports are now
  exercised in debug and release, with a planted password leak as a positive control.

- Derive export AES keys directly into wiped heap storage, avoiding moved stack copies. Custody
  scans now search generated export passwords and both successful and failed-open derived keys,
  with planted-leak controls in debug and release.
- Encrypted store parts include pending certificate requests and their keys, checked against each
  recorded public key before restore changes the destination. The private store-part format is
  version 2; version 1 plaintext is refused. The encryption envelope remains version 1.

## [0.1.0-beta.4] - 2026-11-04

Documentation only: the library and `qg-trust` sign exactly as beta.3 does.

### Changed

- The README says what QSO Graph Trust is, who it is for, what it does and how it is different.
- The crates.io pages and `qg-trust --help` lead with what each does: memory-safe Rust with
  signatures by AWS-LC, Amazon's open-source cryptography library; every QSO checked by ARRL's own
  rules; the key can only sign; the password stays private; and the options, exit codes and final
  status line loggers already use.

## [0.1.0-beta.3] - 2026-11-04

### Added

- `qg-trust`, the command line, on crates.io as `qso-graph-trust-cli`: signs your ADIF log with your
  LoTW certificate (`-i`, the file with it) for your station location (`-l`), within a date range (`-b`,
  `-e`, `YYYY-MM-DD` or `YYYYMMDD`), into the `.tq8` named by `-o` or beside the log. The signed records
  and signatures are tqsllib's, byte for byte, for every location in the standard test set. A QSO
  LoTW would refuse, or the certificate or station cannot sign, is left out and named with the
  reason, and the rest are signed. TQSL's option letters, exit codes (0, 4, 6 to 10 and 15) and
  `Final Status: <name>(<code>)` line; TQSL's options it does not do yet are refused with code 10.
- The key's password is asked for at the terminal with what is typed hidden (`rpassword`), or read as
  one line from standard input when there is no terminal; `-p` is refused, and the password is never
  printed. The signed log is written whole or not at all.

### Changed

- The release publishes the command line after the binding and the library. A crate already on
  crates.io publishes with Trusted Publishing, which each requires; a first-publish token is used
  only for a crate new to crates.io, and refused once every crate exists.
- This repository's crates are marked in cargo-vet as built from source, now that they are also
  on crates.io.
- The README is the product page, for the hams who use it: what it does, how to sign a log step by
  step, what is still to come, how the key is kept safe, credits and sources. Building and the plan
  move to `CONTRIBUTING.md`.
- Supply chain: `rpassword` and `rtoolbox` audited (with their known Ctrl-C and buffer findings in the
  notes); Microsoft's `windows-sys` added as a trusted publisher (decision 0004).

## [0.1.0-beta.2] - 2026-11-04

Documentation only: no change to what the library does or signs.

### Changed

- The library's description on crates.io: "Sign ADIF logs for ARRL's Logbook of The World (LoTW)".
- The README and the library's README say what the beta does today and what is still to come, with
  the status of each phase, how to add the library, and the feature-parity list. The beta reads the
  certificate and key from TQSL's `.tbk` file; QG Trust does the signing.
- `SECURITY.md` says what is promised now: the key only ever signs and is wiped from freed memory, the
  library's own code has no `unsafe`, and the one binding with `unsafe` code is AWS-LC's. The OS
  credential store and upload are marked as still to come.
- `AGENTS.md` and `CONTRIBUTING.md` list every CI check and say how a release is made; the decisions
  index names what each superseded decision became.
- The Sources no longer link a private repository.
- Claims brought into line with the code: the signed records and signatures match TQSL's byte for
  byte, and only the identification line differs; the OS credential store and upload are planned,
  not present (README, `AGENTS.md`, `NOTICE`); a `.tbk` file's certificates are checked to LoTW's root,
  and a certificate a program reads itself is checked only when it calls `verify`; the custody test
  says what it proves; cargo-vet's exemptions are named as not yet audited; what ARRL does when a key
  is compromised, from its own page.
- Adding the library names the two crates the example also needs; the feature-parity list frames QG
  Trust as an alternative; decision 0007 records how releases are actually published; the test
  corpus's README is current.

## [0.1.0-beta.1] - 2026-11-04

The first release on crates.io: `qso-graph-trust` and `qso-graph-trust-awslc`.

### Added

- Ready for crates.io (decision 0007): `qso-graph-trust` and its binding `qso-graph-trust-awslc` at
  `0.1.0-beta.1`, each with a README (the library's example is compiled as a doc test), keywords and
  categories, and every public item documented. The internal modules (ARRL's tables, the XML reader)
  are private. The library carries ARRL's terms unchanged, as `LICENSE-ARRL.md`, checked against
  `data/tqsl-config`, and each published crate carries `LICENSE.md`, `NOTICE.md` and `AUTHORS.md`,
  the repository's own, checked by `scripts/package-files.py`. The README's example installs the
  wiping allocator and asks for the key's password at run time. An ADIF record's fields are private:
  a record is read and passed to `Qso::from_adif`. The command line is not published until it signs.
  CI tests each pull request's own commit, packages both crates as crates.io would receive them, and
  `.github/workflows/release.yml` publishes them from main with Trusted Publishing, then tags the
  commit; a run that stopped halfway finishes when run again, and a first-publish token left in
  the Environment once the crates exist fails the run. Each crate names exactly what its package
  holds (`include`). Its decisions are
  `scripts/release_check.py`'s, each tested with the cases it must refuse.
- Credits and Sources, in the README and the library's README: TrustedQSL's contributors, as its
  `AUTHORS.txt` lists them, ARRL, and rfrht's qso-web; and what QG Trust was built from, ARRL's LoTW
  developer documentation, TrustedQSL's source and API documentation, other projects and the
  standards, with what it carries of TQSL's and under which terms (also in `NOTICE`).
- The repository: the library (`qso-graph-trust`) and command line (`qso-graph-trust-cli`, the `qg-trust` command) crates, CI on Windows, macOS
  and Linux, and the policy checks that fail the build on C in the library or unsafe code, each proved
  by a planted case (qso-graph-desktop#170).
- Test certificates made the way LoTW's are, for the tests to come (`tests/corpus`).
- The signed log (qso-graph-desktop#171): an ADIF log and a station location become the `.tq7` and
  `.tq8` LoTW receives, checked against ARRL's TQSL configuration 11.35 (`data/tqsl-config`), and
  matching tqsllib 2.8.7's `.tq7` byte for byte but for the identification line. A log is signed
  only with the certificate's own key, for its call and DXCC entity, while it is in force, and for
  QSOs within its QSO dates.
- No key data in freed memory (qso-graph-desktop#172): `qg-trust` installs a wiping global
  allocator (`zeroizing-alloc`), `cargo xtask policy` refuses any program without it, and the
  custody test reads a signing program's memory and finds no key data or password, with two
  controls proving it finds what is there.
- The standard test set (qso-graph-desktop#172, `tests/corpus/standard`): KC4QPQ with its home and
  four park locations, KN4YU as the club call and W4W as a one-month special-event call, from a test
  CA, with `standard.tbk` written by TQSL's own app. QG Trust signs every location's log as tqsllib
  does, byte for byte.
- Reading TQSL's `.tbk` file (qso-graph-desktop#172): every certificate, key and station
  location, and the QSOs TQSL has signed. Read by QG Trust's own XML reader, bounded as it reads, with
  no DTD; gzip into one wiped buffer. Chains are checked as RFC 5280 asks (path length, key usage, no
  unknown critical or repeated extensions), signatures through aws-lc-rs inside the binding. Each callsign certificate must chain, signature by signature,
  to LoTW's root, pinned as TQSL embeds it (`src/lotw/arrl.rs`): a root a file brings establishes
  nothing. A key must be its certificate's, for its call, DXCC entity and serial; one with no password
  is unlocked at import to prove it. Signing with only what TQSL's `.tbk` file of the standard set holds
  gives tqsllib's signed logs, byte for byte.
- The standard set's certificates have ARRL-style serials (10001 to 10003), so TQSL records each.
- TQSL's settings that change what LoTW receives come with the import (`tbk::Preferences`): custom
  ADIF modes, Cabrillo contests, ignore seconds, allow bad calls, ignore log callsigns, and the log's
  QTH handling. Upload, server, proxy and TLS settings are never taken from a file.

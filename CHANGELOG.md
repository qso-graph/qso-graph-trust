# Changelog

All notable changes to QSO Graph Trust. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Inspect certificate deletions with `Store::inspect_delete` and a public `PendingDelete` preview
  before committing. Commit refuses changes to the public store or referenced key presence and
  pending deletions from another Store instance without deleting anything (decision 0015).

### Changed

- `qg-trust cert delete` uses inspection and commit with its existing output and force check.
  `Store::delete_certificate` remains the one-step wrapper, preserving record-first deletion.
- `StoreError` and `ImportError` are `#[non_exhaustive]`, so a new error variant no longer breaks a
  caller's `match`. Callers matching every variant add a wildcard arm once.

## [0.1.6] - 2026-11-09

### Added

- Inspect `.tq6`, `.p12`, and TQSL backup imports before committing them: public certificate and
  key details, per-key backup passwords, root fingerprints, locations, and signed-QSO record size.
  Commit uses the inspected data under one lock, refuses conflicting store changes, and rolls
  back staged credentials if publication fails (decision 0014).
- Memory-custody checks for canceling and committing inspected protected imports, including
  backup keys with different passwords.

### Changed

- `qg-trust import` uses the same inspection and commit path for all three file formats.
- A failed fresh TQSL backup import now leaves all certificates, keys, roots, locations, and
  signed-QSO records unchanged instead of retaining entries imported before the failure.
  Reimporting an installed backup keeps existing certificates and keys without asking for their
  backup passwords; keys being installed still receive all checks. Backup password prompts and
  key-error text retain their original wording.
- Refused inspected imports and the one-step certificate wrappers return only a preview index
  and fixed category, keeping issuer names and email out of commit errors.
- Import-lock regression coverage synchronizes on a blocked OS acquisition and rejects a missing
  lock even with delayed worker startup. Custody helpers reserve unique owner-only export
  directories atomically, so stale PID-named directories cannot prevent a run.
- Update the test-only RSA tool to 0.10.0 and remove its resolved audit exception.
- Derive oversized test passwords from the test corpus.
- Licensed GPL-3.0-or-later, the same as every QSO Graph project; the ARRL notice appears once, in the README.
- AGENTS.md and CLAUDE.md: the organization's shared agent guide, and this repository's own.
- README: American spelling and style fixes for the QSO Graph style guide (Google Developer
  Documentation Style Guide, American English).
- README: the security figures for this release.

## [0.1.5] - 2026-11-08

### Added

- A default station location for logger calls and `sign` / `send`, managed with `qg-trust location default NAME`.

- `qg-trust -z` signs a test file without recording QSOs; `-w` and `signed clear` clear the signing record after confirmation, with `signed clear --yes` for scripts.

- Read ADIF logs in ADX XML form as well as ADI, selected by content, for signing through the library and CLI (decision 0013).

- The file readers are fuzzed: cargo-fuzz and libFuzzer, with a target for ADIF logs, `.tq6`, `.p12`
  and `.tbk` files, each driving the library as `qg-trust` does and checking that no record the
  library refuses is ever signed and that everything imported hangs together. In CI on every pull
  request and longer each week. In `fuzz/` only, on a pinned nightly, and never shipped
  (decision 0012); `cargo xtask policy` holds it to that.
- The custody test searches everything `qg-trust` writes, as well as memory, for a key or password:
  every file a run leaves and every run's output, through import, signing, the diagnostic log,
  certificate requests and deletion, and the encrypted export.
- `docs/TQSLLIB-MAP.md` maps every function and variable tqsllib 2.8.7 publishes to QG Trust, with a
  test or a stated reason, kept true by `scripts/tqsllib-map.py --check` in CI.

### Changed

- `-p` is accepted, not refused: fldigi sends it by default, so refusing broke its uploads. TQSL
  calls it a password; it is the key's passphrase. A key in the store needs none, so it is ignored
  there, with a warning that a passphrase on a command line can be read by other programs; it
  unlocks a key read with `-i` that has one, in place of asking. It is never written anywhere.
- `-n` and `-s` explain how to update or edit locations.
- `qg-trust -h` wraps to the terminal's width, lists the commands in one column, and names
  qg-trust's own options; `--version` prints `qg-trust` and its version only.
- `qg-trust sign` and `send` sign the whole log as it is, QSOs signed before included: LoTW takes a
  QSO it already has without harm, and a contest log's repeat contacts are QSOs. `-d`/`--dedupe`
  leaves QSOs signed before out and says how many. `--again` is still accepted, and does what every
  run now does. The form loggers call in place of `tqsl` keeps TQSL's `-a`.

## [0.1.4] - 2026-11-07

### Added

- `store::Listing::read(dir)`: a read-only, public listing of a store folder, for programs that show
  what the store holds and must not change it. It writes nothing (no folder, no `store.lock`, no
  file), takes no lock and never calls a credential store; a missing folder or `store.xml` is an
  empty listing, and a file the store refuses is refused with the same error. It gives the
  certificates (`ListedCertificate`: id, certificate, and `has_key` as the file records it, not
  checked against the credential store) and the trusted roots, as `Store::trusted_roots` does. It
  carries no credential name.

## [0.1.3] - 2026-11-07

0.1.2 was not released; its changes are in 0.1.3.

### Added

- `qg-trust -c CALL` (`--callsign`), as TQSL's: signs as CALL in place of the station location's
  own call, for that run only, with a certificate for CALL and the location's DXCC entity. The call
  is trimmed and put in capitals; one that is not a callsign is refused with code 10, and a call
  with no certificate in force fails as a location's own call does, with code 4. `-f` compares the
  log's own station fields with the location as `-c` changes it. With the store or with `-i`.
- `qg-trust -t FILE` (`--diagnose`), as TQSL's: a diagnostic log of the run for support, with
  TQSL's header (the program and version, the system, the command line, the working folder) and
  then each step: the options, the store, the station location and certificate chosen (call, DXCC
  entity, serial), how many QSOs were read and signed and how many left out for each reason, what
  was written, LoTW's answer to an upload and the final status. It never holds a key, a password or
  anything decrypted: in the command line, any value that could be a password is written
  `<redacted>`. The file is its owner's alone on Unix. A file that cannot be opened is said on
  standard error, in TQSL's words, and the run goes on.
- A new ARRL root can be trusted without a new QG Trust release. ARRL delivers a new root only
  inside the `.tq6` it issues; `qg-trust import` now names a root a `.tq6` or `.p12` brings, with its
  SHA-256 fingerprint, and trusts it when run again with `--trust-root <fingerprint>`. A root in
  your own TQSL backup, or in QG Trust's own encrypted export, is trusted and named. Only a root
  that is self-signed, a CA allowed to sign certificates, and that a callsign certificate in the same
  file chains to is ever accepted; LoTW's pinned roots stay trusted always.
- `qg-trust root list [--json]` lists every trusted root and CA, built in or accepted, with its
  dates, serial and SHA-256 fingerprint; `qg-trust root remove <fingerprint>` stops trusting one you
  accepted.
- Library: `Store::trust`, `Store::trust_with`, `Store::trusted_roots`, `Store::remove_root`,
  `Store::trust_backup_roots`, `tbk::read_trusting_roots`, `certificate::fingerprint` and
  `certificate::parse_fingerprint`; `ImportError::UntrustedRoot` and `ImportError::RootMismatch`;
  `RestoreReport::roots`. `Store::import_tq6` and `Store::import_pkcs12` take the confirmed
  fingerprint as an `Option<&str>`. The store file is version 3, with a `<roots>` section; versions 1
  and 2 are still read.

### Fixed

- `qg-trust location list` lines its columns up whatever the names' lengths; a name longer than
  20 characters pushed the call, entity and grid columns along on its line.
- An upload is named by its file in LoTW's activity list (`us12223.tq8`), not `log.tq8` for
  every upload. Only the file's name is sent, never its folder, with any character but letters,
  digits, `.`, `-` and `_` replaced. Library: `UploadRequest::try_named`.

## [0.1.1] - 2026-11-07

### Added

- `cargo xtask consumer <Cargo.toml>`: the library's checks against another program's build of
  it, run from a release's checkout. The library must be that release, from this repository by
  its tag and commit; everything it needs must be the version this release's lock file holds,
  since the other program's lock file resolves them itself (a crate it does not hold at all was
  brought by the program's own features, and is listed); it brings no C but AWS-LC's, the
  FIPS build accepted only when the program itself turns it on and only under aws-lc-rs; and
  every program it builds installs the wiping allocator. QSO Graph Desktop runs it in CI.

### Fixed

- A callsign certificate ARRL issued since mid-2023 is trusted. 0.1.0 pinned only the root and CA
  TQSL 2.8.7 embeds (2015 and 2019) and refused one issued under ARRL's 2023 root and CA, which
  share their names, saying it was "not issued under a trusted LoTW root". Both 2023 certificates
  are pinned now, from ARRL's own `.tq6`; TQSL takes them from there too, and embeds neither.

### Changed

- Signing and publication require KI7MT's manually started Release workflow on main and its exact
  commit. PR and ordinary binary builds stay unsigned. Release defaults to a dry run that verifies
  signing and notarization without publishing. Signing inputs are passed explicitly to the binary
  workflow; both publication stages use the main-only crates-io environment.

## [0.1.0] - 2026-11-05

### Added

- `qg-trust` works from QG Trust's own store, with keys in the OS credential store:
  `qg-trust import` brings certificates, keys, station locations and TQSL's record of signed QSOs
  from a TQSL backup (`.tbk`), and certificates from ARRL's `.tq6` or a `.p12`; `qg-trust sign`
  signs from the store, leaving out QSOs signed before unless `--again` is given; `qg-trust send`
  signs and uploads; `qg-trust upload` uploads a `.tq8`; `qg-trust cert list|request|renew|delete|abandon`
  and `qg-trust location list|show|add|edit|delete|fields` manage them. `--json` on the lists, an
  example in every command's help, nothing replaced without `--force`. TQSL's signing settings are
  options of `sign` and `send`, and `import` names those a backup used.
- Uploads to LoTW over HTTPS, the certificate and host name always verified against Mozilla's roots
  built in (webpki-roots), with rustls on AWS-LC; no redirect followed, a time limit, LoTW's answer
  read within the library's bound and reported with TQSL's codes (2, 3, 11).
- For loggers: without `-i`, the TQSL-style options sign from the store; `-u` uploads, `-a`
  (`abort`, `compliant`, `all`, `ask`) handles QSOs signed before as TQSL does in batch, and `-f`
  (`ignore`, `report`, `update`) the log's own location details. With no `-a`, QSOs signed before
  stop the run with TQSL's code 14, since `qg-trust` cannot ask. Exit codes 0 to 4, 6 to 11, 14 and 15.
- The library names DXCC entities and the location fields each takes (`station::dxcc_name`,
  `station::fields_for`).
- The library checks a file is a signed log before it is uploaded (`upload::check_signed_log`):
  a TQSL backup, which is gzip too and holds private keys, is refused.
- A new-only signed log is refused at writing if another signing recorded one of its QSOs after
  the plan was made (`StoreError::SignedMeanwhile`), so two runs never both sign a QSO as new.
- A key imported for a certificate already in the store without one (from a `.tq6` alone) is
  attached to it, from a `.tbk` or a `.p12`, instead of being refused as already there.
- Upload sends the checked signed log, gzipped afresh: nothing the check did not read goes with it.
- Versioned library store with keys in the OS credential store, file locking, atomic metadata
  updates and recovery reporting; credential-store round trips are tested on Windows, Linux and
  macOS with a test-only service name.
- CLI argument parsing with clap, shell completions and styled output.
- `.deb` and `.rpm` packages of `qg-trust` for Linux x86_64 and arm64, on each release beside the
  archives, with shell completions; QSO Graph's apt and dnf repositories at packages.qso-graph.net
  sign and serve them.
- Release packaging for Windows x86_64, Linux x86_64 and arm64, and macOS Apple silicon. PR CI builds
  all four unsigned archives; the release workflow signs Windows and macOS programs, notarizes
  macOS programs and attests the archives before publishing.

- Library upload request construction and bounded LoTW response parsing, with TQSL's multipart
  field, filename format and result codes. The endpoint is fixed; callers supply verified TLS.
  The library opens no connection; `qg-trust` makes the connection.
- Library signed-QSO records with exact TQSL keys, backup merging, duplicate inspection and the
  new-only/sign-again/cancel choices. Selected QSOs are recorded after their `.tq8` is written;
  encrypted store exports carry the record. Store XML version 2 reads version 1 and keeps up to
  100,000 records within the 32 MiB file limit.
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

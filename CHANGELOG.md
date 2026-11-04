# Changelog

All notable changes to QSO Graph Trust. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  commit; a run that stopped halfway finishes when run again. Its decisions are
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
- Importing TQSL's backup, the `.tbk` (qso-graph-desktop#172): every certificate, key and station
  location, and the QSOs TQSL has signed. Read by QG Trust's own XML reader, bounded as it reads, with
  no DTD; gzip into one wiped buffer. Chains are checked as RFC 5280 asks (path length, key usage, no
  unknown critical or repeated extensions), signatures through aws-lc-rs inside the binding. Each callsign certificate must chain, signature by signature,
  to LoTW's root, pinned as TQSL embeds it (`src/lotw/arrl.rs`): a root a file brings establishes
  nothing. A key must be its certificate's, for its call, DXCC entity and serial; one with no password
  is unlocked at import to prove it. Signing with only what TQSL's backup of the standard set holds
  gives tqsllib's signed logs, byte for byte.
- The standard set's certificates have ARRL-style serials (10001 to 10003), so TQSL records each.
- TQSL's settings that change what LoTW receives come with the import (`tbk::Preferences`): custom
  ADIF modes, Cabrillo contests, ignore seconds, allow bad calls, ignore log callsigns, and the log's
  QTH handling. Upload, server, proxy and TLS settings are never taken from a file.

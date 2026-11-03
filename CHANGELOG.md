# Changelog

All notable changes to QSO Graph Trust. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

# Changelog

All notable changes to QSO Graph Trust. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The repository: the library (`qso-graph-trust`) and command line (`qgt`) crates, CI on Windows, macOS
  and Linux, and the policy checks that fail the build on C in the library or unsafe code, each proved
  by a planted case (qso-graph-desktop#170).
- Test certificates made the way LoTW's are, for the tests to come (`tests/corpus`).

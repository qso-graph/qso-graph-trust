# 0003: The library, the command line and the app live in one repository

Decided 2026-11-02 by KI7MT: "the lib, app, cli, repo live together unless there is a reason to
separate them."

## What was decided

`qso-graph-trust` holds the library (`crates/qso-graph-trust`), the `qgt` command line (`crates/qgt`)
and, from phase 5, the QSO Graph Trust app. QSO Graph Desktop stays in its own repository and uses the
library as a dependency pinned to a QGT release.

## Why

- **One version.** The app, the command line and the library always match.
- **One set of rules.** The policy checks (decision 0002) cover everything that ships as QGT. They
  cover only the library's tree, so the app's Electron (C++) does not affect them, and the app never
  holds a key.
- **One pull request for a change across layers**, such as a new library call and the screen that
  uses it.

The cost: one open pull request per repository means app work and library work queue behind each
other. With the library first (phases 2 to 4) and the app last, that is the order anyway.

## When to revisit

If a reason to separate them appears, such as a release cadence the app needs that the library
should not follow, this is revisited with that reason.

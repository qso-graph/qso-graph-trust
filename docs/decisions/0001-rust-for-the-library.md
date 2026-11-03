# 0001: Rust for the library and command line, Electron for the app

Decided 2026-11-02 by KI7MT.

## What was decided

The library and the `qg-trust` command line are Rust. The app is Electron, sharing QSO Graph Desktop's
screens and tests. One library serves QSO Graph Desktop, the app, the command line and other people's
tools.

## Why

The language was chosen by elimination against requirements taken from the job, not by preference:

| Requirement | Why it is required | Languages it removed |
| --- | --- | --- |
| Not C, and not compiled to C | C is what is being moved away from | C, C++, Nim, V, Vala |
| No runtime or crypto written in C or C++ | The key, signing and parsing must be free of C | Python, Ruby, Erlang/Elixir, OCaml, Haskell, Java/Kotlin, C#, JavaScript/TypeScript, Dart, Swift off Apple, Kotlin/Native, D |
| Native X.509 and PKCS#12 | That is the work | Ada/SPARK |
| Memory-safe | Memory errors are how such code is attacked | Zig, Delphi |
| One credential implementation with QSO Graph Desktop, in-process | QSO Graph Desktop's credential core is Rust; a second implementation in a second language is a seam to defend | Go |

Go was the defensible runner-up: its TLS and crypto are pure Go, its module holds FIPS 140-3
certificate #5247, and its RSA has been constant-time since 1.20. It lost on needing a second
credential implementation beside QSO Graph Desktop's Rust core, reached across a process boundary.

The app's toolkit is not bound by the no-C rule, because the app never holds a key: the library does.
Electron reuses QSO Graph Desktop's screens, its window tests and Chromium's screen-reader support.

## Exit criterion

If QGT cannot meet or beat TQSL (every file it reads, the same behaviour to loggers, signatures LoTW
accepts, and safety shown by tests), the language was wrong, and this decision is revisited with the
evidence.

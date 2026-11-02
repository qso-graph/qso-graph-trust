# 0002: No C or C++ in the library; TLS is the one place C is allowed

Decided 2026-11-02 by KI7MT.

## What was decided

Nothing in the dependency tree of `qso-graph-trust`, the crate that holds the key, the signing and
every file parser, may link a native library or build C, C++ or assembly, on any platform.

`cargo xtask policy` enforces it on every pull request, over that tree with every feature on and on
every platform:

- no crate in it declares a native link (`links`);
- no crate in it depends on a crate whose job is building native code (`cc`, `cmake`, `bindgen` and
  the like);
- every build script or procedural macro in it is on a reviewed list by **exact name and version**,
  because a build script can run a compiler itself without declaring anything. A new version is a new
  review. The list is empty today.

What a reviewed build script does is a judgement made by reading it; the check guarantees that
judgement is made for every one, and made again when its version changes. Planted cases prove each
rule fails when broken (`xtask/tests/planted.rs`).

The HTTPS connection to LoTW is the one exception. No production-grade pure-Rust TLS provider exists
(`rustls-rustcrypto` is 0.0.2-alpha and says not to use it in production), so the upload uses rustls
with aws-lc-rs, as QSO Graph Desktop's core already does. It lives in its own crate, outside
`qso-graph-trust`'s tree, so the check still covers everything that touches the key.

## Why the line is there

The core requirement is that the ham's key stays theirs. TLS carries a log that is already signed:
the signature protects its integrity whatever the transport does, and the connection never sees the
key. The key, the signing and the parsers of files from outside are where memory errors would matter.

## What the check allows

Calling the operating system's own interfaces (Keychain, Windows Credential Manager, the Secret
Service over D-Bus) is not a C library linked by QGT. If a crate that reaches them declares a native
link, it is exempted by its exact name in `xtask/src/lib.rs`, with a line here saying why.

Exemptions today: none.

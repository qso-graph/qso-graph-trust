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
- every crate in it from outside the workspace comes from crates.io, where a published version can
  never change, and is on a reviewed list by **exact name and version**. Reading it is the review:
  no `#[link]` or `extern` block, no assembly, and a build script or procedural macro, if any, that
  compiles nothing. A build script can run a compiler, and an `extern` block can link a library,
  without declaring `links`, so no metadata check can stand in for reading. A new version is a new
  review. The list is empty today;
- every build script or procedural macro in it, a workspace crate's included, is on that list;
- as a second line, every file of every crate in it is searched: a `#[link]`, `#[link_name]` or
  `#[link_section]` attribute, an `extern` block, inline or global assembly, or a native source or
  object file (`.c`, `.h`, `.s`, `.o`, `.a`, `.so`, `.dll` and the like) fails the check, even in a
  comment.

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

Calling the operating system's own interfaces (Keychain, Windows Credential Manager, the Secret
Service over D-Bus) is not a C library linked by QGT. If a crate that reaches them declares a native
link, it is exempted by its exact name in `xtask/src/lib.rs`, with a line here saying why.

Exemptions today: none.

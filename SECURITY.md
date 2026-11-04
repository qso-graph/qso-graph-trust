# Security

QGT handles the key that proves a ham's identity to LoTW, so a security problem in it is taken as
seriously as a security problem gets.

## Reporting a problem

**Report it privately**, never in a public issue or pull request: use GitHub's
[private vulnerability reporting](https://github.com/qso-graph/qso-graph-trust/security/advisories/new)
for this repository. Say what you found, how to reproduce it with test data, and what you think it
allows. Don't include a real certificate, key or password; describe its shape instead.

You'll get an answer, and a fix is made before the details are published.

## Supported versions

QGT is in beta. The latest release on crates.io, beta or not, is supported; a fix is a new release.

## What QGT promises

- **The key is only ever used to sign.** No API returns it, and it is never in a log, an error or a
  trace. Every QGT program wipes the memory it frees, and the custody test proves no key data or
  password is left there.
- **The library's own code has no `unsafe`.** The one crate with `unsafe` code is the binding to
  AWS-LC, `qso-graph-trust-awslc`, which makes LoTW's signature; AWS-LC is the only C in the library's
  dependency tree (`cargo xtask policy`, decisions 0002 and 0006).
- **A certificate is trusted only if it chains to LoTW's own root,** pinned in the library, never to
  a root a file brings with it.
- **To come:** the key held by the OS credential store, leaving it only as a signature or a backup QGT
  encrypts itself; and TLS verification never turned off when QGT uploads.

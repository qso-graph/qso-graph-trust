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

QGT is in development and has no release yet. Once it does, the latest release is supported.

## What QGT promises

- The private key is held by the OS credential store and leaves it only as a signature or a backup QGT
  encrypts itself.
- The library contains no `unsafe` code and no C or C++ (`cargo xtask policy`).
- TLS verification is never turned off.

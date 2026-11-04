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
  trace. Every QGT program wipes the memory it frees. The custody test, on Linux, signs with a key
  file, drops everything, and reads the program's whole memory: none of the key's numbers, its file or
  its password is left there. While a key signs it is in memory, as in every signer.
- **The library's own code has no `unsafe`.** The one crate with `unsafe` code is the binding to
  AWS-LC, `qso-graph-trust-awslc`, which makes LoTW's signature; AWS-LC is the only C in the library's
  dependency tree (`cargo xtask policy`, decisions 0002 and 0006).
- **A certificate is trusted only if it chains to LoTW's own root,** pinned in the
  library (`tbk::read` with `Trust::lotw()`), never to a root a file brings with it. A certificate
  a program reads itself with `Certificate::from_pem_or_der` is checked only when the program calls
  `Certificate::verify`; `sign_log` checks the key, call, entity and dates, not the chain.
- **A password is never taken from the command line.** `qg-trust` asks for it at the terminal with
  what is typed hidden, or reads one line from standard input when there is no terminal, and never
  prints it.
- **To come:** the key held by the OS credential store, leaving it only as a signature or an export QGT
  encrypts itself; and TLS verification never turned off when QGT uploads.

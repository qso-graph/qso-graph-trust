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

The latest release is supported. A fix is a new release, published to crates.io, GitHub Releases,
Homebrew, apt and dnf together.

## What QGT promises, and what proves it

Each promise is held by a test or a check that runs on every pull request, so it can't quietly stop
being true.

- **The key stays in the OS credential store and is only ever used to sign.** It is stored in the
  macOS Keychain, Windows Credential Manager or the Secret Service on Linux, under QGT's own service,
  never as a file. It leaves the store only to sign, or into an export QGT encrypts itself under a
  password it generates, 20 letters and digits, about 119 bits; a typed password cannot seal one
  (decision 0009). No API returns it, and it is never in a log,
  an error or a trace. While a key signs it is in memory, as in every signer.
- **Nothing QGT writes holds a key or a password.** The custody test
  (`crates/qso-graph-trust-custody/tests/custody.rs`, `nothing_qg_trust_writes_holds_a_key_or_a_password`)
  runs `qg-trust` through import, signing, certificate requests, export and deletion, and searches
  every file it leaves, every line of output and every diagnostic log for the key in each encoding and
  for every password. Its control plants a key in a file and a password in a line of output, and the
  search must find both.
- **No key data is left in freed memory.** Every QGT program, and QSO Graph Desktop's native code,
  installs a wiping global allocator, so every block freed is overwritten, whichever crate allocated it
  (`cargo xtask policy`: the wiping allocator). The custody test signs, drops everything, then reads
  the program's whole memory, on Linux, and finds none of the key's numbers, its file or its password,
  with and without the processor's AES instructions. Its control runs without the wiping allocator,
  and the same search must find the key.
- **Every file QGT reads is fuzzed and bounded.** The ADIF, ADX, `.tq6`, `.p12` and `.tbk` readers
  run under cargo-fuzz and libFuzzer in CI, for a minute each on every pull request and ten minutes
  each every week, checking that nothing panics and that no record the library refuses is ever signed
  (decision 0012). Every reader caps each length, count and depth before allocating, and input past a
  limit is refused, never cut short. File-path readers share one regular-file check: on Unix they
  open nonblocking before checking the opened handle, so a named pipe needs no writer and is
  refused without waiting. Metadata and actual reads both enforce the byte limit, including file
  growth during reading. This covers TQSL's `station_data`, QGT's `store.xml`, and every CLI input
  read (logs, signed logs, certificates, and backups). XML declarations require XML 1.0 and UTF-8;
  malformed comments and forbidden character-data delimiters are refused by every XML reader.
  Review inputs become permanent regressions and reproducible fuzz seeds.
- **Exact station signing preserves the selected location.** When the caller selects
  `SigningOptions::with_exact_station(true)` for conversion and signing, each QSO's named station
  fields must agree with that location. Empty station fields are never filled from the log; VUCC
  lists compare as sets on every QSO, including the first. Every accepted QSO signs with the input
  station unchanged. The default retains TQSL-compatible station handling (decision 0018).
- **Signed-log upload checks require signatures.** Each signature must be nonempty base64 decoding
  to exactly the RSA modulus length of the certificate its station references. This is an encoding
  and structure check, not cryptographic signature verification or certificate-chain validation.
- **Memory-safe Rust.** The library, the command line and the custody test are `#![forbid(unsafe_code)]`.
  Signatures and certificate checks are made by AWS-LC, Amazon's open-source cryptography library,
  through one small crate, `qso-graph-trust-awslc`, whose every call into AWS-LC is checked and
  documented. The policy checks prove nothing else reaches outside Rust and that the library opens no
  connection (`cargo xtask policy`: no C in the library, no unsafe code outside the AWS-LC binding, no networking in the library;
  decisions 0002 and 0006).
- **A certificate is trusted only if it chains to a trusted LoTW root.** LoTW's public roots and CAs
  are pinned in the library and always trusted. A root a `.tq6` or `.p12` brings is trusted only if it
  is in the file, self-signed, a CA, and used by a certificate in the file, and only once the operator
  confirms its SHA-256 fingerprint; a TQSL backup's roots are trusted as TQSL trusts them (decision
  0011). `qg-trust root list` shows every trusted root with its fingerprint and dates, and
  `qg-trust root remove` takes one away.
- **Logs go to LoTW only, over HTTPS, checked.** The upload address is fixed in the library; no file
  or caller can change it. The connection is HTTPS only, with the server's certificate and name always
  verified, no redirect followed, a time limit on the whole exchange, and the answer read only up to a
  fixed size.
- **A passphrase is never needed on the command line.** A key in the store needs none. `-p`, TQSL's
  key passphrase, is accepted only so loggers that always send it keep working: it is ignored for a key
  in the store, with a warning that a command line can be read by other programs, and is never written
  to output or the diagnostic log, where it is shown as `<redacted>`. When a passphrase is needed, for a
  key read from a file, `qg-trust` asks at the terminal with what is typed hidden, unless `-p` gave it.
- **The supply chain is locked.** Every dependency is pinned to an exact, reviewed version, from
  crates.io only (`cargo xtask policy`: dependency sources; decision 0004), and the compiler is pinned.
  CodeQL and the eight policy checks run on every pull request. Each release is built from `main` by
  CI, signed (Windows), signed and notarized by Apple (macOS), GPG-signed (apt and dnf), and carries a
  build provenance attestation.

# QSO Graph Trust

QSO Graph Trust is the part of the QSO Graph Project that signs your logs for ARRL's
[Logbook of The World](https://lotw.arrl.org) (LoTW). It's a ground-up rewrite in Rust, not a
method-by-method port of TQSL. What it does was decided from the sources below, and how it does it is
its own.

## Sources

- **ARRL's LoTW developer documentation:** [developer information](https://lotw.arrl.org/lotw-help/developer-information/),
  [the signed log, `.tq8`](https://lotw.arrl.org/lotw-help/developer-tq8/),
  [submitting QSOs](https://lotw.arrl.org/lotw-help/developer-submit-qsos/),
  [LoTW's PKI](https://lotw.arrl.org/lotw-help/developer-pki/),
  [certificate security](https://lotw.arrl.org/lotw-help/certificatesecurity/),
  [station locations](https://lotw.arrl.org/lotw-help/stnloc/),
  [TQSL's command line](https://lotw.arrl.org/lotw-help/cmdline/), and the
  [LoTW Trusted Partners guidelines](https://www.arrl.org/files/file/LoTW_Developer/LoTW%20Trusted%20Partners-1_0.pdf).
- **TrustedQSL:** [its source](https://git.code.sf.net/p/trustedqsl/tqsl) at v2.8.7, read for what LoTW
  receives; [tqsllib's API documentation](https://www.rickmurphy.net/lotw/doxygen/); and
  [TQSL's change log](https://lotw.arrl.org/lotw-help/tqslchangelog/). QSO Graph Trust carries two things
  of TQSL's, both ARRL's, under ARRL's terms: the TQSL configuration (`config.xml`), from which its LoTW
  tables are generated, and ARRL's root and CA certificates as TQSL embeds them. TQSL 2.8.7, built from
  its own source, is the reference its signed records and signatures are tested against, byte for byte.
- **Other open-source projects:** rfrht's [qso-web](https://github.com/rfrht/qso-web), credited below,
  and a survey of 126 ham-radio Rust crates on crates.io, which found no other LoTW signing crate.
- **Standards:** [ADIF 3.1.7](https://adif.org/317/ADIF_317.htm); RFC 5280 (X.509 certificates),
  RFC 4055 and RFC 8017 (RSA), RFC 1952 (gzip); W3C XML 1.0.

## Who it's for

- **Hams** using [QSO Graph Desktop](https://github.com/qso-graph/qso-graph-desktop), who want to sign
  and upload their QSOs to LoTW without leaving it.
- **Authors of loggers and tools**, who want LoTW signing inside their own program, through the
  library or the `qg-trust` command line.

## What it does

It takes your ADIF log and your LoTW callsign certificate, signs each QSO the way LoTW requires, and
writes the `.tq8` file LoTW accepts. Uploading it, and looking after your certificates, come next.

## How it's different

- **Your key stays locked away.** It will live in your computer's own password safe (the macOS
  Keychain, Windows Credential Manager, or the Linux keyring), never as a file someone could copy.
  *(Coming soon.)*
- **It works inside the program you already use.** QSO Graph Desktop, another logger or a script can
  sign for LoTW directly, with no separate program to switch to.
- **It's built to be safe.** Your key is only ever used to sign: it is never shown, saved to a log or
  sent anywhere, and the program clears it from memory when it's done. Every part is tested. More, and
  how to report a security problem: [SECURITY.md](SECURITY.md).
- **It's part of QSO Graph Desktop.** Your certificates, station locations, signing and upload sit
  alongside the rest of your station. *(Coming soon.)*

> **This is a beta.** Signing works today.

## Sign a log

1. **Install `qg-trust`** (it needs [Rust](https://rustup.rs)):

   ```sh
   cargo install qso-graph-trust-cli
   ```

2. **Sign** your log with your certificate (`-i`, the `.tbk` file TQSL saves) for your station
   location (`-l`):

   ```sh
   qg-trust -i tqslconfig.tbk -l "Home" mylog.adi
   ```

   If your key has a password, `qg-trust` asks for it, with what you type hidden. It writes
   `mylog.tq8` and tells you how many QSOs it signed. A QSO LoTW would refuse is left out and named,
   with the reason.
3. **Upload `mylog.tq8`** on LoTW's website.

To sign only some dates, add `-b 2026-01-01` and `-e 2026-06-30`. `qg-trust --help` lists everything,
and the [command line's page](crates/qso-graph-trust-cli/README.md) has every option and exit code.

## For developers

The library is [`qso-graph-trust`](https://crates.io/crates/qso-graph-trust); its
[page](crates/qso-graph-trust/README.md) has an example. To work on QSO Graph Trust itself:
[CONTRIBUTING.md](CONTRIBUTING.md). What it does and plans, feature by feature:
[docs/FEATURE-PARITY.md](docs/FEATURE-PARITY.md).

## Credits

QSO Graph Trust stands on other people's work.

**TrustedQSL (TQSL)** and the people who built it and keep it running. TQSL's contributors, as its
`AUTHORS.txt` lists them, are **WA1GON, K1MK, KE3Z, K1MU, KC2YWE and AA6YQ**, with ARRL. Since 2003 their
work has carried the signature on every QSO confirmed through Logbook of The World: a signing format, a
certificate system and a program that hams on every platform rely on, kept current through two decades of
operating systems, library changes and new modes, as volunteers. Thank you.

**ARRL**, for LoTW itself and for documenting it for developers.

**rfrht's [qso-web](https://github.com/rfrht/qso-web)**, a shell script that builds and signs a `.tq8` with
OpenSSL, without TQSL, and uploads it to LoTW, showing that LoTW accepts a log signed by another program.

## Licence

GPL-3.0-only ([LICENSE](LICENSE)); see [NOTICE](NOTICE). QSO Graph Trust is not made, affiliated with or
endorsed by ARRL. "Logbook of The World", "LoTW" and "TQSL" are ARRL's names, used here only to say what it
works with.

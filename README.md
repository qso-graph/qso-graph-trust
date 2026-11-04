# QSO Graph Trust

Sign your ADIF logs for ARRL's [Logbook of The World](https://lotw.arrl.org) (LoTW). QSO Graph Trust is
an alternative to TQSL: it reads the certificates and backups TQSL makes, and the logs it signs carry
the same signed records TQSL's do, byte for byte.

> **This is a beta.** It signs your log with your LoTW certificate, from the command line. Still to
> come: keeping your key in your computer's own credential store, uploading straight to LoTW,
> requesting certificates, and signing inside [QSO Graph Desktop](https://github.com/qso-graph/qso-graph-desktop).

## Sign a log

1. **Find TQSL's backup file.** It holds your certificate. In TQSL, *File → Backup Station Locations, Certificates, and Preferences…*
   saves one. TQSL also saves one by itself, `tqslconfig.tbk`, each time it closes, unless that is
   turned off in its Preferences.
2. **Install `qg-trust`** (it needs [Rust](https://rustup.rs)):

   ```sh
   cargo install qso-graph-trust-cli
   ```

3. **Sign**, naming TQSL's backup file, your station location as TQSL calls it, and your log:

   ```sh
   qg-trust -i tqslconfig.tbk -l "Home" mylog.adi
   ```

   If your key has a password, `qg-trust` asks for it, with what you type hidden. It writes
   `mylog.tq8` and tells you how many QSOs it signed. A QSO LoTW would refuse is left out and named,
   with the reason.
4. **Upload `mylog.tq8`** on LoTW's website, as you would one TQSL saved.

To sign only some dates, add `-b 2026-01-01` and `-e 2026-06-30`. `qg-trust --help` lists everything,
and the [command line's page](crates/qso-graph-trust-cli/README.md) has every option and exit code.
Loggers that run `tqsl` will find the same option letters, exit codes and final status line.

## Your key stays yours

- Your key is only ever used to sign. It is never printed, logged or sent anywhere.
- A password is never typed on the command line, and the program wipes the memory it frees, so no
  key or password is left behind in it.
- A backup's certificates are trusted only if they come from LoTW's own certificate authority.

More, and how to report a security problem: [SECURITY.md](SECURITY.md).

## For developers

The signing is a Rust library, [`qso-graph-trust`](https://crates.io/crates/qso-graph-trust), for your
own programs; its [page](crates/qso-graph-trust/README.md) has an example. To work on QSO Graph Trust
itself: [CONTRIBUTING.md](CONTRIBUTING.md). What it does, plans and leaves out, feature by feature
against TQSL: [docs/FEATURE-PARITY.md](docs/FEATURE-PARITY.md).

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

## Sources

QSO Graph Trust is a ground-up rewrite in Rust, not a method-by-method port of TQSL. What it does was
decided from these, and how is its own:

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
- **Other open-source projects:** qso-web, above, and a survey of 126 ham-radio Rust crates on crates.io,
  which found no other LoTW signing crate.
- **Standards:** [ADIF 3.1.7](https://adif.org/317/ADIF_317.htm); RFC 5280 (X.509 certificates),
  RFC 4055 and RFC 8017 (RSA), RFC 1952 (gzip); W3C XML 1.0.

## Licence

GPL-3.0-only ([LICENSE](LICENSE)); see [NOTICE](NOTICE). QSO Graph Trust is not made, affiliated with or
endorsed by ARRL. "Logbook of The World", "LoTW" and "TQSL" are ARRL's names, used here only to say what it
works with.

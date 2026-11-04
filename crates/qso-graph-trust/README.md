<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust

Sign ADIF logs for ARRL's [Logbook of The World](https://lotw.arrl.org) (LoTW). From the same key,
station location and QSOs, the signed records and their signatures are TQSL's, byte for byte; only the line naming the program
that made the file differs.

QSO Graph Trust is the library behind the [`qg-trust`](https://crates.io/crates/qso-graph-trust-cli)
command line and, still to come, LoTW signing in [QSO Graph Desktop](https://github.com/qso-graph/qso-graph-desktop),
and it is for other people's programs too. Its parsers are safe Rust, and the library
forbids `unsafe` code. LoTW's signature is AWS-LC's, through one small binding, `qso-graph-trust-awslc`,
the only crate here with `unsafe` code; a password-protected key is unlocked with RustCrypto.

**This is a beta.** For now it reads your certificate and key from a TQSL backup (`.tbk`), with the
key's password. Still to come: keeping keys in the operating system's credential store, uploading to
LoTW, and requesting certificates. What is done, planned and left out, feature by feature against
TQSL: [`docs/FEATURE-PARITY.md`](https://github.com/qso-graph/qso-graph-trust/blob/main/docs/FEATURE-PARITY.md).

## Example

This example takes the certificate, the key and a station location from a TQSL backup, then signs an
ADIF log with them and writes the `.tq8`. It also uses two other crates, `zeroize` and
`zeroizing-alloc` (`cargo add zeroize zeroizing-alloc@=0.1.1`):

```rust,no_run
use std::time::SystemTime;

use qso_graph_trust::certificate::Trust;
use qso_graph_trust::qso::Qso;
use qso_graph_trust::signed_log::{sign_log, tq8};
use qso_graph_trust::{records, tbk};
use zeroize::Zeroizing;

// Every program that signs installs a wiping allocator, so no key text is left in memory it frees,
// whichever crate allocated it. QSO Graph Trust's own programs use exactly this one.
#[global_allocator]
static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A backup's certificates are trusted only if they chain to LoTW's own root, pinned here.
    let backup = tbk::read(&std::fs::read("tqslconfig.tbk")?, &Trust::lotw())?;

    let entry = backup.certificates.iter().find(|c| c.callsign == "K1ABC").ok_or("no certificate")?;
    let certificate = entry.certificate.as_ref().ok_or("no certificate yet")?;
    // Ask for the key's password when the program runs: never on a command line, in a file or in code.
    let password: Zeroizing<Vec<u8>> = ask_for_password()?;
    let key = entry.key.as_ref().ok_or("no key")?.unlock(Some(&password))?;
    let station = &backup.locations.iter().find(|l| l.name == "Home").ok_or("no location")?.station;

    // Every QSO is checked as LoTW checks it; one it would refuse is an error naming the field.
    let qsos = records::parse(&std::fs::read("log.adi")?)?
        .iter()
        .map(Qso::from_adif)
        .collect::<Result<Vec<_>, _>>()?;

    let signed = sign_log(certificate, &key, station, &qsos, SystemTime::now())?;
    std::fs::write("log.tq8", tq8(&signed))?;
    Ok(())
}
# fn ask_for_password() -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> { unimplemented!() }
```

`ask_for_password` is your program's: a prompt that does not echo, or the OS's own dialog.

The `.tq8` is what LoTW accepts: upload it on LoTW's website.

## Checking a download

Each release is published by this repository's release workflow, which GitHub attests: a signed
statement that the `.crate` file was built by that workflow from that commit. With the GitHub CLI:

```sh
gh attestation verify qso-graph-trust-<version>.crate -R qso-graph/qso-graph-trust
```

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

QG Trust is a ground-up rewrite in Rust, not a method-by-method port of TQSL. What it does was decided
from these, and how is QG Trust's own:

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
  [TQSL's change log](https://lotw.arrl.org/lotw-help/tqslchangelog/). QG Trust carries two things of
  TQSL's, both ARRL's, under ARRL's terms: the TQSL configuration (`config.xml`), from which the LoTW
  tables are generated, and ARRL's root and CA certificates as TQSL embeds them. TQSL 2.8.7, built from
  its own source, is the reference QG Trust's signed records and signatures are tested against, byte
  for byte.
- **Other open-source projects:** qso-web, above, and a survey of 126 ham-radio Rust crates on crates.io,
  which found no other LoTW signing crate.
- **Standards:** [ADIF 3.1.7](https://adif.org/317/ADIF_317.htm); RFC 5280 (X.509 certificates),
  RFC 4055 and RFC 8017 (RSA), RFC 1952 (gzip); W3C XML 1.0.

## Licence

GPL-3.0-only. LoTW's tables are generated from ARRL's TQSL configuration, Copyright (C) 2001-2015
American Radio Relay League, Inc., portions (C) 2003-2026 The TrustedQSL Developers, redistributed under
ARRL's terms in `LICENSE-ARRL.md` (ARRL's text, unchanged), which ships with this crate.

QSO Graph Trust is not made, affiliated with or endorsed by ARRL. "Logbook of The World" and "LoTW" are
ARRL's marks, used here only to say what this library works with.

Source, decisions and the plan: <https://github.com/qso-graph/qso-graph-trust>.

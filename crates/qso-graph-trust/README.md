<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust

Sign logs for ARRL's [Logbook of The World](https://lotw.arrl.org) (LoTW). The signed log is the same,
byte for byte, as the one TQSL makes from the same key, station location and QSOs.

QSO Graph Trust is one library shared by [QSO Graph Desktop](https://github.com/qso-graph/qso-graph-desktop),
its `qg-trust` command line and other people's programs. Its parsers and signing are safe Rust: the
library forbids `unsafe` code, and its one cryptographic provider, AWS-LC, is reached through a single
small binding, `qso-graph-trust-awslc`.

**This is a beta.** It signs from a TQSL backup (`.tbk`) and the key's password. Keeping keys in the
operating system's credential store, uploading to LoTW and requesting certificates are still to come.

## Example

Read a TQSL backup, then sign an ADIF log for one of its station locations:

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

## Credits

QSO Graph Trust exists because of [TrustedQSL](https://sourceforge.net/projects/trustedqsl/) (TQSL) and
the people who built it and keep it running. TQSL's contributors, as its `AUTHORS.txt` lists them,
are **WA1GON, K1MK, KE3Z, K1MU, KC2YWE and AA6YQ**, with ARRL. Since 2003 their work has carried the
signature on every QSO confirmed through Logbook of The World: a signing format, a certificate system and
a program that hams on every platform rely on, kept current through two decades of operating systems,
library changes and new modes, as volunteers. QG Trust learned what LoTW needs from that work, and thanks
them for it.

QG Trust is written in Rust from ARRL's LoTW documentation and from what TQSL does, not ported from its
code. It carries two things of TQSL's, both ARRL's, under ARRL's terms: the TQSL configuration
(`config.xml`), from which the LoTW tables are generated, and ARRL's root and CA certificates as TQSL
embeds them. TQSL 2.8.7, built from [its own source](https://git.code.sf.net/p/trustedqsl/tqsl), is the
reference every signature QG Trust makes is tested against, byte for byte.

## Licence

GPL-3.0-only. LoTW's tables are generated from ARRL's TQSL configuration, Copyright (C) 2001-2015
American Radio Relay League, Inc., portions (C) 2003-2026 The TrustedQSL Developers, redistributed under
ARRL's terms in `LICENSE-ARRL.md` (ARRL's text, unchanged), which ships with this crate.

QSO Graph Trust is not made, affiliated with or endorsed by ARRL. "Logbook of The World" and "LoTW" are
ARRL's marks, used here only to say what this library works with.

Source, decisions and the plan: <https://github.com/qso-graph/qso-graph-trust>.

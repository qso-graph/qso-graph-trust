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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A backup's certificates are trusted only if they chain to LoTW's own root, pinned here.
    let backup = tbk::read(&std::fs::read("tqslconfig.tbk")?, &Trust::lotw())?;

    let entry = backup.certificates.iter().find(|c| c.callsign == "K1ABC").ok_or("no certificate")?;
    let certificate = entry.certificate.as_ref().ok_or("no certificate yet")?;
    let key = entry.key.as_ref().ok_or("no key")?.unlock(Some(b"the key's password"))?;
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
```

The `.tq8` is what LoTW accepts: upload it on LoTW's website.

## Licence

GPL-3.0-only. LoTW's tables are generated from ARRL's TQSL configuration, Copyright (C) 2001-2015
American Radio Relay League, Inc., portions (C) 2003-2026 The TrustedQSL Developers, redistributed under
ARRL's terms in `LICENSE-ARRL.md` (ARRL's text, unchanged), which ships with this crate.

QSO Graph Trust is not made, affiliated with or endorsed by ARRL. "Logbook of The World" and "LoTW" are
ARRL's marks, used here only to say what this library works with.

Source, decisions and the plan: <https://github.com/qso-graph/qso-graph-trust>.

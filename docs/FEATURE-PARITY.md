<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Feature parity: TQSL and QG Trust

Everything TQSL 2.8.7 does, and what QG Trust does about each. QG Trust doesn't need everything TQSL
has, so every feature is placed in one of three lists, in priority order:

1. **Needed for 0.7.0:** what an operator needs to choose QG Trust as an alternative. Built first, in
   the order listed.
2. **Nice to have:** worth doing later, not needed for that choice.
3. **Won't add:** left out on purpose, with the reason.

**Published:** `0.1.0-beta.4` on crates.io: the library (`qso-graph-trust`), its binding
(`qso-graph-trust-awslc`) and the command line (`qso-graph-trust-cli`, the `qg-trust` command).

This is the library's list. The command line (`qg-trust`) and QSO Graph Desktop are built on the
library, so their lists follow from it: the command line is at the end, and Desktop's screens are
in [#174](https://github.com/qso-graph/qso-graph-desktop/issues/174).

**Status:** **Done** (built and tested) · **Part done** (what's missing is in the next column) ·
**0.7.0** (planned for milestone 0.7.0) · **Later** · **Won't**.
**Issue** is where the work is tracked: the phases of
[#169](https://github.com/qso-graph/qso-graph-desktop/issues/169), which are
[#171](https://github.com/qso-graph/qso-graph-desktop/issues/171) (signing),
[#172](https://github.com/qso-graph/qso-graph-desktop/issues/172) (the library),
[#173](https://github.com/qso-graph/qso-graph-desktop/issues/173) (the command line) and
[#174](https://github.com/qso-graph/qso-graph-desktop/issues/174) (Desktop).

## Summary

| List | Features | Done | Part done | To do |
|---|---|---|---|---|
| Needed for 0.7.0 | 43 | 16 | 5 | 22 |
| Nice to have | 15 |  |  | 15 |
| Won't add | 15 | | | |

## 1. Needed for 0.7.0

### 1.1 Signing a log

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Sign an ADIF log | File: Sign and save | Signed records and signatures match TQSL's byte for byte; only the identification line differs | Done | #171 |
| Save the signed log (`.tq8`) | File: Sign and save | | Done | #171 |
| Read ADIF | | | Done | #171 |
| Choose the station location to sign for | prompt | | Done | #171 |
| Refuse QSOs outside the certificate's dates | | | Done | #171 |
| Refuse what LoTW would refuse (calls, bands, modes, dates, satellites) | | Names the field at fault | Done | #171 |
| Check the log's own station fields against the location | | Refuses a mismatch, as TQSL does by default | Done | #171 |
| No key left in memory after use | | Done for `qg-trust`; Desktop's native code still to do | Part done | #172 |

### 1.2 Keys and storage

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Keys kept in the OS credential store | a file | | 0.7.0 | #172 |
| Certificates and locations saved, in one format the command line and Desktop share | files | | 0.7.0 | #172 |
| Record of QSOs already signed (the duplicate check) | `uploaded.db` | | 0.7.0 | #172 |

### 1.3 Moving from TQSL

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Export certificates, keys and the signed-QSO record to one file | File menu | A part of QSO Graph Desktop's one export file, beside Callsigns and Locations and Settings; all ticked exports everything. This part alone is encrypted, under a password QG Trust makes up. To move only some calls, delete the others first | 0.7.0 | #172, #174 |
| Import it on any computer (macOS, Windows, Linux), keys into that computer's credential store | File: Restore | Part by part, onto a clean slate: what this computer holds is removed first, nothing merged | 0.7.0 | #172, #174 |
| Read TQSL's `.tbk` file: certificates, keys, locations | File menu | Reads and checks it; saving what it holds waits on 1.2 | Part done | #172 |
| Restore TQSL's record of QSOs already signed | File: Restore | Read; saving waits on 1.2 | Part done | #172 |
| Use TQSL's settings that change what's signed: custom mode mappings, ignore seconds, ignore callsigns in the log, non-amateur calls, location details in the log | Preferences | Read from the `.tbk` file; not yet used when signing | Part done | #172 |
| Say which of TQSL's settings were not taken | | Listed | Done | #172 |

### 1.4 Certificates

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Check a certificate leads to LoTW's root | on load | A file's own root certificates count for nothing | Done | #172 |
| Load a certificate from ARRL (`.tq6`) | Load Callsign Certificate | Reads its fields; loading not yet | 0.7.0 | #172 |
| Load a certificate and key (`.p12`) | Load Callsign Certificate | | 0.7.0 | #172 |
| Certificate details: call, DXCC, QSO dates, valid dates, serial | Display Properties | Read | Done | #172 |
| Delete a certificate | Delete Callsign Certificate | | 0.7.0 | #172 |
| Warn before a certificate expires | at startup, 60 days | | 0.7.0 | #172 |

### 1.5 Station locations

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Add a station location | Add Station Location | | Done | #172 |
| The right fields for each DXCC entity (state, county, province, park and others) | wizard | From ARRL's configuration | Done | #172 |
| Zones must fit the entity and state | wizard warns | Refused | Done | #172 |
| Grid squares, including VUCC lists of two or four | wizard | | Done | #172 |
| IOTA reference | wizard | | Done | #172 |
| Edit a station location | Edit Station Location | | 0.7.0 | #172 |
| Delete a station location | Delete | | 0.7.0 | #172 |

### 1.6 Signing choices

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Sign only QSOs in a date range | dialog | `qg-trust -b`, `-e` | Done | #173 |
| Confirm the station location before signing | dialog | | 0.7.0 | #174 |
| QSOs signed before: new only, sign again, or cancel | dialog | Needs 1.2's record | 0.7.0 | #172 |
| Show which QSOs were signed before | dialog | | 0.7.0 | #172 |
| Report what was signed and what was refused | Status Log | `qg-trust` gives the count and names every QSO left out, with the reason; Desktop's view to come | Part done | #173, #174 |

### 1.7 New certificates

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Request a new certificate (`.tq5`), matching TQSL's | Request New Callsign Certificate | Library: `CertificateRequest::generate`; Desktop/CLI to come | Part done | #172 |
| Request: call, DXCC entity, first and last QSO date | wizard | Library validates DXCC and QSO dates | Part done | #172 |
| Request: name, address, email | wizard | Library validates and writes bounded public fields | Part done | #172 |
| Request: kind of call (club, DXpedition, special event, former, replacing, QSL manager) | wizard | `CallKind` intent; TQSL has no kind-specific wire field; caller chooses signer | Part done | #172 |
| Request signed by a certificate already held | wizard | Library: `Authorization::Additional`, borrowed `TqslKey` | Part done | #172 |
| Renew a certificate | Renew Callsign Certificate | Library: `Authorization::Renewal`, fresh key and stored response handoff | Part done | #172 |

### 1.8 Upload to LoTW

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Upload a signed log and report LoTW's answer | Sign and upload | Never in tests: nothing is uploaded to ARRL | 0.7.0 | #172 |
| Always check LoTW's server certificate | a setting | Never turned off | 0.7.0 | #172 |

## 2. Nice to have

| Feature | TQSL | Why later | Status |
|---|---|---|---|
| Sign a Cabrillo log, read Cabrillo, custom contest definitions | Sign and save; Preferences | Most loggers export ADIF | Later |
| Read ADX (ADIF in XML) | | Few loggers write it | Later |
| Test signing: sign, upload nothing | Test Signing | Saving `.tq8` without uploading already does this | Later |
| Grid checked against the entity, state or county | warns | TQSL only warns | Later |
| Continent and WPX prefix in a location | wizard | Not signed | Later |
| Primary QSL manager call | Preferences | Rarely used | Later |
| Restore a deleted certificate | Restore Deleted | Delete comes first | Later |
| Restore a deleted station location | Restore Deleted | Delete comes first | Later |
| Automatic export on exit | Preferences | Comes after export itself (1.3) | Later |
| Rebuild the record of signed QSOs from LoTW | Help: Synchronize | Needs upload first | Later |
| Ask LoTW whether a certificate is still good (by serial) | | Calls ARRL; needs a decision first | Later |
| Take a new ARRL configuration (`config.xml`) without a new release | automatic | A release with new tables works meanwhile | Later |
| Wipe the record of signed QSOs | `-w` | Rarely needed | Later |
| Create a new ADIF file (QSO entry) | Create New ADIF file | A logger's job | Later |
| Edit an ADIF file | Edit existing ADIF file | A logger's job | Later |

## 3. Won't add

| Feature | TQSL | Why not |
|---|---|---|
| Save one certificate and key (`.p12`) | Save Callsign Certificate | The export moves keys; to move only some, delete the rest first |
| `.p12` export in Apple Keychain's older format | Preferences | QG Trust saves no `.p12`; the Keychain reads modern AES-256 files from macOS 15 on anyway |
| Key password on the command line (`-p`) | `-p` | A password never goes on a command line; another way is needed |
| Choosing the upload server and its answers | Server Setup | Logs go to LoTW only |
| Settings for upload, server or proxy taken from a `.tbk` file | File menu | A file could send logs elsewhere |
| A choice to turn off key passwords | Preferences | Handled by the key store (1.2) |
| Proxy settings | Network Proxy | Desktop's own network settings |
| Check for program updates | Help | Desktop's updater |
| Language | File: Language | Desktop's own |
| Documentation, About, first-run help | Help | Desktop's own |
| Diagnostic mode | File: Diagnostic Mode | Desktop's own diagnostics |
| TQSL's window: tabs, status tab, file extensions, open in ADIF editor | main window, Preferences | Desktop's own screens |
| Log in to the LoTW website | button | Opens a browser; nothing for the library to do |
| Show the options at startup without a date dialog (`-d`) | `-d` | No dialog in the library |
| Quiet and batch modes as TQSL's window has them (`-q`, `-x`) | `-q`, `-x` | The command line has no window |

## 4. The command line (`qg-trust`)

Follows the library: each option comes once the library feature under it is built. A logger that
calls TQSL's command line today should get the same meaning, including exit codes.

| TQSL option | Meaning | Needs | Status | Issue |
|---|---|---|---|---|
| `-h`, `-v` | help, version | | Done | #173 |
| `FILE`, `-o` | the log to sign; the `.tq8` to write | 1.1 | Done | #173 |
| `-l` | station location | 1.5 | Part done: by name | #173 |
| `-b`, `-e` | first and last QSO date | 1.6 | Done | #173 |
| `-a` | QSOs signed before: abort, all, compliant, ask | 1.6 | 0.7.0 | #173 |
| `-f` | location details in the log: ignore, report, update | 1.3 | 0.7.0 | #173 |
| `-i` | import `.tq6`, `.p12` or `.tbk` | 1.3, 1.4 | Part done: a `.tbk` is read for the run, not imported | #173 |
| `-s` | add, or with `-l` edit, a location | 1.5 | 0.7.0 | #173 |
| `-u` | upload after signing | 1.8 | 0.7.0 | #173 |
| `-c` | default call | 1.4 | 0.7.0 | #173 |
| `-t` | diagnostic log, with no key or password in it | | 0.7.0 | #173 |
| Exit codes 0 to 15 | the same numbers TQSL uses, and its `Final Status` line | | Part done: 0, 4, 6 to 10 and 15 | #173 |
| `-z` | test signing | 2 | Later | |
| `-n` | check for updates | 3 | Won't | |
| `-p` | a password on the command line: refused; the password is asked for at the terminal, hidden, or read from standard input | 3 | Won't | |
| `-d`, `-q`, `-x` | accepted and ignored: there is no window or date dialog | 3 | Done | #173 |

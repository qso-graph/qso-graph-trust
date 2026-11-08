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
**0.1.0** adds the store-backed `qg-trust` commands and the upload.

tqsllib's own interface, function by function, is mapped to QG Trust's Rust, command line and tests
in [TQSLLIB-MAP.md](TQSLLIB-MAP.md).

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
| Needed for 0.7.0 | 43 | 39 | 3 | 1 |
| Nice to have | 15 |  |  | 15 |
| Won't add | 15 | | | |

## 1. Needed for 0.7.0

### 1.1 Signing a log

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Sign an ADIF log | File: Sign and save | Signed records and signatures match TQSL's byte for byte; only the identification line differs | Done | #171 |
| Save the signed log (`.tq8`) | File: Sign and save | | Done | #171 |
| Read ADIF | | | Done | #171 |
| Read ADX (ADIF in XML) | | Detected by content; same signing path as ADI | Done | #172 |
| Choose the station location to sign for | prompt | | Done | #171 |
| Refuse QSOs outside the certificate's dates | | | Done | #171 |
| Refuse what LoTW would refuse (calls, bands, modes, dates, satellites) | | Names the field at fault | Done | #171 |
| Check the log's own station fields against the location | | Refuses a mismatch, as TQSL does by default | Done | #171 |
| No key left in memory after use | | Done for `qg-trust`; Desktop's native code still to do | Part done | #172 |

### 1.2 Keys and storage

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Keys kept in the OS credential store | a file | macOS Keychain, Windows Credential Manager or the Secret Service, behind an interface no caller can read through; `qg-trust` uses it | Done | #172, #173 |
| Certificates and locations saved, in one format the command line and Desktop share | files | One versioned `store.xml`, replaced whole under a lock; a newer version is refused, never rewritten | Done | #172 |
| Record of QSOs already signed (the duplicate check) | `uploaded.db` | TQSL's own duplicate key, checked against TQSL's record of the standard set | Done | #172 |

### 1.3 Moving from TQSL

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Export certificates, keys and the signed-QSO record to one file | File menu | A part of QSO Graph Desktop's one export file, beside Callsigns and Locations and Settings; all ticked exports everything. This part alone is encrypted (AES-256-GCM), under a 20-character password QG Trust makes up. To move only some calls, delete the others first | Done | #172, #174 |
| Import it on any computer (macOS, Windows, Linux), keys into that computer's credential store | File: Restore | Part by part, onto a clean slate: everything is checked first, then what this computer holds is replaced, nothing merged; Desktop's export file carries it | Part done: Desktop's screen | #172, #174 |
| Read TQSL's `.tbk` file: certificates, keys, locations | File menu | `qg-trust import`: reads, checks and saves what it holds, keys into the OS credential store | Done | #172, #173 |
| Restore TQSL's record of QSOs already signed | File: Restore | Merged into the record, never overwriting what is there | Done | #172 |
| Use TQSL's settings that change what's signed: custom mode mappings, ignore seconds, ignore callsigns in the log, non-amateur calls, location details in the log | Preferences | [Signing options](SIGNING-OPTIONS.md), by hand or from a `.tbk`'s preferences; checked against tqsllib | Done | #172 |
| Say which of TQSL's settings were not taken | | Listed | Done | #172 |

### 1.4 Certificates

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Check a certificate leads to LoTW's root | on load | A file's own root certificates count for nothing | Done | #172 |
| Load a certificate from ARRL (`.tq6`) | Load Callsign Certificate | Every certificate checked; attached to its request's key | Done | #172 |
| Load a certificate and key (`.p12`) | Load Callsign Certificate | AES or 3DES protection; RC2-40 refused | Done | #172 |
| Certificate details: call, DXCC, QSO dates, valid dates, serial | Display Properties | Read | Done | #172 |
| Delete a certificate | Delete Callsign Certificate | With its key | Done | #172 |
| Warn before a certificate expires | at startup, 60 days | Those ending within the days given, and those already expired, as TQSL counts them | Done | #172 |

### 1.5 Station locations

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Add a station location | Add Station Location | | Done | #172 |
| The right fields for each DXCC entity (state, county, province, park and others) | wizard | From ARRL's configuration | Done | #172 |
| Zones must fit the entity and state | wizard warns | Refused | Done | #172 |
| Grid squares, including VUCC lists of two or four | wizard | | Done | #172 |
| IOTA reference | wizard | | Done | #172 |
| Edit a station location | Edit Station Location | | Done | #172 |
| Delete a station location | Delete | | Done | #172 |

### 1.6 Signing choices

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Sign only QSOs in a date range | dialog | `qg-trust -b`, `-e` | Done | #173 |
| Confirm the station location before signing | dialog | | 0.7.0 | #174 |
| QSOs signed before: new only, sign again, or cancel | dialog | Recorded once the `.tq8` is written, as TQSL does | Done | #172 |
| Show which QSOs were signed before | dialog | With where and when, when known | Done | #172 |
| Report what was signed and what was refused | Status Log | `qg-trust` gives the count and names every QSO left out, with the reason; Desktop's view to come | Part done | #173, #174 |

### 1.7 New certificates

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Request a new certificate (`.tq5`), matching TQSL's | Request New Callsign Certificate | Matches tqsllib's but the key, signatures and identification line; the request waits in the store for ARRL's answer | Done | #172 |
| Request: call, DXCC entity, first and last QSO date | wizard | | Done | #172 |
| Request: name, address, email | wizard | | Done | #172 |
| Request: kind of call (club, DXpedition, special event, former, replacing, QSL manager) | wizard | Recorded as the operator's choice; TQSL's request carries no field for it | Done | #172 |
| Request signed by a certificate already held | wizard | | Done | #172 |
| Renew a certificate | Renew Callsign Certificate | With a new key | Done | #172 |

### 1.8 Upload to LoTW

| Feature | TQSL | QG Trust today | Status | Issue |
|---|---|---|---|---|
| Upload a signed log and report LoTW's answer | Sign and upload | `qg-trust upload` and `send`: the request and LoTW's answer as TQSL makes and reads them, over HTTPS. Tests use a stand-in: nothing is uploaded to ARRL | Done | #172, #173 |
| Always check LoTW's server certificate | a setting | `qg-trust` checks it against Mozilla's roots, built in; never turned off, and proved refusing self-signed, expired, wrong-host and untrusted certificates | Done | #173 |

## 2. Nice to have

| Feature | TQSL | Why later | Status |
|---|---|---|---|
| Sign a Cabrillo log, read Cabrillo, custom contest definitions | Sign and save; Preferences | Most loggers export ADIF | Later |
| Test signing: sign, upload nothing | Test Signing | `-z` writes an uncompressed signed file without recording QSOs | Done |
| Grid checked against the entity, state or county | warns | TQSL only warns | Later |
| Continent and WPX prefix in a location | wizard | Not signed | Later |
| Primary QSL manager call | Preferences | Rarely used | Later |
| Restore a deleted certificate | Restore Deleted | Delete comes first | Later |
| Restore a deleted station location | Restore Deleted | Delete comes first | Later |
| Automatic export on exit | Preferences | Comes after export itself (1.3) | Later |
| Rebuild the record of signed QSOs from LoTW | Help: Synchronize | Needs upload first | Later |
| Ask LoTW whether a certificate is still good (by serial) | | Calls ARRL; needs a decision first | Later |
| Take a new ARRL configuration (`config.xml`) without a new release | automatic | A release with new tables works meanwhile | Later |
| Wipe the record of signed QSOs | `-w` | `-w` and `signed clear` ask for approval; `signed clear --yes` is for scripts | Done |
| Create a new ADIF file (QSO entry) | Create New ADIF file | A logger's job | Later |
| Edit an ADIF file | Edit existing ADIF file | A logger's job | Later |

## 3. Won't add

| Feature | TQSL | Why not |
|---|---|---|
| Save one certificate and key (`.p12`) | Save Callsign Certificate | The export moves keys; to move only some, delete the rest first |
| `.p12` export in Apple Keychain's older format | Preferences | QG Trust saves no `.p12`; the Keychain reads modern AES-256 files from macOS 15 on anyway |
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
| `-l` | station location | 1.5 | Done: by name, from the store or `-i` | #173 |
| `-b`, `-e` | first and last QSO date | 1.6 | Done | #173 |
| `-a` | QSOs signed before: abort, all, compliant, ask | 1.6 | Done: `ask` stops with code 14, as `qg-trust` cannot ask | #173 |
| `-f` | location details in the log: ignore, report, update | 1.3 | Done | #173 |
| `-i` | import `.tq6`, `.p12` or `.tbk` | 1.3, 1.4 | Part done: `-i` reads a `.tbk` for the run; `qg-trust import` imports all three | #173 |
| `-s` | add, or with `-l` edit, a location | 1.5 | Part done: `qg-trust location add` and `edit`; `-s` opens TQSL's window, which has no counterpart | #173 |
| `-u` | upload after signing | 1.8 | Done | #173 |
| `-c` | default call | 1.4 | Done: the location's call is replaced for the run, never in the store, and the certificate is chosen for that call and the location's DXCC entity; `-f` compares the log with the location as `-c` changes it | #173 |
| `-t` | diagnostic log, with no key or password in it | | Done: TQSL's header, then each step, counts of QSOs signed and left out by reason, the upload's answer and the exit code; any value that could be a password is written `<redacted>`; owner-only on Unix | #173 |
| Exit codes 0 to 15 | the same numbers TQSL uses, and its `Final Status` line | | Done: 0 to 4, 6 to 11, 14 and 15; 5, 12 and 13 have no cause in `qg-trust` | #173 |
| `-z` | test signing | 2 | Done: no records; no effect with `-u`, as in TQSL | #173 |
| `-n` | check for updates | 3 | Won't | |
| `-p` | the key's passphrase (TQSL calls it a password) | 3 | Done: accepted, so loggers that always send it (fldigi does by default) keep working, with a warning that a key in the store needs none and that a command line can be read by other programs. It unlocks only a key read with `-i` that has one; it is never written to output or the diagnostic log | #173 |
| `-d`, `-q`, `-x` | accepted and ignored: there is no window or date dialog | 3 | Done | #173 |

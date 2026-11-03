<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Feature parity: TQSL 2.8.7 and QSO Graph Trust

Every feature and option TQSL 2.8.7 has, in its app and on its command line, and where QSO Graph Trust
stands on each, so it can be decided what to implement, what not to, what is done and what is left.
Not everything here needs to be in QG Trust. The list is complete so the
choice is made row by row, not by omission.

Read from TQSL's source at v2.8.7 (commit d9e01726): the menus and tabs (`apps/tqsl.cpp`), preferences
(`apps/tqsl_prefs.cpp`), the certificate request wizard (`apps/crqwiz.cpp`), certificate loading
(`apps/loadcertwiz.cpp`), station locations (`apps/stationdial.cpp`, `apps/tqslwiz.cpp`), QSO entry
(`apps/qsodatadialog.cpp`), passwords (`apps/getpassword.cpp`) and the command line (`cmdLineDesc`).

**Where** says where it would live: **Lib** (the `qso-graph-trust` library), **CLI** (`qg-trust`),
**QSGD** (QG Trust's extension in QSO Graph Desktop, its only interface, decision 0005).

**Status** is a fact about the code: **Done** (code and a test, on `main`), **In review** (an open pull
request), **Not started**. **Decision** is **Implement**, **Won't**, or **Undecided**.

## 1. Signing logs (File menu, Log Operations tab)

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 1.1 | Sign an ADIF log | File: Sign and save | Lib | Done | Implement | `.tq7`/`.tq8` byte for byte as tqsllib's (Gate B, #4) |
| 1.2 | Sign a Cabrillo log | File: Sign and save | Lib | Not started | Undecided | Uses the Cabrillo contest definitions (5.4) |
| 1.3 | Save the signed log (`.tq8`) | File: Sign and save | Lib, CLI, QSGD | Lib done | Implement | gzip, `signed_log::tq8` |
| 1.4 | Sign and upload to LoTW | File: Sign and upload | Lib, CLI, QSGD | Not started | Undecided | Uploading is phase 4. Never in tests: nothing is uploaded to ARRL |
| 1.5 | Test signing (sign, upload nothing) | File: Test Signing | CLI, QSGD | Not started | Undecided | `tqsl -z` |
| 1.6 | Choose the station location to sign for | prompt; `-l` | Lib, CLI, QSGD | Lib done | Implement | `StationLocation` |
| 1.7 | Confirm the station location before signing | dialog | QSGD | Not started | Undecided | "Please verify that this is the correct Station Location" |
| 1.8 | QSO date range to sign | dialog; `-b`, `-e` | Lib, CLI, QSGD | Not started | Undecided | Preference "Prompt for QSO Date range" (5.2) |
| 1.9 | Refuse QSOs outside the certificate's QSO dates | converter | Lib | Done | Implement | `LogError::QsoOutsideCertificate` |
| 1.10 | Previously signed QSOs: new only, re-upload, or cancel | dialog; `-a` | Lib, CLI, QSGD | Not started | Undecided | Needs QG Trust's own record of signed QSOs (4.4) |
| 1.11 | Show details of previously signed QSOs | dialog | QSGD | Not started | Undecided | Preference "Display details of previously signed QSOs" |
| 1.12 | Check the log's own station fields (`MY_*`, `STATION_CALLSIGN`) | converter | Lib | Done | Implement | Refused if they disagree (TQSL's default, "Report") |
| 1.13 | Refuse what LoTW would refuse (calls, bands, modes, dates, satellites) | converter | Lib | Done | Implement | `QsoError`, naming the field |
| 1.14 | Status log of what was signed or refused | Status Log tab | QSGD | Not started | Undecided | |

## 2. Callsign certificates (Callsign Certificate menu and tab)

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 2.1 | Request a new certificate (`.tq5`) | Request New Callsign Certificate | Lib, QSGD | Not started | Undecided | Gate C: `.tq5` output matches tqsllib's |
| 2.2 | Request: callsign, DXCC entity, first and last QSO date | wizard | Lib, QSGD | Not started | Undecided | Dates checked against the entity's valid dates |
| 2.3 | Request: name, address, city, state, postal code, country, email | wizard | Lib, QSGD | Not started | Undecided | |
| 2.4 | Request: kind of call (club, DXpedition, special event, former, replacing, QSL manager) | wizard | Lib, QSGD | Not started | Undecided | Some need approval with an existing certificate |
| 2.5 | Request signed by an existing certificate | wizard | Lib, QSGD | Not started | Undecided | |
| 2.6 | Key password chosen at request | wizard | Lib, QSGD | Not started | Undecided | Only 1024-bit keys |
| 2.7 | Renew a certificate | Renew Callsign Certificate | Lib, QSGD | Not started | Undecided | |
| 2.8 | Load a certificate (`.tq6`) | Load Callsign Certificate from File; `-i` | Lib, CLI, QSGD | Not started | Undecided | Certificate fields are read (Lib); importing a `.tq6` is not yet |
| 2.9 | Load a certificate and key (`.p12`) | Load from File; `-i` | Lib, CLI, QSGD | Not started | Undecided | |
| 2.10 | Save a certificate and key (`.p12`) | Save Callsign Certificate to File | Lib, QSGD | Not started | Implement | Always protected by a password QG Trust generates, 80 bits or more, 14 to 24 characters (Gate C) |
| 2.11 | `.p12` compatible with Apple Keychain | preference "Export P12 files compatible with Apple Keychain" | Lib | Not started | Undecided | TQSL's weak-crypto export |
| 2.12 | Certificate properties | Display Callsign Certificate Properties | Lib, QSGD | Lib done in part | Undecided | Call, DXCC, QSO dates, validity, serial (`Certificate`) |
| 2.13 | Delete a certificate | Delete Callsign Certificate | Lib, QSGD | Not started | Undecided | |
| 2.14 | Restore a deleted certificate | Restore Deleted Callsign Certificate | Lib, QSGD | Not started | Undecided | |
| 2.15 | Certificate chain checked to LoTW's root | on load | Lib | Done | Implement | Pinned root; a file's own roots trust nothing (#7) |
| 2.16 | Expiry warning before a certificate ends | startup; preference CertWarnDays (60) | QSGD | Not started | Undecided | |
| 2.17 | Certificate status from LoTW (by serial) | `lotw/crl?serial=` | Lib, QSGD | Not started | Undecided | Calls ARRL; none until decided |
| 2.18 | Key held in the OS credential store | (TQSL: a file) | Lib, QSGD | Not started | Implement | QG Trust's requirement, not TQSL's |
| 2.19 | No key data left in freed memory | | Lib, CLI | Done for `qg-trust` | Implement | Wiping allocator, policy check, custody test (#5) |

## 3. Station locations (Station Location menu and tab)

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 3.1 | Add a station location | Add Station Location; `-s` | Lib, QSGD | Lib done | Undecided | `StationLocation::new`, checked against ARRL's configuration |
| 3.2 | Edit a station location | Edit Station Location; `-s -l` | QSGD | Not started | Undecided | |
| 3.3 | Delete a station location | Delete | QSGD | Not started | Undecided | |
| 3.4 | Restore a deleted station location | Restore a Deleted Station Location | QSGD | Not started | Undecided | |
| 3.5 | Location properties | Display Station Location Properties | QSGD | Not started | Undecided | |
| 3.6 | Fields per DXCC entity (state, county, province, oblast, prefecture, park) | wizard pages | Lib | Done | Implement | From `config.xml` |
| 3.7 | Zones consistent with entity and state | wizard | Lib | Done | Implement | Refused; TQSL warns |
| 3.8 | Grid checked against the entity, state or county (`vuccgrids.dat`) | wizard | Lib | Not started | Undecided | TQSL warns and lets you go on |
| 3.9 | Grid lists (VUCC: two or four) | wizard | Lib | Done | Implement | |
| 3.10 | IOTA reference checked | wizard | Lib | Done | Implement | |
| 3.11 | Continent and WPX prefix fields | wizard | Lib | Not started | Undecided | In TQSL's field list; not signed |

## 4. Backup and restore (File menu)

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 4.1 | Restore TQSL's backup (`.tbk`): certificates, keys, locations | Restore; `-i file.tbk` | Lib, CLI, QSGD | Lib done (#7) | Implement | Gate C; signing after it matches tqsllib's |
| 4.2 | Restore TQSL's settings from a backup | Restore | Lib | Read (#7), not yet applied | Undecided | Settings that change signing are read; applying them is not yet |
| 4.3 | Back up QG Trust (its own format) | Backup | Lib, QSGD | Not started | Undecided | Keys always under a generated password (2.10) |
| 4.4 | Record of signed QSOs (duplicate check) | `uploaded.db`; restored from `.tbk` | Lib | Read from `.tbk` (#7) | Undecided | QG Trust's own store not started |
| 4.5 | Automatic backup on exit; folder; versions kept | preferences (Options) | QSGD | Not started | Undecided | |

## 5. Preferences (File: Preferences, six tabs)

### 5.1 Options

| # | Setting | Status | Decision | Notes |
|---|---|---|---|---|
| 5.1.1 | ADIF file extensions (`adi adif`) | Not started | Undecided | TQSL's file dialogs |
| 5.1.2 | Cabrillo file extensions (`log cbr`) | Not started | Undecided | |
| 5.1.3 | Allow automatic configuration backup | Not started | Undecided | 4.5 |
| 5.1.4 | Backup file folder | Not started | Undecided | 4.5 |
| 5.1.5 | Number of backups to retain (10) | Not started | Undecided | 4.5 |
| 5.1.6 | Open ADIF files in ADIF editor | Not started | Undecided | 7.2 |
| 5.1.7 | Display status messages in separate tab | Not started | Undecided | TQSL's window |
| 5.1.8 | Enable passphrases for callsign certificates | Not started | Undecided | 2.6 |
| 5.1.9 | Export P12 files compatible with Apple Keychain | Not started | Undecided | 2.11 |

### 5.2 Log Handling

| # | Setting | Status | Decision | Notes |
|---|---|---|---|---|
| 5.2.1 | Ignore seconds in QSO times | Read (#7) | Undecided | Changes `QSO_TIME`; not yet applied when signing |
| 5.2.2 | Ignore callsigns in ADIF files | Read (#7) | Undecided | Skips the `STATION_CALLSIGN`/`OPERATOR` check |
| 5.2.3 | Allow nonamateur call signs | Read (#7) | Undecided | Signs calls TQSL thinks invalid |
| 5.2.4 | QTH details in the log: ignore, report, or override the location | Read (#7) | Undecided | Report is TQSL's default and QG Trust's behaviour |
| 5.2.5 | Prompt for QSO date range when signing | Not started | Undecided | 1.8 |
| 5.2.6 | Display details of previously signed QSOs | Not started | Undecided | 1.11 |
| 5.2.7 | Primary QSL manager callsign | Not started | Undecided | |

### 5.3 ADIF Modes

| # | Setting | Status | Decision | Notes |
|---|---|---|---|---|
| 5.3.1 | Custom ADIF mode mappings (ADIF mode to LoTW mode) | Read (#7) | Undecided | Changes `MODE`; one naming a standard mode is left out, as TQSL does |

### 5.4 Cabrillo Specs

| # | Setting | Status | Decision | Notes |
|---|---|---|---|---|
| 5.4.1 | Custom Cabrillo contest definitions (name, HF or VHF, call-worked field) | Read (#7) | Undecided | For Cabrillo signing (1.2) |

### 5.5 Network Proxy

| # | Setting | Status | Decision | Notes |
|---|---|---|---|---|
| 5.5.1 | Enable a proxy; address, port, type | Not started | Undecided | Never taken from a backup (#7) |

### 5.6 Server Setup (hidden in TQSL unless enabled)

| # | Setting | Status | Decision | Notes |
|---|---|---|---|---|
| 5.6.1 | Upload URL, form field, status and message patterns | Not started | Undecided | Never taken from a backup (#7): a file could send logs elsewhere |
| 5.6.2 | Verify the upload server's certificate | Not started | Implement | Never off (AGENTS.md: TLS verification is never turned off) |

## 6. LoTW online (Help menu, upload)

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 6.1 | Upload a signed log, report LoTW's answer | Sign and upload; `-u` | Lib, CLI, QSGD | Not started | Undecided | Phase 4 |
| 6.2 | Synchronize uploaded data with LoTW | Help: Synchronize | Lib, QSGD | Not started | Undecided | Downloads your QSOs to rebuild the signed-QSO record |
| 6.3 | Log in to the LoTW website | Log Operations: button | QSGD | Not started | Undecided | Opens a browser |
| 6.4 | Check for program updates | Help: Check for Updates; `-n` | QSGD | Not started | Undecided | QSO Graph Desktop has its own updater |
| 6.5 | Update ARRL's configuration (`config.xml`) | automatic; `-n` | Lib | Not started | Undecided | QG Trust regenerates its tables from a new `config.xml` (AGENTS.md) |

## 7. Log files

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 7.1 | Create a new ADIF file (QSO entry) | File: Create New ADIF file | QSGD | Not started | Undecided | Band, frequency, mode, propagation, satellite, date, time |
| 7.2 | Edit an existing ADIF file | File: Edit existing ADIF file | QSGD | Not started | Undecided | |
| 7.3 | Read ADIF | converter | Lib | Done | Implement | |
| 7.4 | Read ADX (XML ADIF) | | Lib | Not started | Undecided | In Gate C's fuzzing list |
| 7.5 | Read Cabrillo | converter | Lib | Not started | Undecided | 1.2 |

## 8. Command line

TQSL's options (`tqsl -h`), and `qg-trust`'s. A logger calling `tqsl` today should find the same meaning.

| # | TQSL | Meaning | Status in `qg-trust` | Decision | Notes |
|---|---|---|---|---|---|
| 8.1 | `-a`, `--action` | previously signed QSOs: abort, all, compliant, ask | Not started | Undecided | |
| 8.2 | `-b`, `--begindate` | first QSO date to sign | Not started | Undecided | |
| 8.3 | `-c`, `--callsign` | default callsign | Not started | Undecided | |
| 8.4 | `-d`, `--nodate` | no date range dialog | Not started | Undecided | |
| 8.5 | `-e`, `--enddate` | last QSO date to sign | Not started | Undecided | |
| 8.6 | `-f`, `--verify` | QTH details: ignore, report, update | Not started | Undecided | 5.2.4 |
| 8.7 | `-h`, `--help` | help | Done | Implement | |
| 8.8 | `-i`, `--import` | import `.p12`, `.tq6` or `.tbk` | Not started | Undecided | 2.8, 2.9, 4.1 |
| 8.9 | `-l`, `--location` | station location | Not started | Undecided | |
| 8.10 | `-n`, `--updates` | check for updates | Not started | Undecided | 6.4 |
| 8.11 | `-o`, `--output` | output file (default the input's name, `.tq8`) | Not started | Undecided | |
| 8.12 | `-p`, `--password` | key password on the command line | Not started | Won't as-is | AGENTS.md: a password never appears on a command line. Another way is needed |
| 8.13 | `-q`, `--quiet` | quiet, as `-x` | Not started | Undecided | |
| 8.14 | `-s`, `--editlocation` | create, or with `-l` edit, a location | Not started | Undecided | |
| 8.15 | `-t`, `--diagnose` | diagnostic log file | Not started | Undecided | No key data or password ever in it |
| 8.16 | `-u`, `--upload` | upload after signing | Not started | Undecided | 6.1 |
| 8.17 | `-v`, `--version` | version | Done | Implement | |
| 8.18 | `-w`, `--wipe` | wipe the uploads database | Not started | Undecided | |
| 8.19 | `-x`, `--batch` | exit after processing | Not started | Undecided | |
| 8.20 | `-z`, `--test-sign` | test sign a log | Not started | Undecided | 1.5 |
| 8.21 | `FILE` | the ADIF or Cabrillo log to sign | Not started | Undecided | |
| 8.22 | Exit codes 0 to 15 | Success, Cancel, Rejected, Unexpected response, TQSL error, Library error, Input, Output, No QSOs, Some not processed, Syntax, Connection failed, Unknown, Busy, Already uploaded, Bad passphrase | Syntax (10) done | Undecided | Same numbers, so a logger reads the same meaning |

## 9. The app itself

| # | Feature | TQSL | Where | Status | Decision | Notes |
|---|---|---|---|---|---|---|
| 9.1 | Language | File: Language | QSGD | Not started | Undecided | QSO Graph Desktop's own |
| 9.2 | Diagnostic mode (trace file) | File: Diagnostic Mode | QSGD | Not started | Undecided | No key data or password ever in it |
| 9.3 | Documentation, About | Help | QSGD | Not started | Undecided | |
| 9.4 | Tabs: Log Operations, Station Locations, Callsign Certificates, Status Log | main window | QSGD | Not started | Undecided | The Callsigns page (decision 0005) |
| 9.5 | First-run help | startup | QSGD | Not started | Undecided | |

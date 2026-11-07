<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust-cli: `qg-trust`

Sign your log for ARRL's [Logbook of The World](https://lotw.arrl.org) (LoTW) and upload it, from
the command line, with your key kept in your computer's credential store (macOS Keychain, Windows
Credential Manager, or the Secret Service on Linux) instead of a file.

```sh
cargo install qso-graph-trust-cli
```

- **Bring what you have from TQSL in one step:** your certificates, keys, station locations and
  TQSL's record of what you have signed, from a TQSL backup (`.tbk`).
- **Sign and upload in one command,** with QSOs you signed before left out unless you ask.
- **Works with your logger:** the same option letters, exit codes and final status line loggers
  already use with the `tqsl` command line.
- **Every QSO checked by ARRL's own rules** before it is signed; one LoTW would refuse is named, with
  the reason, and the rest are signed. Signatures are byte for byte what TQSL makes.
- **Your key stays yours:** it leaves the credential store only to sign, a password is never taken
  from the command line, and everything the program frees is wiped.
- **The upload is HTTPS to LoTW only,** its certificate always checked against Mozilla's roots.

## Getting started

```sh
qg-trust import ~/tqsl-backup.tbk     # certificates, keys, locations and your signing record
qg-trust cert list                    # what you have, and when each certificate expires
qg-trust location list                # your station locations
qg-trust send log.adi -l Home         # sign log.adi for Home and upload it to LoTW
```

`qg-trust sign log.adi -l Home` signs without uploading, into `log.tq8`; `qg-trust upload log.tq8`
uploads one later. A key that TQSL protected with a password is asked for once, when you import it.

| Command | |
|---|---|
| `qg-trust sign LOG -l NAME` | sign a log; `-b`/`-e` choose dates, `--again` signs QSOs signed before, `--cert ID` picks the certificate when you have more than one for the call |
| `qg-trust send LOG -l NAME` | sign and upload, keeping the `.tq8` beside the log |
| `qg-trust upload LOG.tq8` | upload a signed log |
| `qg-trust import FILE` | a TQSL backup (`.tbk`), ARRL's answer to a request (`.tq6`) or a `.p12`; `--trust-root FINGERPRINT` trusts a new ARRL root the `.tq6` or `.p12` brings, once `import` has named it |
| `qg-trust cert list` | your certificates and requests (`--json` for scripts) |
| `qg-trust cert request` | ask ARRL for a certificate: writes the `.tq5` to upload at LoTW |
| `qg-trust cert renew CALL` | renew one, with a new key, for the QSO dates it has (`--to DATE` or `--no-end-date` to change the last) |
| `qg-trust cert delete ID --force` | delete a certificate and its key |
| `qg-trust location list` / `show NAME` | your station locations |
| `qg-trust location add NAME --call CALL --dxcc N --grid GRID FIELD=VALUE…` | add one |
| `qg-trust location edit NAME …` / `delete NAME --force` | change or delete one |
| `qg-trust location fields N` | the fields a DXCC entity's locations take |
| `qg-trust root list` | the LoTW roots and CAs your certificates chain to, built in and accepted, with their SHA-256 fingerprints (`--json` for scripts) |
| `qg-trust root remove FINGERPRINT` | stop trusting a root you accepted; the built-in ones stay |

Every command has `--help`, with an example. TQSL's settings that change what is signed are options
of `sign` and `send` (`--ignore-seconds`, `--qth`, `--mode ADIF=LOTW`, …); `import` names the ones a
backup used.

The store is the one QSO Graph Desktop uses, so a ham sees the same certificates and locations in
both. `QG_TRUST_STORE` names another folder.

## For loggers

Loggers that call `tqsl` call `qg-trust` with the same options:

```sh
qg-trust -x -d -l "Home" -a compliant -u log.adi
```

signs with the keys in the store and uploads. `-i FILE` instead reads a TQSL backup for that one run.

| Option | |
|---|---|
| `-l`, `--location NAME` | your station location, by name |
| `-b`, `--begindate DATE` | sign only QSOs on or after DATE (`YYYY-MM-DD` or `YYYYMMDD`) |
| `-e`, `--enddate DATE` | sign only QSOs on or before DATE |
| `-o`, `--output FILE` | where to write the signed log (default: the log's name with `.tq8`) |
| `-u`, `--upload` | upload the signed log to LoTW |
| `-a`, `--action ACTION` | QSOs signed before: `abort`, `compliant` (only new ones), `all`, or `ask` |
| `-f`, `--verify HOW` | the log's own location details: `ignore`, `report` (the default), `update` |
| `-i`, `--import FILE` | read the certificate, key and location from a TQSL backup for this run |
| `-c`, `--callsign CALL` | sign as CALL in place of the location's own call, with CALL's certificate |
| `-t`, `--diagnose FILE` | write a diagnostic log of the run for support; it never holds a key or a password |
| `-x`, `-q`, `-d` | accepted and ignored; `qg-trust` always exits when done |
| `-h`, `-v` | help, version |
| `--completions SHELL` | write shell completions (bash, zsh, fish, powershell, elvish) |

`qg-trust` cannot ask, so without `-a` (or with `-a ask`) it stops where TQSL would ask: at QSOs
signed before, with code 14, and at a QSO it cannot sign, with code 8, signing nothing either
time and saying which `-a` to give. `-a abort` stops at either, as TQSL's batch mode does;
`-a compliant` and `-a all` sign the rest. `-a` other than `all` needs the store's record of signed
QSOs, so it is refused with `-i`. If the key read with `-i` has a
password, `qg-trust` asks for it at the terminal, with what you type hidden; when a logger runs it,
it reads the password as one line from standard input.

Help, version and completions exit successfully without a Final Status line. Completion scripts
never contain color codes. Messages use color at a terminal. `NO_COLOR` or `CLICOLOR=0` disables
it; `CLICOLOR_FORCE` enables color when output is redirected. The Final Status line is always plain
text.

The last line a logger call writes to standard error is `Final Status: <name>(<code>)`; the
commands above use the same codes without that line:

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | LoTW refused the upload, with its reason |
| 3 | LoTW's answer could not be read: check your LoTW account before uploading again |
| 4 | No certificate for the station location's call and entity in force, or a key that cannot sign |
| 6 | The certificate file or the log could not be read, or the certificate is not LoTW's |
| 7 | The signed log could not be written |
| 8 | No QSOs to sign: nothing is written |
| 9 | Some QSOs not signed, each named with the reason; the rest are |
| 10 | Command syntax: a missing or unknown option, an invalid date, a password given on the command line |
| 11 | LoTW could not be reached: the signed log is kept for another try |
| 14 | QSOs signed before, with `-a abort`, or no `-a` saying what to do |
| 15 | The password does not unlock the key: nothing is written |

GPL-3.0-only. QSO Graph Trust is not made, affiliated with or endorsed by ARRL; "Logbook of The World",
"LoTW" and "TQSL" are ARRL's names, used here only to say what it works with. Credits, sources and the
source code: <https://github.com/qso-graph/qso-graph-trust>.

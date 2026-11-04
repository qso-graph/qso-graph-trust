<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust-cli: `qg-trust`

Sign ADIF logs for ARRL's [Logbook of The World](https://lotw.arrl.org) (LoTW) from the command line,
with [`qso-graph-trust`](https://crates.io/crates/qso-graph-trust). From the same key, station location
and QSOs, the signed records and their signatures are TQSL's, byte for byte; only the line naming the
program that made the file differs.

```sh
cargo install qso-graph-trust-cli
```

**This is a beta.** It signs your log with your LoTW certificate. For now it gets the certificate, and
your station location, from the backup file TQSL saves (`.tbk`), and asks for the key's password. Keeping keys in the operating system's credential store,
uploading to LoTW and the record of QSOs already signed are still to come.

## Signing a log

```sh
qg-trust -i tqslconfig.tbk -l "Home" log.adi
```

writes `log.tq8`, which you upload on LoTW's website. If the key has a password, `qg-trust` asks for
it at the terminal, with what you type hidden; with no terminal, as when a logger runs it, it reads
one line from standard input. A password is never given on the command line.

| Option | |
|---|---|
| `-i`, `--import FILE` | TQSL's backup file, where `qg-trust` gets your certificate and station location |
| `-l`, `--location NAME` | the station location, by its name in the backup |
| `-b`, `--begindate DATE` | sign only QSOs on or after DATE (`YYYY-MM-DD` or `YYYYMMDD`) |
| `-e`, `--enddate DATE` | sign only QSOs on or before DATE |
| `-o`, `--output FILE` | where to write the signed log (default: the log's name with `.tq8`) |
| `-x`, `-q`, `-d` | accepted, as TQSL takes them; `qg-trust` always exits when done |
| `-h`, `-v` | help, version |

The option letters, the exit codes and the last line it writes to standard error,
`Final Status: <name>(<code>)`, are TQSL's, so a logger that runs `tqsl` reads `qg-trust` the same way.
`-i` differs: TQSL imports the file into its own store; `qg-trust` reads the backup for this run.

| Code | Meaning |
|---|---|
| 0 | Success |
| 4 | No certificate for the station location's call and entity in force, or a key that cannot sign |
| 6 | The backup or the log could not be read, or the backup's certificates are not under LoTW's root |
| 7 | The signed log could not be written |
| 8 | No QSOs to sign: nothing is written |
| 9 | Some QSOs not signed, each named with the reason; the rest are |
| 10 | Command syntax: a missing or unknown option, an invalid date, a password given on the command line |
| 15 | The password does not unlock the key: nothing is written |

TQSL's other options (`-a`, `-c`, `-f`, `-n`, `-p`, `-s`, `-t`, `-u`, `-w`, `-z`) are refused with code
10, saying so; what `qg-trust` will and won't take on is in the
[feature-parity list](https://github.com/qso-graph/qso-graph-trust/blob/main/docs/FEATURE-PARITY.md).

The program wipes every block of memory it frees, so no key data or password is left there.

GPL-3.0-only. QSO Graph Trust is not made, affiliated with or endorsed by ARRL; "Logbook of The World",
"LoTW" and "TQSL" are ARRL's names, used here only to say what it works with. Credits, sources and the
source code: <https://github.com/qso-graph/qso-graph-trust>.

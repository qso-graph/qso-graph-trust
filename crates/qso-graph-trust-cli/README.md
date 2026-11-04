<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust-cli: `qg-trust`

Sign your ADIF logs with your LoTW certificate from the command line, so ARRL's
[Logbook of The World](https://lotw.arrl.org) (LoTW) accepts them.

```sh
cargo install qso-graph-trust-cli
```

- **Works with your logger:** the same option letters, exit codes and final status line loggers
  already use with the `tqsl` command line.
- **Every QSO checked by ARRL's own rules** before it is signed; one LoTW would refuse is named, with
  the reason, and the rest are signed.
- **Your password stays private:** asked for with what you type hidden, never on the command line, and
  wiped from memory with everything else the program frees.

## Signing a log

```sh
qg-trust -i tqslconfig.tbk -l "Home" log.adi
```

writes `log.tq8`, which you upload on LoTW's website. If the key has a password, `qg-trust` asks for
it at the terminal, with what you type hidden; when a logger runs it, it reads the password as one
line from standard input.

| Option | |
|---|---|
| `-i`, `--import FILE` | the file with your certificate (the `.tbk` TQSL saves) |
| `-l`, `--location NAME` | your station location, by name |
| `-b`, `--begindate DATE` | sign only QSOs on or after DATE (`YYYY-MM-DD` or `YYYYMMDD`) |
| `-e`, `--enddate DATE` | sign only QSOs on or before DATE |
| `-o`, `--output FILE` | where to write the signed log (default: the log's name with `.tq8`) |
| `-x`, `-q`, `-d` | accepted and ignored; `qg-trust` always exits when done |
| `-h`, `-v` | help, version |

For loggers, the last line written to standard error is `Final Status: <name>(<code>)`, with these
codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 4 | No certificate for the station location's call and entity in force, or a key that cannot sign |
| 6 | The certificate file or the log could not be read, or the certificate is not LoTW's |
| 7 | The signed log could not be written |
| 8 | No QSOs to sign: nothing is written |
| 9 | Some QSOs not signed, each named with the reason; the rest are |
| 10 | Command syntax: a missing or unknown option, an invalid date, a password given on the command line |
| 15 | The password does not unlock the key: nothing is written |

GPL-3.0-only. QSO Graph Trust is not made, affiliated with or endorsed by ARRL; "Logbook of The World",
"LoTW" and "TQSL" are ARRL's names, used here only to say what it works with. Credits, sources and the
source code: <https://github.com/qso-graph/qso-graph-trust>.

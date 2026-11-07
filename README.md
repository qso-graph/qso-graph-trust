<p align="center">
  <a href="https://github.com/qso-graph/qso-graph-trust/releases/latest"><img src="https://img.shields.io/github/v/release/qso-graph/qso-graph-trust?sort=semver&label=Release&color=blue" alt="Latest release"></a>
  <a href="https://crates.io/crates/qso-graph-trust-cli"><img src="https://img.shields.io/crates/v/qso-graph-trust-cli?label=crates.io&color=blue" alt="qso-graph-trust-cli on crates.io"></a>
  <a href="https://docs.rs/qso-graph-trust"><img src="https://img.shields.io/docsrs/qso-graph-trust?label=docs.rs" alt="The library's documentation on docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0--only-blue" alt="License: GPL-3.0-only"></a>
  <img src="https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platforms: Windows, Linux, macOS">
</p>

<p align="center">
  <a href="#install"><img src="https://img.shields.io/badge/Windows-signed-2ea44f" alt="Windows: signed"></a>
  <a href="#install"><img src="https://img.shields.io/badge/macOS-notarized-2ea44f" alt="macOS: notarized"></a>
  <a href="#install"><img src="https://img.shields.io/badge/apt%20%26%20dnf-GPG%20signed-2ea44f" alt="apt and dnf: GPG signed"></a>
  <a href="https://github.com/qso-graph/qso-graph-trust/attestations"><img src="https://img.shields.io/badge/Provenance-attested-2ea44f" alt="Provenance: attested, the attestations"></a>
</p>

# QSO Graph Trust

QSO Graph Trust is the part of the QSO Graph Project that signs your logs for ARRL's
[Logbook of The World](https://lotw.arrl.org) (LoTW). It's a ground-up rewrite in Rust, not a
method-by-method port of TQSL. What it does was decided from the sources below, and how it does it is
its own.

## Sources

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
  tables are generated, and ARRL's root and CA certificates (the 2015 pair as TQSL embeds them, the 2023 pair as ARRL
  issues them in a `.tq6`). TQSL 2.8.7, built from
  its own source, is the reference its signed records and signatures are tested against, byte for byte.
- **Other open-source projects:** rfrht's [qso-web](https://github.com/rfrht/qso-web), credited below,
  and a survey of 126 ham-radio Rust crates on crates.io, which found no other LoTW signing crate.
- **Standards:** [ADIF 3.1.7](https://adif.org/317/ADIF_317.htm); RFC 5280 (X.509 certificates),
  RFC 4055 and RFC 8017 (RSA), RFC 1952 (gzip); W3C XML 1.0.

## Who it's for

- **Hams** who want to sign and upload their QSOs to LoTW from the command line or their logger,
  with their key in their computer's credential store.
- **Authors of loggers and tools**, who want LoTW signing inside their own program, through the
  library or the `qg-trust` command line.

## What it does

`qg-trust` signs your ADIF log with your LoTW callsign certificate and uploads it to LoTW, in one
command. It brings over everything you have in TQSL from a TQSL backup: certificates, keys, station
locations and the record of what you have already signed. It also requests and renews certificates and
manages station locations. Loggers that run `tqsl` can run `qg-trust` with the same options, exit
codes and final status line.

## How it's different

- **Your key stays locked away.** It lives in your computer's own credential store (the macOS
  Keychain, Windows Credential Manager, or the Secret Service on Linux), never as a file someone could
  copy, and leaves it only to sign.
- **Every QSO is checked by ARRL's own rules** before it's signed. A QSO LoTW would refuse is named,
  with the reason, and the rest are signed. Signatures are byte for byte what TQSL makes.
- **It works inside the program you already use.** Another logger or a script can sign and upload for
  LoTW directly, and the library puts signing inside your own program.
- **It's built to be safe.** A password is never taken from the command line; the upload is HTTPS to
  LoTW only, its certificate always checked; and everything the program frees is wiped from memory.
  More, and how to report a security problem: [SECURITY.md](SECURITY.md).
- **It's signed.** The macOS program is signed by QSO Graph and notarized by Apple, the Windows
  program is signed by QSO Graph, and the Linux packages and their repositories are signed with QSO
  Graph's release key.

## Install

**macOS (Apple silicon) and Linux, with [Homebrew](https://brew.sh):**

```sh
brew install qso-graph/tap/qso-graph-trust
```

**Debian, Ubuntu:**

```sh
sudo curl -fsSL -o /usr/share/keyrings/qso-graph.gpg https://packages.qso-graph.net/qso-graph.gpg
echo "deb [signed-by=/usr/share/keyrings/qso-graph.gpg] https://packages.qso-graph.net/apt stable main" | sudo tee /etc/apt/sources.list.d/qso-graph.list
sudo apt update && sudo apt install qso-graph-trust
```

**Fedora, RHEL, Rocky:**

```sh
sudo curl -fsSL -o /etc/yum.repos.d/qso-graph.repo https://packages.qso-graph.net/qso-graph.repo
sudo dnf install qso-graph-trust
```

**Windows:** download `qg-trust-<version>-windows-x86_64.zip` from the
[latest release](https://github.com/qso-graph/qso-graph-trust/releases/latest) and put `qg-trust.exe`
on your `PATH`. Every release also has the macOS and Linux programs, and `SHA256SUMS.txt` to check
them against.

**With Rust:** `cargo install qso-graph-trust-cli`.

## Sign and upload a log

```sh
qg-trust import ~/tqsl-backup.tbk     # certificates, keys, locations and your signing record
qg-trust cert list                    # what you have, and when each certificate expires
qg-trust send mylog.adi -l Home       # sign mylog.adi for station location Home and upload it
```

A key that TQSL protected with a password is asked for once, when you import it, with what you type
hidden. `send` leaves out QSOs you signed before unless you ask, and keeps `mylog.tq8` beside the log.
`qg-trust sign mylog.adi -l Home` signs without uploading; `qg-trust upload mylog.tq8` uploads it
later. To sign only some dates, add `-b 2026-01-01` and `-e 2026-06-30`.

When ARRL starts issuing under a new root, its `.tq6` brings the root, and `qg-trust import` names it
with its SHA-256 fingerprint before trusting it: run it again with `--trust-root <fingerprint>` once
you know it is ARRL's. A new root in your own TQSL backup is trusted and named. `qg-trust root list`
shows every root your certificates chain to, and `qg-trust root remove <fingerprint>` stops trusting
one you accepted.

From a logger, the `tqsl` options work as they are:

```sh
qg-trust -x -d -l "Home" -a compliant -u mylog.adi
```

`qg-trust --help` lists everything, and the [command line's page](crates/qso-graph-trust-cli/README.md)
has every command, option and exit code.

## For developers

The library is [`qso-graph-trust`](https://crates.io/crates/qso-graph-trust); its
[page](crates/qso-graph-trust/README.md) has an example. To work on QSO Graph Trust itself:
[CONTRIBUTING.md](CONTRIBUTING.md). What it does and plans, feature by feature:
[docs/FEATURE-PARITY.md](docs/FEATURE-PARITY.md).

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

## Licence

GPL-3.0-only ([LICENSE](LICENSE)); see [NOTICE](NOTICE). QSO Graph Trust is not made, affiliated with or
endorsed by ARRL. "Logbook of The World", "LoTW" and "TQSL" are ARRL's names, used here only to say what it
works with.

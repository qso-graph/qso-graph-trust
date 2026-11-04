// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! What `qg-trust` does with its arguments. Everything outside the program, the root it trusts, the
//! time, how a password is asked for and where messages go, comes in through [`Env`], so the tests
//! run the real path against the standard test set.
//!
//! The options are TQSL 2.8.7's where they mean the same (`apps/tqsl.cpp`, `cmdLineDesc`), and so
//! are the exit codes (`apps/tqslapp.h`) and the last line, `Final Status: <name>(<code>)`, which
//! TQSL writes to standard error and loggers read. `-i` differs: TQSL imports a file into its own
//! store, and `qg-trust`, which has no store yet, reads the TQSL backup it names for this run.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use qso_graph_trust::certificate::Trust;
use qso_graph_trust::qso::{Date, Qso};
use qso_graph_trust::signed_log::{LogError, sign_log, tq8};
use qso_graph_trust::signing::KeyError;
use qso_graph_trust::tbk::{self, BackedUpCertificate};
use qso_graph_trust::{VERSION, records};
use zeroize::Zeroizing;

/// TQSL's exit codes, by the names TQSL gives them (`apps/tqslapp.h`). Those `qg-trust` cannot yet
/// return (cancel, upload and the uploads database) are listed so the names stay in step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Exit {
    Success = 0,
    TqslError = 4,
    InputError = 6,
    OutputError = 7,
    NoQsos = 8,
    QsosSuppressed = 9,
    CommandError = 10,
    BadPassphrase = 15,
}

impl Exit {
    /// The name TQSL prints in its final status line.
    fn name(self) -> &'static str {
        match self {
            Exit::Success => "Success",
            Exit::TqslError => "TQSL Error",
            Exit::InputError => "Error opening input file",
            Exit::OutputError => "Error opening output file",
            Exit::NoQsos => "No QSOs to upload",
            Exit::QsosSuppressed => "Some QSOs not processed",
            Exit::CommandError => "Command Syntax Error",
            Exit::BadPassphrase => "Incorrect passphrase when importing P12 file",
        }
    }
}

/// What the program gives `run`.
pub(crate) struct Env<'a> {
    /// The roots a backup's certificates must chain to: LoTW's, outside the tests.
    pub trust: &'a Trust,
    /// Now, for which certificates are in force.
    pub now: SystemTime,
    /// Asks for a key's password, given the prompt.
    pub ask_password: &'a mut dyn FnMut(&str) -> io::Result<Zeroizing<Vec<u8>>>,
    /// Standard output: help and the version.
    pub out: &'a mut dyn Write,
    /// Standard error: every message, and the final status line.
    pub err: &'a mut dyn Write,
}

const HELP: &str = "\
qg-trust: QSO Graph Trust's command line. Signs your ADIF log with your LoTW certificate, for ARRL's
Logbook of The World (LoTW).

Usage: qg-trust -i CERTIFICATE.tbk -l LOCATION [-b DATE] [-e DATE] [-o OUTPUT.tq8] LOG.adi

  -i, --import FILE      the file with your certificate (the .tbk TQSL saves)
  -l, --location NAME    your station location, by name
  -b, --begindate DATE   sign only QSOs on or after DATE (YYYY-MM-DD or YYYYMMDD)
  -e, --enddate DATE     sign only QSOs on or before DATE
  -o, --output FILE      where to write the signed log (default: LOG with .tq8)
  -x, --batch            accepted, as TQSL's; qg-trust always exits when done
  -q, --quiet            the same as -x
  -d, --nodate           accepted, as TQSL's; qg-trust shows no date dialog
  -h, --help             this help
  -v, --version          the version

The key's password is asked for when it is needed, never given on the command line: at the
terminal with what is typed hidden, or as one line on standard input when there is no terminal.
Exit codes and the last line, \"Final Status: <name>(<code>)\" on standard error, are TQSL's.";

/// The parsed command line.
#[derive(Debug, Default)]
struct Options {
    backup: Option<PathBuf>,
    location: Option<String>,
    begin: Option<Date>,
    end: Option<Date>,
    output: Option<PathBuf>,
    input: Option<PathBuf>,
}

enum Command {
    Help,
    Version,
    Sign(Options),
}

/// Runs `qg-trust` with these arguments and returns its exit code.
pub(crate) fn run(args: &[String], env: &mut Env<'_>) -> u8 {
    let code = match parse(args) {
        Ok(Command::Help) => {
            let _ = writeln!(env.out, "{HELP}");
            return 0;
        }
        Ok(Command::Version) => {
            let _ = writeln!(env.out, "qg-trust {VERSION}");
            return 0;
        }
        Ok(Command::Sign(options)) => sign(&options, env),
        Err(message) => {
            let _ = writeln!(
                env.err,
                "qg-trust: {message}; qg-trust --help says how it is used"
            );
            Exit::CommandError
        }
    };
    let _ = writeln!(env.err, "Final Status: {}({})", code.name(), code as u8);
    code as u8
}

fn parse(args: &[String]) -> Result<Command, String> {
    let mut options = Options::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            match inline.clone().or_else(|| rest.next().cloned()) {
                Some(v) if !v.is_empty() => Ok(v),
                _ => Err(format!("{name} needs a value")),
            }
        };
        match flag {
            "-h" | "--help" => return Ok(Command::Help),
            "-v" | "--version" => return Ok(Command::Version),
            "-i" | "--import" => options.backup = Some(PathBuf::from(value("-i")?)),
            "-l" | "--location" => options.location = Some(value("-l")?),
            "-b" | "--begindate" => options.begin = Some(date(&value("-b")?, "start")?),
            "-e" | "--enddate" => options.end = Some(date(&value("-e")?, "end")?),
            "-o" | "--output" => options.output = Some(PathBuf::from(value("-o")?)),
            "-x" | "--batch" | "-q" | "--quiet" | "-d" | "--nodate" => {}
            "-p" | "--password" => {
                return Err(
                    "a password is never given on the command line: qg-trust asks for \
                            the key's password when it needs it"
                        .to_string(),
                );
            }
            "-a" | "--action" | "-c" | "--callsign" | "-f" | "--verify" | "-n" | "--updates"
            | "-s" | "--editlocation" | "-t" | "--diagnose" | "-u" | "--upload" | "-w"
            | "--wipe" | "-z" | "--test-sign" => {
                return Err(format!("{flag} is TQSL's, and qg-trust does not do it yet"));
            }
            _ if flag.starts_with('-') && flag.len() > 1 => {
                return Err(format!("{flag} is not an option qg-trust knows"));
            }
            _ if options.input.is_some() => return Err("give one log to sign".to_string()),
            _ => options.input = Some(PathBuf::from(arg)),
        }
    }
    if options.input.is_none() {
        return Err("give the log to sign".to_string());
    }
    if options.backup.is_none() {
        return Err("-i names the file with your certificate".to_string());
    }
    if options.location.is_none() {
        return Err("-l names the station location to sign for".to_string());
    }
    if let (Some(b), Some(e)) = (options.begin, options.end)
        && b > e
    {
        return Err("the start date is after the end date".to_string());
    }
    Ok(Command::Sign(options))
}

/// A date as TQSL takes one on its command line: YYYY-MM-DD or YYYYMMDD.
fn date(text: &str, which: &str) -> Result<Date, String> {
    Date::from_iso(text)
        .or_else(|| Date::from_adif(text))
        .ok_or_else(|| format!("{which} date of {text} is invalid"))
}

fn sign(options: &Options, env: &mut Env<'_>) -> Exit {
    let (Some(backup_path), Some(name), Some(input)) =
        (&options.backup, &options.location, &options.input)
    else {
        return Exit::CommandError;
    };
    let backup = match read_file(backup_path, tbk::MAX_TBK_LEN) {
        Ok(bytes) => match tbk::read(&bytes, env.trust) {
            Ok(backup) => backup,
            Err(e) => {
                let _ = writeln!(env.err, "qg-trust: {}: {e}", backup_path.display());
                return Exit::InputError;
            }
        },
        Err(e) => {
            let _ = writeln!(env.err, "qg-trust: {}: {e}", backup_path.display());
            return Exit::InputError;
        }
    };
    let Some(location) = backup.locations.iter().find(|l| l.name == *name) else {
        let names: Vec<&str> = backup.locations.iter().map(|l| l.name.as_str()).collect();
        let _ = writeln!(
            env.err,
            "qg-trust: the backup has no station location named {name:?}; it has: {}",
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            }
        );
        return Exit::CommandError;
    };
    let station = &location.station;

    let Some(entry) = certificate_for(
        &backup.certificates,
        station.call(),
        station.dxcc(),
        env.now,
    ) else {
        let _ = writeln!(
            env.err,
            "qg-trust: the backup has no certificate for {} (DXCC {}) in force now, with its key",
            station.call(),
            station.dxcc()
        );
        return Exit::TqslError;
    };
    let (Some(certificate), Some(entry_key)) = (&entry.certificate, &entry.key) else {
        return Exit::TqslError;
    };
    let key = if entry_key.is_encrypted() {
        let prompt = format!("Password for {}'s key: ", entry.callsign);
        let password = match (env.ask_password)(&prompt) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(env.err, "qg-trust: the password could not be read: {e}");
                return Exit::BadPassphrase;
            }
        };
        entry_key.unlock(Some(&password))
    } else {
        entry_key.unlock(None)
    };
    let key = match key {
        Ok(key) => key,
        Err(KeyError::WrongPassword | KeyError::PasswordNeeded) => {
            let _ = writeln!(
                env.err,
                "qg-trust: that password does not unlock {}'s key",
                entry.callsign
            );
            return Exit::BadPassphrase;
        }
        Err(e) => {
            let _ = writeln!(env.err, "qg-trust: {}'s key: {e}", entry.callsign);
            return Exit::TqslError;
        }
    };

    let records = match read_file(input, 64 * 1024 * 1024)
        .map_err(|e| e.to_string())
        .and_then(|bytes| records::parse(&bytes).map_err(|e| e.to_string()))
    {
        Ok(records) => records,
        Err(e) => {
            let _ = writeln!(env.err, "qg-trust: {}: {e}", input.display());
            return Exit::InputError;
        }
    };

    // Each QSO by its place in the log, from 1, as a message names it.
    let mut numbers = Vec::new();
    let mut qsos = Vec::new();
    let (mut refused, mut out_of_range) = (0usize, 0usize);
    for (i, record) in records.iter().enumerate() {
        match Qso::from_adif(record) {
            Ok(qso) => {
                let date = qso.date();
                if options.begin.is_some_and(|b| date < b) || options.end.is_some_and(|e| date > e)
                {
                    out_of_range += 1;
                    continue;
                }
                numbers.push(i + 1);
                qsos.push(qso);
            }
            Err(e) => {
                let _ = writeln!(
                    env.err,
                    "qg-trust: {} QSO {}: not signed: {e}",
                    input.display(),
                    i + 1
                );
                refused += 1;
            }
        }
    }
    if out_of_range > 0 {
        let _ = writeln!(
            env.err,
            "{}: {out_of_range} QSOs were outside the selected date range",
            input.display()
        );
    }

    // A QSO the certificate or station cannot sign is left out, said so, and the rest are signed.
    let signed = loop {
        if qsos.is_empty() {
            let _ = writeln!(env.err, "qg-trust: {}: no QSOs to sign", input.display());
            return Exit::NoQsos;
        }
        match sign_log(certificate, &key, station, &qsos, env.now) {
            Ok(signed) => break signed,
            Err(LogError::QsoOutsideCertificate { index }) => {
                let _ = writeln!(
                    env.err,
                    "qg-trust: {} QSO {}: not signed: outside the QSO dates {}'s certificate covers",
                    input.display(),
                    numbers[index],
                    entry.callsign
                );
                numbers.remove(index);
                qsos.remove(index);
                refused += 1;
            }
            Err(LogError::QsoFromAnotherStation {
                index,
                field,
                value,
            }) => {
                let _ = writeln!(
                    env.err,
                    "qg-trust: {} QSO {}: not signed: its {field} is {value:?}, not this station \
                     location's",
                    input.display(),
                    numbers[index]
                );
                numbers.remove(index);
                qsos.remove(index);
                refused += 1;
            }
            Err(e) => {
                let _ = writeln!(env.err, "qg-trust: {}: {e}", input.display());
                return Exit::TqslError;
            }
        }
    };

    let output = options
        .output
        .clone()
        .unwrap_or_else(|| input.with_extension("tq8"));
    if let Err(e) = write_whole(&output, &tq8(&signed)) {
        let _ = writeln!(env.err, "qg-trust: {}: {e}", output.display());
        return Exit::OutputError;
    }
    let _ = writeln!(
        env.err,
        "qg-trust: signed {} QSO{} for {name} into {}",
        qsos.len(),
        if qsos.len() == 1 { "" } else { "s" },
        output.display()
    );
    if refused > 0 || out_of_range > 0 {
        Exit::QsosSuppressed
    } else {
        Exit::Success
    }
}

/// The certificate to sign with: the station's call and entity, with its key, in force now. Of
/// several, the one in force longest, as a renewed certificate is.
fn certificate_for<'a>(
    certificates: &'a [BackedUpCertificate],
    call: &str,
    dxcc: u32,
    now: SystemTime,
) -> Option<&'a BackedUpCertificate> {
    certificates
        .iter()
        .filter(|c| c.callsign == call && c.dxcc == dxcc && c.key.is_some())
        .filter(|c| {
            c.certificate
                .as_ref()
                .is_some_and(|cert| cert.is_valid_at(now))
        })
        .max_by_key(|c| c.certificate.as_ref().map(|cert| cert.validity().1))
}

/// A file read whole, refused past `limit` before it is read.
fn read_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let len = std::fs::metadata(path)?.len();
    if usize::try_from(len).map_or(true, |l| l > limit) {
        return Err(io::Error::other("larger than any file qg-trust reads"));
    }
    std::fs::read(path)
}

/// `bytes` written to `path` whole or not at all: to a file beside it, then renamed over it.
fn write_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("not a file name"))?;
    let mut partial = name.to_os_string();
    partial.push(".partial");
    let partial = path.with_file_name(partial);
    let written = (|| {
        let mut file = std::fs::File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    match written.and_then(|()| std::fs::rename(&partial, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests;

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

use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anstyle::{AnsiColor, Style};
use clap::{CommandFactory, Parser, error::ErrorKind};
use clap_complete::Shell;
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
    /// Whether help, errors and messages use ANSI styling, decided by the caller.
    pub color: bool,
    /// Standard output: help, the version and shell completions.
    pub out: &'a mut dyn Write,
    /// Standard error: every message, and the final status line.
    pub err: &'a mut dyn Write,
}

const AFTER_HELP: &str = "\
The key's password is asked for when it is needed, with what you type hidden, or read as one line
from standard input when a logger runs qg-trust. The last line on standard error is
\"Final Status: <name>(<code>)\", as loggers expect.";

/// The option names and letters stay in step with TQSL so loggers can call either program.
#[derive(Debug, Parser)]
#[command(
    name = "qg-trust",
    version = VERSION,
    about = "Sign your ADIF log with your LoTW certificate for ARRL's Logbook of The World (LoTW).",
    after_help = AFTER_HELP,
    override_usage = "qg-trust -i <FILE> -l <NAME> [OPTIONS] <LOG.adi>\n       qg-trust --completions <SHELL>",
    disable_version_flag = true,
    disable_help_flag = true
)]
struct Options {
    /// The file with your certificate (the .tbk TQSL saves).
    #[arg(
        short = 'i',
        long = "import",
        value_name = "FILE",
        help_heading = "Signing",
        required_unless_present = "completions"
    )]
    backup: Option<PathBuf>,
    /// Your station location, by name.
    #[arg(
        short = 'l',
        long,
        value_name = "NAME",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        help_heading = "Signing",
        required_unless_present = "completions"
    )]
    location: Option<String>,
    /// Sign only QSOs on or after DATE (YYYY-MM-DD or YYYYMMDD).
    #[arg(short = 'b', long = "begindate", value_name = "DATE", help_heading = "Signing",
          value_parser = |s: &str| date(s, "start"))]
    begin: Option<Date>,
    /// Sign only QSOs on or before DATE (YYYY-MM-DD or YYYYMMDD).
    #[arg(short = 'e', long = "enddate", value_name = "DATE", help_heading = "Signing",
          value_parser = |s: &str| date(s, "end"))]
    end: Option<Date>,
    /// Where to write the signed log (default: LOG with .tq8).
    #[arg(short = 'o', long, value_name = "FILE", help_heading = "Signing")]
    output: Option<PathBuf>,
    /// The ADIF log to sign.
    #[arg(value_name = "LOG.adi", required_unless_present = "completions")]
    input: Option<PathBuf>,
    /// qg-trust always exits when done.
    #[arg(
        short = 'x',
        long,
        help_heading = "Accepted for loggers that pass them"
    )]
    batch: bool,
    /// The same as --batch.
    #[arg(
        short = 'q',
        long,
        help_heading = "Accepted for loggers that pass them"
    )]
    quiet: bool,
    /// Accepted and ignored.
    #[arg(
        short = 'd',
        long,
        help_heading = "Accepted for loggers that pass them"
    )]
    nodate: bool,
    /// Print the version.
    #[arg(short = 'v', long, action = clap::ArgAction::Version, help_heading = "Other")]
    version: Option<bool>,
    /// Write a shell completion script for qg-trust.
    #[arg(long, value_name = "SHELL", help_heading = "Other")]
    completions: Option<Shell>,
    /// Print this help.
    #[arg(short = 'h', long, action = clap::ArgAction::Help, help_heading = "Other")]
    help: Option<bool>,
}

/// Runs `qg-trust` with these arguments and returns its exit code.
pub(crate) fn run(args: &[String], env: &mut Env<'_>) -> u8 {
    let code = if let Some(message) = refused_option(args) {
        syntax_error(env, &message)
    } else {
        match Options::try_parse_from(
            std::iter::once("qg-trust").chain(args.iter().map(String::as_str)),
        ) {
            Ok(options) => {
                if let Some(shell) = options.completions {
                    // Completion scripts are source code, so they never receive styling.
                    // Written whole from a buffer: clap_complete panics on a failed write, and a
                    // reader that stops early (`| head`) is not a failure of qg-trust's.
                    let mut script = Vec::new();
                    clap_complete::generate(
                        shell,
                        &mut Options::command(),
                        "qg-trust",
                        &mut script,
                    );
                    let _ = env.out.write_all(&script);
                    return 0;
                }
                if let (Some(begin), Some(end)) = (options.begin, options.end)
                    && begin > end
                {
                    syntax_error(env, "the start date is after the end date")
                } else {
                    sign(&options, env)
                }
            }
            Err(error) => {
                let display = matches!(
                    error.kind(),
                    ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
                );
                let writer = if display { &mut env.out } else { &mut env.err };
                let rendered = error.render();
                if env.color {
                    let _ = write!(writer, "{}", rendered.ansi());
                } else {
                    let _ = write!(writer, "{rendered}");
                }
                if display {
                    return 0;
                }
                Exit::CommandError
            }
        }
    };
    let _ = writeln!(env.err, "Final Status: {}({})", code.name(), code as u8);
    code as u8
}

fn syntax_error(env: &mut Env<'_>, message: &str) -> Exit {
    env.message(
        Tone::Error,
        format_args!("{message}; qg-trust --help says how it is used"),
    );
    Exit::CommandError
}

/// Refuse unsupported TQSL options before clap can include a password in a diagnostic. Values
/// belong to the option before them, and `--` makes the remaining words file names.
fn refused_option(args: &[String]) -> Option<String> {
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        if arg.starts_with("--") {
            let (flag, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), false), |(f, _)| (f, true));
            if let Some(message) = refusal(flag) {
                return Some(message);
            }
            if !inline
                && matches!(
                    flag,
                    "--import"
                        | "--location"
                        | "--begindate"
                        | "--enddate"
                        | "--output"
                        | "--completions"
                )
                && rest
                    .clone()
                    .next()
                    .is_some_and(|value| !value.starts_with('-'))
            {
                // A following option is not a value in clap; it must still be checked.
                rest.next();
            }
        } else if let Some(shorts) = arg.strip_prefix('-') {
            for (index, short) in shorts.char_indices() {
                let flag = format!("-{short}");
                if let Some(message) = refusal(&flag) {
                    return Some(message);
                }
                if matches!(short, 'i' | 'l' | 'b' | 'e' | 'o') {
                    if index + short.len_utf8() == shorts.len()
                        && rest
                            .clone()
                            .next()
                            .is_some_and(|value| !value.starts_with('-'))
                    {
                        rest.next();
                    }
                    break;
                }
            }
        }
    }
    None
}

fn refusal(flag: &str) -> Option<String> {
    match flag {
        "-p" | "--password" => Some(
            "a password is never given on the command line: qg-trust asks for \
             the key's password when it needs it"
                .to_string(),
        ),
        "-a" | "--action" | "-c" | "--callsign" | "-f" | "--verify" | "-n" | "--updates" | "-s"
        | "--editlocation" | "-t" | "--diagnose" | "-u" | "--upload" | "-w" | "--wipe" | "-z"
        | "--test-sign" => Some(format!("{flag} is not supported yet")),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Tone {
    Error,
    Warning,
    Success,
}

impl Env<'_> {
    /// Keep the words identical for loggers, and reset styling before the final status line.
    fn message(&mut self, tone: Tone, message: fmt::Arguments<'_>) {
        if !self.color {
            let _ = writeln!(self.err, "qg-trust: {message}");
            return;
        }
        let program = Style::new().bold();
        let style = match tone {
            Tone::Error => AnsiColor::Red.on_default(),
            Tone::Warning => AnsiColor::Yellow.on_default(),
            Tone::Success => AnsiColor::Green.on_default(),
        };
        let _ = writeln!(
            self.err,
            "{program}qg-trust:{program:#} {style}{message}{style:#}"
        );
    }
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
                env.message(Tone::Error, format_args!("{}: {e}", backup_path.display()));
                return Exit::InputError;
            }
        },
        Err(e) => {
            env.message(Tone::Error, format_args!("{}: {e}", backup_path.display()));
            return Exit::InputError;
        }
    };
    let Some(location) = backup.locations.iter().find(|l| l.name == *name) else {
        let names: Vec<&str> = backup.locations.iter().map(|l| l.name.as_str()).collect();
        env.message(
            Tone::Error,
            format_args!(
                "there is no station location named {name:?}; there are: {}",
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            ),
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
        env.message(
            Tone::Error,
            format_args!(
                "there is no certificate for {} (DXCC {}) in force now, with its key",
                station.call(),
                station.dxcc()
            ),
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
                env.message(
                    Tone::Error,
                    format_args!("the password could not be read: {e}"),
                );
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
            env.message(
                Tone::Error,
                format_args!("that password does not unlock {}'s key", entry.callsign),
            );
            return Exit::BadPassphrase;
        }
        Err(e) => {
            env.message(Tone::Error, format_args!("{}'s key: {e}", entry.callsign));
            return Exit::TqslError;
        }
    };

    let records = match read_file(input, 64 * 1024 * 1024)
        .map_err(|e| e.to_string())
        .and_then(|bytes| records::parse(&bytes).map_err(|e| e.to_string()))
    {
        Ok(records) => records,
        Err(e) => {
            env.message(Tone::Error, format_args!("{}: {e}", input.display()));
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
                env.message(
                    Tone::Warning,
                    format_args!("{} QSO {}: not signed: {e}", input.display(), i + 1),
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
            env.message(
                Tone::Error,
                format_args!("{}: no QSOs to sign", input.display()),
            );
            return Exit::NoQsos;
        }
        match sign_log(certificate, &key, station, &qsos, env.now) {
            Ok(signed) => break signed,
            Err(LogError::QsoOutsideCertificate { index }) => {
                env.message(
                    Tone::Warning,
                    format_args!(
                        "{} QSO {}: not signed: outside the QSO dates {}'s certificate covers",
                        input.display(),
                        numbers[index],
                        entry.callsign
                    ),
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
                env.message(
                    Tone::Warning,
                    format_args!(
                        "{} QSO {}: not signed: its {field} is {value:?}, not this station \
                     location's",
                        input.display(),
                        numbers[index]
                    ),
                );
                numbers.remove(index);
                qsos.remove(index);
                refused += 1;
            }
            Err(e) => {
                env.message(Tone::Error, format_args!("{}: {e}", input.display()));
                return Exit::TqslError;
            }
        }
    };

    let output = options
        .output
        .clone()
        .unwrap_or_else(|| input.with_extension("tq8"));
    if let Err(e) = write_whole(&output, &tq8(&signed)) {
        env.message(Tone::Error, format_args!("{}: {e}", output.display()));
        return Exit::OutputError;
    }
    env.message(
        Tone::Success,
        format_args!(
            "signed {} QSO{} for {name} into {}",
            qsos.len(),
            if qsos.len() == 1 { "" } else { "s" },
            output.display()
        ),
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

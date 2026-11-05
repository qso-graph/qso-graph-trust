// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! What `qg-trust` does with its arguments. Everything outside the program, the root it trusts, the
//! time, how a password is asked for and where messages go, comes in through [`Env`], so the tests
//! run the real path against the standard test set.
//!
//! The options are TQSL 2.8.7's where they mean the same (`apps/tqsl.cpp`, `cmdLineDesc`), and so
//! are the exit codes (`apps/tqslapp.h`) and the last line, `Final Status: <name>(<code>)`, which
//! TQSL writes to standard error and loggers read. Without `-i`, keys and locations come from QG
//! Trust's store ([`crate::commands`]), as TQSL's come from its own. `-i` differs: TQSL imports a
//! file into its store, and `qg-trust` reads the TQSL backup it names for this run only.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anstyle::{AnsiColor, Style};
use clap::{CommandFactory, FromArgMatches, Parser, error::ErrorKind};
use clap_complete::Shell;
use qso_graph_trust::certificate::Trust;
use qso_graph_trust::qso::{Date, Qso};
use qso_graph_trust::signed_log::{LogError, sign_log, tq8};
use qso_graph_trust::signing::KeyError;
use qso_graph_trust::store::{Store, StoreError};
use qso_graph_trust::tbk::{self, BackedUpCertificate};
use qso_graph_trust::upload::UploadRequest;
use qso_graph_trust::{VERSION, records};
use zeroize::Zeroizing;

/// TQSL's exit codes, by the names TQSL gives them (`apps/tqslapp.h`, `apps/tqsl.cpp` `exitNow`).
/// TQSL's library error (5), unknown (12) and busy (13) are not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Exit {
    Success = 0,
    Cancel = 1,
    Rejected = 2,
    UnexpectedResponse = 3,
    TqslError = 4,
    InputError = 6,
    OutputError = 7,
    NoQsos = 8,
    QsosSuppressed = 9,
    CommandError = 10,
    ConnectionFailed = 11,
    UploadedAlready = 14,
    BadPassphrase = 15,
}

impl Exit {
    /// The name TQSL prints in its final status line.
    fn name(self) -> &'static str {
        match self {
            Exit::Success => "Success",
            Exit::Cancel => "User Cancelled",
            Exit::Rejected => "Upload Rejected",
            Exit::UnexpectedResponse => "Unexpected LoTW Response",
            Exit::TqslError => "TQSL Error",
            Exit::InputError => "Error opening input file",
            Exit::OutputError => "Error opening output file",
            Exit::NoQsos => "No QSOs to upload",
            Exit::QsosSuppressed => "Some QSOs not processed",
            Exit::CommandError => "Command Syntax Error",
            Exit::ConnectionFailed => "LoTW Connection Failed",
            Exit::UploadedAlready => "Previously signed QSOs were detected",
            Exit::BadPassphrase => "Incorrect passphrase when importing P12 file",
        }
    }
}

/// Sends an upload and returns LoTW's HTTP status and answer, or why none came.
pub(crate) type Upload<'a> =
    dyn FnMut(&UploadRequest) -> Result<(u16, Vec<u8>), UploadFailure> + 'a;

/// Why no answer came from LoTW, and whether the log may have reached it anyway.
#[derive(Debug)]
pub(crate) struct UploadFailure {
    /// What went wrong, in words; never the request.
    pub message: String,
    /// False only when the log cannot have been sent: no connection, or a certificate refused.
    pub maybe_sent: bool,
}

/// What the program gives `run`.
pub(crate) struct Env<'a> {
    /// The roots a backup's certificates must chain to: LoTW's, outside the tests.
    pub trust: &'a Trust,
    /// Now, for which certificates are in force.
    pub now: SystemTime,
    /// Asks for a key's password, given the prompt.
    pub ask_password: &'a mut dyn FnMut(&str) -> io::Result<Zeroizing<Vec<u8>>>,
    /// Whether help and the version use ANSI styling, decided for standard output.
    pub color_out: bool,
    /// Whether messages use ANSI styling, decided for standard error.
    pub color_err: bool,
    /// Standard output: help, the version and shell completions.
    pub out: &'a mut dyn Write,
    /// Standard error: every message, and the final status line.
    pub err: &'a mut dyn Write,
    /// QG Trust's store, opened the first time a command needs it.
    pub store: &'a dyn Fn() -> Result<&'a Store, StoreError>,
    /// Sends an upload to LoTW over verified TLS: the HTTP status and the body, bounded to
    /// `upload::MAX_RESPONSE_BYTES`, or why no answer came.
    pub upload: &'a mut Upload<'a>,
}

const AFTER_HELP: &str = "\
Commands:
  qg-trust import FILE      certificates, keys and locations from TQSL (.tbk), ARRL (.tq6) or a .p12
  qg-trust cert list        your certificates; cert request, renew, delete
  qg-trust location list    your station locations; location add, edit, delete
  qg-trust sign LOG -l NAME sign a log;  qg-trust send LOG -l NAME  signs and uploads it
  qg-trust upload LOG.tq8   upload a signed log
qg-trust <command> --help says more, with an example.

The options above are TQSL's, for loggers: without -i, keys and locations come from the store.
With -i, the key's password is asked for when it is needed, with what you type hidden, or read as one line
from standard input when a logger runs qg-trust. The last line on standard error is
\"Final Status: <name>(<code>)\", as loggers expect.";

/// The option names and letters stay in step with TQSL so loggers can call either program.
#[derive(Debug, Parser)]
#[command(
    name = "qg-trust",
    version = VERSION,
    about = "Sign your log for ARRL's Logbook of The World (LoTW) and upload it, with your key kept in \
             your computer's credential store.",
    after_help = AFTER_HELP,
    override_usage = "qg-trust <COMMAND> [ARGS]     (import, cert, location, sign, send, upload: below)\n       \
                      qg-trust -l <NAME> [OPTIONS] <LOG.adi>     (as loggers call tqsl)\n       \
                      qg-trust --completions <SHELL>",
    disable_version_flag = true,
    disable_help_flag = true,
    args_override_self = true
)]
struct Options {
    /// The file with your certificate (the .tbk TQSL saves).
    #[arg(
        short = 'i',
        long = "import",
        value_name = "FILE",
        allow_hyphen_values = true,
        help_heading = "Signing"
    )]
    backup: Option<PathBuf>,
    /// Your station location, by name.
    #[arg(
        short = 'l',
        long,
        value_name = "NAME",
        allow_hyphen_values = true,
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        help_heading = "Signing"
    )]
    location: Option<String>,
    /// Sign only QSOs on or after DATE (YYYY-MM-DD or YYYYMMDD).
    #[arg(short = 'b', long = "begindate", value_name = "DATE", help_heading = "Signing",
          allow_hyphen_values = true, value_parser = date)]
    begin: Option<Date>,
    /// Sign only QSOs on or before DATE (YYYY-MM-DD or YYYYMMDD).
    #[arg(short = 'e', long = "enddate", value_name = "DATE", help_heading = "Signing",
          allow_hyphen_values = true, value_parser = date)]
    end: Option<Date>,
    /// Where to write the signed log (default: LOG with .tq8).
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        allow_hyphen_values = true,
        help_heading = "Signing"
    )]
    output: Option<PathBuf>,
    /// The ADIF log to sign.
    #[arg(value_name = "LOG.adi")]
    input: Option<PathBuf>,
    /// Upload the signed log to LoTW.
    #[arg(short = 'u', long, help_heading = "Signing")]
    upload: bool,
    /// What to do with QSOs signed before: abort, compliant (sign only new ones), all, or ask
    /// (refused with code 14, as qg-trust cannot ask).
    #[arg(
        short = 'a',
        long,
        value_name = "ACTION",
        value_enum,
        ignore_case = true,
        help_heading = "Signing"
    )]
    action: Option<Action>,
    /// The log's own location details (its MY_ fields): ignore them, report a QSO that disagrees
    /// (TQSL's default) or update the location from them. With keys in the store (no -i).
    #[arg(
        short = 'f',
        long,
        value_name = "HOW",
        value_enum,
        ignore_case = true,
        help_heading = "Signing"
    )]
    verify: Option<Verify>,
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
    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue, help_heading = "Other")]
    version: bool,
    /// Write a shell completion script for qg-trust.
    #[arg(long, value_name = "SHELL", help_heading = "Other")]
    completions: Option<Shell>,
    /// Print this help.
    #[arg(short = 'h', long, action = clap::ArgAction::SetTrue, help_heading = "Other")]
    help: bool,
    #[command(flatten)]
    rejected: Rejected,
}

/// TQSL's `-a`: what to do with QSOs signed before (`apps/tqsl.cpp`, `TQSL_ACTION_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Action {
    /// Sign nothing if any QSO was signed before.
    Abort,
    /// Sign only the new QSOs.
    Compliant,
    /// Sign every QSO, again if need be.
    All,
    /// Ask: qg-trust cannot, so it stops with TQSL's code 14.
    Ask,
}

/// TQSL's `-f`: what the log's own location details do (`TQSL_LOC_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Verify {
    /// Not looked at.
    Ignore,
    /// A QSO that disagrees with the location is refused.
    Report,
    /// The log's details take the place of the location's.
    Update,
}

/// These options are recognized only to explain why qg-trust refuses them. Their values are
/// never used in a diagnostic, even when another argument prevents a successful parse.
/// An omitted value gets an empty default so clap records its index for ordering refusals.
#[derive(Debug, clap::Args)]
struct Rejected {
    #[arg(short = 'p', long = "password", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    password: Option<Option<String>>,
    #[arg(short = 'c', long = "callsign", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    callsign: Option<Option<String>>,
    #[arg(short = 'n', long = "updates", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    updates: Option<Option<String>>,
    #[arg(short = 's', long = "editlocation", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    editlocation: Option<Option<String>>,
    #[arg(short = 't', long = "diagnose", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    diagnose: Option<Option<String>>,
    #[arg(short = 'w', long = "wipe", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    wipe: Option<Option<String>>,
    #[arg(short = 'z', long = "test-sign", hide = true, num_args = 0..=1, default_missing_value = "", allow_hyphen_values = true)]
    test_sign: Option<Option<String>>,
}

const PASSWORD_MESSAGE: &str = "a password is never given on the command line: qg-trust asks for \
    the key's password when it needs it";

// Only these literals can become a refusal message, never a slice of an argument.
const REJECTED_MESSAGES: &[(char, &str, &str, &str)] = &[
    ('p', "--password", PASSWORD_MESSAGE, PASSWORD_MESSAGE),
    (
        'c',
        "--callsign",
        "-c is not supported yet",
        "--callsign is not supported yet",
    ),
    (
        'n',
        "--updates",
        "-n is not supported yet",
        "--updates is not supported yet",
    ),
    (
        's',
        "--editlocation",
        "-s is not supported yet",
        "--editlocation is not supported yet",
    ),
    (
        't',
        "--diagnose",
        "-t is not supported yet",
        "--diagnose is not supported yet",
    ),
    (
        'w',
        "--wipe",
        "-w is not supported yet",
        "--wipe is not supported yet",
    ),
    (
        'z',
        "--test-sign",
        "-z is not supported yet",
        "--test-sign is not supported yet",
    ),
];

/// Runs `qg-trust` with OS arguments so invalid text cannot panic before the final status line.
pub(crate) fn run(args: &[OsString], env: &mut Env<'_>) -> u8 {
    if let Some(first) = args.first().and_then(|a| a.to_str())
        && crate::commands::COMMANDS.contains(&first)
    {
        return match args.iter().map(|a| a.to_str()).collect::<Option<Vec<_>>>() {
            Some(args) => crate::commands::run(&args, env),
            None => {
                env.message(Tone::Error, format_args!("an argument is not valid text"));
                Exit::CommandError as u8
            }
        };
    }
    let code = match args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    {
        Some(args) => match execute(&args, env) {
            Some(code) => code,
            None => return 0,
        },
        None => syntax_error(env, "an argument is not valid text"),
    };
    let _ = writeln!(env.err, "Final Status: {}({})", code.name(), code as u8);
    code as u8
}

/// None means informational output, which has no final status line.
fn execute(args: &[&str], env: &mut Env<'_>) -> Option<Exit> {
    let mut command = Options::command();
    let matches = match command
        .try_get_matches_from_mut(std::iter::once("qg-trust").chain(args.iter().copied()))
    {
        Ok(matches) => matches,
        Err(error) => {
            // Clap's diagnostics, suggestions and parser sources may contain any user value.
            // Render none of them; even an unrecognized error kind gets only our fixed text.
            return Some(syntax_error(
                env,
                rejected_message(args).unwrap_or_else(|| parse_error_message(&error)),
            ));
        }
    };

    // Clap's indices respect values consumed by an option and letters in a short-option group.
    // Defaults have indices too, so only command-line occurrences take part in the ordering.
    // A refused option anywhere on the line is refused before help or the version is shown: a
    // repeated option keeps only its last occurrence's index, so an order-based rule would let
    // `-p SECRET --version -p SECRET2` print the version (found in review).
    let given = |arg: &&clap::Arg| {
        matches.value_source(arg.get_id().as_str()) == Some(clap::parser::ValueSource::CommandLine)
    };
    let earliest = |wanted: &dyn Fn(&clap::Arg) -> bool| {
        command
            .get_arguments()
            .filter(|arg| wanted(arg))
            .filter(given)
            .filter_map(|arg| {
                matches
                    .index_of(arg.get_id().as_str())
                    .map(|index| (index, arg))
            })
            .min_by_key(|(index, _)| *index)
    };
    let first = earliest(&|arg| arg.is_hide_set())
        .or_else(|| earliest(&|arg| matches!(arg.get_id().as_str(), "help" | "version")));
    if let Some((_, arg)) = first {
        match arg.get_id().as_str() {
            "help" => {
                let rendered = command.render_help();
                if env.color_out {
                    let _ = write!(env.out, "{}", rendered.ansi());
                } else {
                    let _ = write!(env.out, "{rendered}");
                }
                return None;
            }
            "version" => {
                let _ = writeln!(env.out, "qg-trust {VERSION}");
                return None;
            }
            _ => {
                let message = REJECTED_MESSAGES
                    .iter()
                    .find_map(|option| {
                        (arg.get_short() == Some(option.0)).then(|| {
                            if args.iter().any(|arg| {
                                arg.split_once('=').map_or(*arg, |(name, _)| name) == option.1
                            }) {
                                option.3
                            } else {
                                option.2
                            }
                        })
                    })
                    .expect("a hidden option has a fixed refusal");
                return Some(syntax_error(env, message));
            }
        }
    }
    // Keep clap's matches so control options can be ordered before the derive API builds Options.
    let options = match Options::from_arg_matches(&matches) {
        Ok(options) => options,
        Err(error) => return Some(syntax_error(env, parse_error_message(&error))),
    };
    if let Some(shell) = options.completions {
        // Completion scripts are source code, so they never receive styling.
        // Written whole from a buffer: clap_complete panics on a failed write, and a
        // reader that stops early (`| head`) is not a failure of qg-trust's.
        let mut script = Vec::new();
        clap_complete::generate(shell, &mut Options::command(), "qg-trust", &mut script);
        let _ = env.out.write_all(&script);
        return None;
    }
    let missing = if options.input.is_none() {
        Some("give the log to sign")
    } else if options.location.is_none() {
        Some("-l names the station location to sign for")
    } else {
        None
    };
    if let Some(message) = missing {
        return Some(syntax_error(env, message));
    }
    if let (Some(begin), Some(end)) = (options.begin, options.end)
        && begin > end
    {
        Some(syntax_error(env, "the start date is after the end date"))
    } else if options.backup.is_none() {
        Some(crate::commands::sign_for_logger(
            &crate::commands::LoggerCall {
                log: options.input.as_deref().unwrap_or(Path::new("")),
                location: options.location.as_deref().unwrap_or(""),
                begin: options.begin,
                end: options.end,
                output: options.output.as_deref(),
                action: options.action,
                verify: options.verify,
                upload: options.upload,
            },
            env,
        ))
    } else if options.action.is_some_and(|a| a != Action::All) {
        Some(syntax_error(
            env,
            "-a abort, compliant and ask need the record of QSOs signed before, which is in the \
             store: qg-trust import the backup, then leave out -i",
        ))
    } else if options.verify.is_some_and(|v| v != Verify::Report) {
        Some(syntax_error(
            env,
            "-f ignore and -f update sign from the store: qg-trust import the backup, then leave out -i",
        ))
    } else {
        let code = sign(&options, env);
        if options.upload && matches!(code, Exit::Success | Exit::QsosSuppressed) {
            let output = options.output.clone().unwrap_or_else(|| {
                options
                    .input
                    .as_deref()
                    .unwrap_or(Path::new(""))
                    .with_extension("tq8")
            });
            match crate::commands::upload_file(&output, env) {
                Ok(_) => Some(code),
                Err(e) => Some(e),
            }
        } else {
            Some(code)
        }
    }
}

fn syntax_error(env: &mut Env<'_>, message: &str) -> Exit {
    env.message(
        Tone::Error,
        format_args!("{message}; qg-trust --help says how it is used"),
    );
    Exit::CommandError
}

/// Select a fixed refusal even if clap could not build Options. This does not parse values or
/// decide acceptance: clap does that. Exact names and short letters only select our own literals.
fn rejected_message(args: &[&str]) -> Option<&'static str> {
    for arg in args {
        let name = arg.split_once('=').map_or(*arg, |(name, _)| name);
        for &(_, long, _, long_message) in REJECTED_MESSAGES {
            if name == long {
                return Some(long_message);
            }
        }
        if let Some(letters) = arg.strip_prefix('-').filter(|s| !s.starts_with('-')) {
            for letter in letters.chars() {
                if let Some(option) = REJECTED_MESSAGES.iter().find(|option| option.0 == letter) {
                    return Some(option.2);
                }
                if matches!(letter, 'i' | 'l' | 'b' | 'e' | 'o') {
                    break;
                }
            }
        }
    }
    None
}

fn parse_error_message(error: &clap::Error) -> &'static str {
    use clap::error::{ContextKind, ContextValue};

    // Match complete, known option names. Never interpolate clap's context into output.
    let option = match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(option)) => option.as_str(),
        _ => "",
    };
    match error.kind() {
        ErrorKind::UnknownArgument => "an option qg-trust does not know was given",
        ErrorKind::InvalidValue | ErrorKind::ValueValidation | ErrorKind::TooFewValues => {
            match option {
                "--begindate <DATE>" => "--begindate needs a date (YYYY-MM-DD or YYYYMMDD)",
                "--enddate <DATE>" => "--enddate needs a date (YYYY-MM-DD or YYYYMMDD)",
                "--import <FILE>" => "-i names the file with your certificate",
                "--location <NAME>" => "-l names the station location to sign for",
                "--output <FILE>" => "-o names the file for the signed log",
                "--action <ACTION>" => "-a takes abort, compliant, all or ask",
                "--verify <HOW>" => "-f takes ignore, report or update",
                "--completions <SHELL>" => {
                    "--completions takes bash, zsh, fish, powershell or elvish"
                }
                _ => "an option needs a valid value",
            }
        }
        ErrorKind::MissingRequiredArgument => {
            "give the log to sign and -l with your station location"
        }
        _ => "the command line is not valid",
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Error,
    Warning,
    Success,
}

impl Env<'_> {
    /// Keep the words identical for loggers, and reset styling before the final status line.
    pub(crate) fn message(&mut self, tone: Tone, message: fmt::Arguments<'_>) {
        if !self.color_err {
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
fn date(text: &str) -> Result<Date, &'static str> {
    Date::from_iso(text)
        .or_else(|| Date::from_adif(text))
        .ok_or("a date must be YYYY-MM-DD or YYYYMMDD")
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
                env.message(Tone::Error, format_args!("the certificate file (-i): {e}"));
                return Exit::InputError;
            }
        },
        Err(e) => {
            env.message(Tone::Error, format_args!("the certificate file (-i): {e}"));
            return Exit::InputError;
        }
    };
    let Some(location) = backup.locations.iter().find(|l| l.name == *name) else {
        let names: Vec<&str> = backup.locations.iter().map(|l| l.name.as_str()).collect();
        env.message(
            Tone::Error,
            format_args!(
                "the station location given to -l is not in the certificate file; there are: {}",
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
            env.message(Tone::Error, format_args!("the log: {e}"));
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
                    format_args!("the log's QSO {}: not signed: {e}", i + 1),
                );
                refused += 1;
            }
        }
    }
    if out_of_range > 0 {
        let _ = writeln!(
            env.err,
            "the log: {out_of_range} QSOs were outside the selected date range"
        );
    }

    // A QSO the certificate or station cannot sign is left out, said so, and the rest are signed.
    let signed = loop {
        if qsos.is_empty() {
            env.message(Tone::Error, format_args!("the log: no QSOs to sign"));
            return Exit::NoQsos;
        }
        match sign_log(certificate, &key, station, &qsos, env.now) {
            Ok(signed) => break signed,
            Err(LogError::QsoOutsideCertificate { index }) => {
                env.message(
                    Tone::Warning,
                    format_args!(
                        "the log's QSO {}: not signed: outside the QSO dates {}'s certificate covers",
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
                        "the log's QSO {}: not signed: its {field} is {value:?}, not this station \
                     location's",
                        numbers[index]
                    ),
                );
                numbers.remove(index);
                qsos.remove(index);
                refused += 1;
            }
            Err(e) => {
                env.message(Tone::Error, format_args!("the log: {e}"));
                return Exit::TqslError;
            }
        }
    };

    let output = options
        .output
        .clone()
        .unwrap_or_else(|| input.with_extension("tq8"));
    if let Err(e) = write_whole(&output, &tq8(&signed)) {
        env.message(Tone::Error, format_args!("the output file (-o): {e}"));
        return Exit::OutputError;
    }
    env.message(
        Tone::Success,
        format_args!(
            "signed {} QSO{} for {}",
            qsos.len(),
            if qsos.len() == 1 { "" } else { "s" },
            entry.callsign
        ),
    );
    if options.output.is_none() {
        let _ = writeln!(env.err, "written beside the log, with .tq8");
    }
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
pub(crate) fn read_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let len = std::fs::metadata(path)?.len();
    if usize::try_from(len).map_or(true, |l| l > limit) {
        return Err(io::Error::other("larger than any file qg-trust reads"));
    }
    std::fs::read(path)
}

/// `bytes` written to `path` whole or not at all: to a file beside it, then renamed over it.
/// The temporary file is new, made with a name of its own (never an existing file or a link
/// followed), so nothing but `path` is ever replaced.
pub(crate) fn write_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let partial = new_partial(path)?;
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
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

/// A name beside `path` for a temporary file, `.NAME.<pid>-<n>.partial`, not yet taken.
pub(crate) fn new_partial(path: &Path) -> io::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("not a file name"))?;
    let mut partial = std::ffi::OsString::from(".");
    partial.push(name);
    partial.push(format!(
        ".{}-{}.partial",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(path.with_file_name(partial))
}

#[cfg(test)]
mod tests;

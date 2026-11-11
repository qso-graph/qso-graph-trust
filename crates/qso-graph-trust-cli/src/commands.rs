// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! `qg-trust`'s commands for people: `sign`, `upload`, `send`, `import`, `cert …`, `location …` and
//! `root …`,
//! working on QG Trust's own store, with keys in the OS credential store. The same store
//! QSO Graph Desktop uses, so a ham sees one set of certificates and locations in both.
//!
//! These commands use TQSL's exit codes but write no `Final Status` line: that line is for loggers,
//! which call the TQSL-style options ([`crate::cli`]).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use qso_graph_trust::certificate::{Certificate, Trust};
use qso_graph_trust::import::ImportError;
use qso_graph_trust::options::{QthHandling, SigningOptions};
use qso_graph_trust::qso::{Date, Qso};
use qso_graph_trust::request::{Authorization, CallKind, CertificateRequest};
use qso_graph_trust::signed_log::LogError;
use qso_graph_trust::station::{self, StationLocation};
use qso_graph_trust::store::{
    DuplicateChoice, ImportChoices, ImportDisposition, RootKind, RootSource, Store, StoreError,
    StoredCertificate, TrustedRoot,
};
use qso_graph_trust::upload::{UploadOutcome, UploadRequest};
use qso_graph_trust::{VERSION, records, tbk, tqsl_locations};

use crate::cli::{Action, Env, Exit, LeftOut, Tone, UploadFailure, Verify, read_file};

/// The words that start a command. Anything else is the TQSL-style command line loggers use.
pub(crate) const COMMANDS: &[&str] = &[
    "sign", "upload", "send", "import", "cert", "location", "root", "signed",
];

/// The largest log or signed log read.
const MAX_LOG_LEN: usize = 64 * 1024 * 1024;

const EXAMPLES: &str = "\
Examples:
  qg-trust import ~/Documents/tqsl-backup.tbk     your certificates, keys and locations, from TQSL
  qg-trust cert list                              what you have, and when each certificate expires
  qg-trust location list                          your station locations
  qg-trust root list                              the LoTW roots your certificates chain to
  qg-trust sign log.adi -l Home                   sign log.adi into log.tq8
  qg-trust send log.adi -l Home                   sign it and upload it to LoTW
  qg-trust upload log.tq8                         upload a log already signed

Each command has its own help: qg-trust sign --help.
Keys stay in your computer's credential store. A password is asked for when one is needed, and
never taken from the command line.";

#[derive(Debug, Parser)]
#[command(
    name = "qg-trust",
    version = VERSION,
    about = "Sign your log for ARRL's Logbook of The World (LoTW) and upload it, with your key kept in \
             your computer's credential store.",
    after_help = EXAMPLES,
    disable_help_subcommand = true,
    subcommand_required = true
)]
struct People {
    #[command(subcommand)]
    command: Command,
}

/// Whether QSOs signed before are signed again. A logger's -a decides as TQSL does; otherwise
/// every QSO is signed unless -d asks to leave those out.
fn signs_again(a: &SignArgs) -> bool {
    match a.action {
        Some(action) => action == Action::All,
        None => a.again || !a.dedupe,
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Sign an ADIF or Cabrillo log for a station location, into a .tq8 for LoTW.
    #[command(
        after_help = "Example:\n  qg-trust sign log.adi -l Home -b 2026-01-01\n\n\
        Every QSO in the log is signed, as it is, including any signed before; -d leaves those \
        out. A QSO LoTW would refuse is named, with the reason, and the rest are signed."
    )]
    Sign(SignArgs),
    /// Upload a signed log (.tq8) to LoTW.
    #[command(after_help = "Example:\n  qg-trust upload log.tq8")]
    Upload(UploadArgs),
    /// Sign an ADIF or Cabrillo log and upload it to LoTW, in one step.
    #[command(after_help = "Example:\n  qg-trust send log.adi -l Home\n\n\
        The signed log is kept beside the log, with .tq8, in case the upload has to be tried again.")]
    Send(SignArgs),
    /// Import certificates, keys and station locations: a TQSL backup (.tbk), ARRL's answer to a
    /// request (.tq6) or a certificate with its key (.p12).
    #[command(
        after_help = "Examples:\n  qg-trust import tqsl-backup.tbk\n  qg-trust import KI7MT.tq6\n  \
        qg-trust import KI7MT.p12\n  qg-trust import KI7MT.tq6 --trust-root 1A:2B:3C:4D:...:9F\n\n\
        When ARRL starts issuing under a new root, its .tq6 brings the root with it, and qg-trust \
        names the root and its SHA-256 fingerprint before trusting it; run again with --trust-root \
        and that fingerprint once you know it is ARRL's. A new root in your own .tbk backup is \
        trusted, and named."
    )]
    Import(ImportArgs),
    /// Your callsign certificates: list, request, renew, delete.
    #[command(subcommand)]
    Cert(Cert),
    /// Your station locations: list, show, add, edit, delete.
    #[command(subcommand)]
    Location(Location),
    /// Manage the record of QSOs signed before.
    #[command(subcommand)]
    Signed(SignedCommand),
    /// The LoTW roots and CAs QG Trust trusts: list, remove.
    #[command(subcommand)]
    Root(Root),
}

#[derive(Debug, Subcommand)]
enum SignedCommand {
    /// Clear the record of QSOs signed before.
    Clear {
        /// Clear without asking, for scripts.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum Root {
    /// List the roots and CAs your certificates must chain to: LoTW's, built in, and any you
    /// accepted.
    #[command(after_help = "Example:\n  qg-trust root list --json")]
    List(ListArgs),
    /// Stop trusting a root you accepted, by its SHA-256 fingerprint; LoTW's built-in ones stay.
    #[command(after_help = "Example:\n  qg-trust root remove 1A:2B:3C:4D:...:9F\n\n\
        qg-trust root list shows each root's fingerprint.")]
    Remove(RootRemoveArgs),
}

#[derive(Debug, Args)]
struct RootRemoveArgs {
    /// The root's SHA-256 fingerprint, from qg-trust root list.
    #[arg(value_name = "FINGERPRINT", value_parser = fingerprint)]
    fingerprint: String,
}

#[derive(Debug, Args)]
struct SignArgs {
    /// The ADIF or Cabrillo log (.adi, .adx, or .log).
    #[arg(value_name = "LOG.adi|adx|log")]
    log: PathBuf,
    /// The station location to sign for, by name (qg-trust location list).
    #[arg(short = 'l', long, value_name = "NAME")]
    location: Option<String>,
    /// Sign only QSOs on or after DATE (YYYY-MM-DD or YYYYMMDD).
    #[arg(short = 'b', long = "from", value_name = "DATE", value_parser = date)]
    begin: Option<Date>,
    /// Sign only QSOs on or before DATE (YYYY-MM-DD or YYYYMMDD).
    #[arg(short = 'e', long = "to", value_name = "DATE", value_parser = date)]
    end: Option<Date>,
    /// Where to write the signed log (default: the log's name with .tq8).
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Leave out QSOs signed before. Without it, every QSO in the log is signed as it is: LoTW
    /// takes a QSO it already has without harm, and a contest log's repeat contacts are QSOs.
    #[arg(short = 'd', long)]
    dedupe: bool,
    /// What every run does now; kept so scripts written for 0.1 still run.
    #[arg(long, hide = true, conflicts_with = "dedupe")]
    again: bool,
    /// The certificate to sign with, by ID (qg-trust cert list), when you have more than one in
    /// force for the call; otherwise the one covering most of the log's QSOs.
    #[arg(long, value_name = "ID")]
    cert: Option<String>,
    /// Replace the signed log if it is there already.
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    options: OptionArgs,
    /// What a logger asked for with -a; people use --again.
    #[arg(skip)]
    action: Option<Action>,
    /// A logger's -c: the call to sign as, in place of the location's, for this run only.
    #[arg(skip)]
    callsign: Option<String>,
}

/// TQSL's settings that change what is signed, each off by default as in TQSL.
#[derive(Debug, Args)]
#[command(next_help_heading = "Signing settings")]
struct OptionArgs {
    /// Sign QSO times without their seconds.
    #[arg(long)]
    ignore_seconds: bool,
    /// Sign QSOs whose call does not look like an amateur call.
    #[arg(long)]
    allow_bad_calls: bool,
    /// Don't check the log's STATION_CALLSIGN and OPERATOR against the certificate.
    #[arg(long)]
    ignore_log_callsigns: bool,
    /// What the log's own MY_ fields do: refuse a QSO that disagrees (the default), ignore them,
    /// or take them in place of the location's.
    #[arg(long, value_enum, value_name = "HOW", default_value_t = Qth::Refuse)]
    qth: Qth,
    /// Sign an ADIF mode as a LoTW mode (repeatable).
    #[arg(long = "mode", value_name = "ADIF=LOTW", value_parser = pair)]
    modes: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Qth {
    Refuse,
    Ignore,
    FromLog,
}

#[derive(Debug, Args)]
struct UploadArgs {
    /// The signed log.
    #[arg(value_name = "LOG.tq8")]
    signed: PathBuf,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// The files to import: .tbk, .tq6 or .p12.
    #[arg(value_name = "FILE", required = true)]
    files: Vec<PathBuf>,
    /// Trust the root a .tq6 or .p12 brings, which qg-trust named when it refused it, by its
    /// SHA-256 fingerprint.
    #[arg(long, value_name = "FINGERPRINT", value_parser = fingerprint)]
    trust_root: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Cert {
    /// List your certificates and requests waiting for ARRL.
    #[command(after_help = "Example:\n  qg-trust cert list --json")]
    List(ListArgs),
    /// Request a certificate for a call (a .tq5 to send to ARRL).
    #[command(
        after_help = "Example:\n  qg-trust cert request --call KI7MT --dxcc 291 --from 2001-01-01 \\\n    \
        --name 'Greg Beam' --address '1 Main St' --city Boise --state ID --postcode 83702 \\\n    \
        --country USA --email ki7mt@example.org -o KI7MT.tq5\n\n\
        Upload the .tq5 at https://lotw.arrl.org/lotw/load-cert, then import the .tq6 ARRL sends back."
    )]
    Request(RequestArgs),
    /// Renew a certificate, with a new key (a .tq5 to send to ARRL).
    #[command(
        after_help = "Example:\n  qg-trust cert renew KI7MT --name 'Greg Beam' --address '1 Main St' \\\n    \
        --city Boise --state ID --postcode 83702 --country USA --email ki7mt@example.org -o KI7MT.tq5"
    )]
    Renew(RenewArgs),
    /// Delete a certificate and its key.
    #[command(after_help = "Example:\n  qg-trust cert delete 1a2b3c4d --force")]
    Delete(DeleteArgs),
    /// Give up a request waiting for ARRL, and delete its key.
    #[command(after_help = "Example:\n  qg-trust cert abandon 5e6f7a8b --force")]
    Abandon(DeleteArgs),
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Print JSON, for scripts.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DeleteArgs {
    /// Its ID, from the list.
    #[arg(value_name = "ID")]
    id: String,
    /// Delete it: this cannot be undone.
    #[arg(long)]
    force: bool,
}

/// Who you are, as ARRL's request asks.
#[derive(Debug, Args)]
#[command(next_help_heading = "You")]
struct Person {
    /// Your name.
    #[arg(long)]
    name: String,
    /// Your street address.
    #[arg(long)]
    address: String,
    /// A second address line.
    #[arg(long, default_value = "")]
    address2: String,
    /// Your city.
    #[arg(long)]
    city: String,
    /// Your state or province.
    #[arg(long, default_value = "")]
    state: String,
    /// Your postal code.
    #[arg(long, default_value = "")]
    postcode: String,
    /// Your country.
    #[arg(long)]
    country: String,
    /// Your email address: ARRL sends the certificate there.
    #[arg(long)]
    email: String,
}

#[derive(Debug, Args)]
struct RequestArgs {
    /// The call the certificate is for.
    #[arg(long)]
    call: String,
    /// Its DXCC entity, by ARRL's number (291 is the United States).
    #[arg(long)]
    dxcc: u32,
    /// The first QSO date it covers.
    #[arg(long = "from", value_name = "DATE", value_parser = date)]
    begin: Date,
    /// The last QSO date it covers, for a call no longer held.
    #[arg(long = "to", value_name = "DATE", value_parser = date)]
    end: Option<Date>,
    /// What kind of call it is.
    #[arg(long, value_enum, default_value_t = Kind::Personal)]
    kind: Kind,
    /// Sign the request with a certificate you have, by ID or call, as ARRL asks for another
    /// call of yours.
    #[arg(long, value_name = "CERT")]
    signed_by: Option<String>,
    /// Where to write the request.
    #[arg(short = 'o', long, value_name = "FILE.tq5")]
    output: PathBuf,
    /// Replace the file if it is there already.
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    person: Person,
}

#[derive(Debug, Args)]
struct RenewArgs {
    /// The certificate to renew, by ID or call.
    #[arg(value_name = "CERT")]
    cert: String,
    /// The last QSO date the new certificate covers (default: the one this certificate has).
    #[arg(long = "to", value_name = "DATE", value_parser = date, conflicts_with = "no_end_date")]
    end: Option<Date>,
    /// No last QSO date: a call you still hold.
    #[arg(long)]
    no_end_date: bool,
    /// Where to write the request.
    #[arg(short = 'o', long, value_name = "FILE.tq5")]
    output: PathBuf,
    /// Replace the file if it is there already.
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    person: Person,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Kind {
    Personal,
    Club,
    Dxpedition,
    SpecialEvent,
    Former,
    Replacing,
    QslManager,
}

#[derive(Debug, Subcommand)]
enum Location {
    /// Compare locations in TQSL and optionally add new ones.
    #[command(
        after_help = "Examples:\n  qg-trust location tqsl\n  qg-trust location tqsl --folder ~/Library/Application\\ Support/TrustedQSL\n  qg-trust location tqsl --add Home\n  qg-trust location tqsl --all"
    )]
    Tqsl(TqslLocationArgs),
    /// List your station locations.
    #[command(after_help = "Example:\n  qg-trust location list")]
    List(ListArgs),
    /// Set your default station location.
    #[command(after_help = "Example:\n  qg-trust location default Home")]
    Default(DefaultLocationArgs),
    /// Show one station location's fields.
    #[command(after_help = "Example:\n  qg-trust location show Home")]
    Show(ShowArgs),
    /// Add a station location.
    #[command(
        after_help = "Example:\n  qg-trust location add Home --call KI7MT --dxcc 291 --grid DN13 \\\n    \
        US_STATE=ID US_COUNTY=Ada CQZ=3 ITUZ=6\n\n\
        qg-trust location fields 291 lists the fields a DXCC entity's locations take."
    )]
    Add(AddArgs),
    /// Change fields of a station location; FIELD= removes one.
    #[command(after_help = "Example:\n  qg-trust location edit Home --grid DN14")]
    Edit(EditArgs),
    /// Delete a station location.
    #[command(after_help = "Example:\n  qg-trust location delete Portable --force")]
    Delete(LocationDeleteArgs),
    /// The fields a DXCC entity's station locations take.
    #[command(after_help = "Example:\n  qg-trust location fields 291")]
    Fields(FieldsArgs),
}

#[derive(Debug, Args)]
struct TqslLocationArgs {
    /// TQSL's folder, if different from the default.
    #[arg(long, value_name = "FOLDER")]
    folder: Option<PathBuf>,
    /// Print JSON, for scripts.
    #[arg(long)]
    json: bool,
    /// Add this new location by name; repeat to choose more.
    #[arg(long, value_name = "NAME", conflicts_with = "all")]
    add: Vec<String>,
    /// Add every new location.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct DefaultLocationArgs {
    /// The location's name.
    name: String,
}

#[derive(Debug, Args)]
struct ShowArgs {
    /// The location's name.
    name: String,
    /// Print JSON, for scripts.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AddArgs {
    /// The location's name.
    name: String,
    /// The station's call.
    #[arg(long)]
    call: String,
    /// The DXCC entity, by ARRL's number.
    #[arg(long)]
    dxcc: u32,
    /// The grid square, or two or four for a station on a boundary (EM17,EM18).
    #[arg(long)]
    grid: Option<String>,
    /// Other fields, as LoTW names them.
    #[arg(value_name = "FIELD=VALUE", value_parser = pair)]
    fields: Vec<(String, String)>,
}

#[derive(Debug, Args)]
struct EditArgs {
    /// The location's name.
    name: String,
    /// A new call.
    #[arg(long)]
    call: Option<String>,
    /// A new grid square.
    #[arg(long)]
    grid: Option<String>,
    /// Fields to change, as LoTW names them; FIELD= removes one.
    #[arg(value_name = "FIELD=VALUE", value_parser = pair_or_empty)]
    fields: Vec<(String, String)>,
}

#[derive(Debug, Args)]
struct LocationDeleteArgs {
    /// The location's name.
    name: String,
    /// Delete it: this cannot be undone.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct FieldsArgs {
    /// The DXCC entity, by ARRL's number.
    dxcc: u32,
}

fn date(text: &str) -> Result<Date, &'static str> {
    Date::from_iso(text)
        .or_else(|| Date::from_adif(text))
        .ok_or("a date must be YYYY-MM-DD or YYYYMMDD")
}

fn fingerprint(text: &str) -> Result<String, &'static str> {
    qso_graph_trust::certificate::parse_fingerprint(text)
        .ok_or("a SHA-256 fingerprint is 32 pairs of hexadecimal digits, as 0F:B9:62:...")
}

fn pair(text: &str) -> Result<(String, String), &'static str> {
    match pair_or_empty(text)? {
        (_, v) if v.is_empty() => Err("give a value after ="),
        p => Ok(p),
    }
}

fn pair_or_empty(text: &str) -> Result<(String, String), &'static str> {
    let (name, value) = text.split_once('=').ok_or("write it as NAME=VALUE")?;
    if name.is_empty() {
        return Err("write it as NAME=VALUE");
    }
    Ok((name.trim().to_string(), value.trim().to_string()))
}

/// Runs a command. Help and errors from parsing are clap's, which here may quote what was typed:
/// no command takes a password, so nothing secret can be on this command line.
pub(crate) fn run(args: &[&str], env: &mut Env<'_>) -> u8 {
    let mut command = People::command();
    let matches = match command
        .try_get_matches_from_mut(std::iter::once("qg-trust").chain(args.iter().copied()))
    {
        Ok(m) => m,
        Err(e) => {
            let rendered = if e.use_stderr() {
                if env.color_err {
                    e.render().ansi().to_string()
                } else {
                    e.render().to_string()
                }
            } else if env.color_out {
                e.render().ansi().to_string()
            } else {
                e.render().to_string()
            };
            if e.use_stderr() {
                let _ = write!(env.err, "{rendered}");
                return Exit::CommandError as u8;
            }
            let _ = write!(env.out, "{rendered}");
            return 0;
        }
    };
    let people = match People::from_arg_matches(&matches) {
        Ok(p) => p,
        Err(_) => return Exit::CommandError as u8,
    };
    let code = match people.command {
        Command::Sign(a) => sign(&a, env).map(|s| {
            if s.suppressed {
                Exit::QsosSuppressed
            } else {
                Exit::Success
            }
        }),
        Command::Send(a) => send(&a, env),
        Command::Upload(a) => upload_file(&a.signed, env),
        Command::Import(a) => import(&a, env),
        Command::Cert(c) => cert(c, env),
        Command::Location(l) => location(l, env),
        Command::Root(r) => root(r, env),
        Command::Signed(SignedCommand::Clear { yes }) => Ok(clear_signed(yes, env)),
    };
    match code {
        Ok(code) | Err(code) => code as u8,
    }
}

type Done = Result<Exit, Exit>;

fn open<'a>(env: &mut Env<'a>) -> Result<&'a Store, Exit> {
    match (env.store)() {
        Ok(store) => Ok(store),
        Err(e) => {
            env.trace.line(format_args!("Store: could not be opened"));
            env.message(
                Tone::Error,
                format_args!("QG Trust's store could not be opened: {e}"),
            );
            Err(Exit::TqslError)
        }
    }
}

pub(crate) fn clear_signed(yes: bool, env: &mut Env<'_>) -> Exit {
    if !yes {
        let _ = write!(
            env.out,
            "Do you really want to wipe the record of QSOs signed before? Enter APPROVE to allow: "
        );
        let _ = env.out.flush();
        if !(env.ask_password)("").is_ok_and(|answer| answer.as_slice() == b"APPROVE") {
            let _ = writeln!(env.out, "Aborted.");
            return Exit::Success;
        }
    }
    let store = match open(env) {
        Ok(store) => store,
        Err(code) => return code,
    };
    match store.wipe_signed_qsos() {
        Ok(count) => {
            let _ = writeln!(env.out, "Wiped {count} signed QSO record{}.", plural(count));
            Exit::Success
        }
        Err(e) => store_error(env, "the record of signed QSOs", &e),
    }
}

fn store_error(env: &mut Env<'_>, what: &str, e: &StoreError) -> Exit {
    env.message(Tone::Error, format_args!("{what}: {e}"));
    Exit::TqslError
}

// ---- Signing and uploading ----

/// What `sign` made: where the signed log is, how many QSOs it holds.
struct Signed {
    path: PathBuf,
    /// The bytes written, uploaded as they are: the file may be replaced by another run.
    tq8: Vec<u8>,
    /// QSOs were left out: refused, outside the dates, or signed before and skipped.
    suppressed: bool,
}

fn signing_options(a: &OptionArgs) -> SigningOptions {
    SigningOptions {
        exact_station: false,
        adif_modes: a.modes.clone(),
        ignore_seconds: a.ignore_seconds,
        allow_bad_calls: a.allow_bad_calls,
        ignore_log_callsigns: a.ignore_log_callsigns,
        qth: match a.qth {
            Qth::Refuse => QthHandling::Refuse,
            Qth::Ignore => QthHandling::Ignore,
            Qth::FromLog => QthHandling::FromLog,
        },
    }
}

fn sign(a: &SignArgs, env: &mut Env<'_>) -> Result<Signed, Exit> {
    sign_inner(a, env, false)
}

fn sign_inner(a: &SignArgs, env: &mut Env<'_>, test_sign: bool) -> Result<Signed, Exit> {
    if let (Some(b), Some(e)) = (a.begin, a.end)
        && b > e
    {
        env.message(
            Tone::Error,
            format_args!("the --from date is after the --to date"),
        );
        return Err(Exit::CommandError);
    }
    let store = open(env)?;
    env.trace.line(format_args!("Store opened"));
    let locations = store
        .locations()
        .map_err(|e| store_error(env, "the station locations", &e))?;
    let default = store
        .default_location()
        .map_err(|e| store_error(env, "the default station location", &e))?;
    let name = match a.location.as_deref().or(default.as_deref()) {
        Some(name) => name,
        None => {
            let names: Vec<&str> = locations.iter().map(|l| l.name.as_str()).collect();
            let message = if names.is_empty() {
                "You have no station locations: qg-trust location add or qg-trust import from TQSL"
                    .to_string()
            } else {
                format!(
                    "No default station location; you have: {}. Use qg-trust location default <NAME> or choose a location in the logger",
                    names.join(", ")
                )
            };
            env.message(Tone::Error, format_args!("{message}"));
            env.trace.line(format_args!("Refused: {message}"));
            return Err(Exit::CommandError);
        }
    };
    if a.location.is_none() {
        env.message(
            Tone::Warning,
            format_args!("No -l given: signing for the default station location {name:?}"),
        );
        env.trace.line(format_args!(
            "No -l given: signing for the default station location {name:?}"
        ));
    }
    let Some(location) = locations.iter().find(|l| l.name == name) else {
        let names: Vec<&str> = locations.iter().map(|l| l.name.as_str()).collect();
        env.message(
            Tone::Error,
            format_args!(
                "there is no station location called {:?}; {}",
                name,
                if names.is_empty() {
                    "you have none yet: qg-trust import your TQSL backup, or qg-trust location add"
                        .to_string()
                } else {
                    format!("you have: {}", names.join(", "))
                }
            ),
        );
        env.trace.line(format_args!(
            "Refused: the station location is not in the store"
        ));
        return Err(Exit::CommandError);
    };
    env.trace.line(format_args!(
        "Station location {:?}: call {}, DXCC {}",
        location.name,
        location.station.call(),
        location.station.dxcc()
    ));
    // TQSL's -c: the location's call replaced for this run; the stored location is not changed.
    let station = match crate::cli::with_call(&location.station, a.callsign.as_deref()) {
        Ok(station) => station,
        Err(e) => {
            env.message(
                Tone::Error,
                format_args!("the station location with -c: {e}"),
            );
            return Err(Exit::TqslError);
        }
    };
    let station = &station;
    if a.callsign.is_some() {
        env.trace.line(format_args!(
            "-c: signing as {} in place of {}",
            station.call(),
            location.station.call()
        ));
    }
    if let Err(e) = check_output(a.output.as_deref().unwrap_or(&a.log.with_extension("tq8"))) {
        env.message(Tone::Error, format_args!("{e}"));
        return Err(Exit::OutputError);
    }
    let options = signing_options(&a.options);
    let records = match read_file(&a.log, MAX_LOG_LEN)
        .map_err(|e| e.to_string())
        .and_then(|bytes| records::parse(&bytes).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => {
            env.message(
                Tone::Error,
                format_args!("the log {}: {e}", a.log.display()),
            );
            return Err(Exit::InputError);
        }
    };
    let mut numbers = Vec::new();
    let mut qsos = Vec::new();
    let (mut refused, mut out_of_range) = (0usize, 0usize);
    let mut left_out = LeftOut::default();
    for (i, record) in records.iter().enumerate() {
        match Qso::from_adif_with_options(record, &options) {
            Ok(qso) => {
                let d = qso.date();
                if a.begin.is_some_and(|b| d < b) || a.end.is_some_and(|e| d > e) {
                    out_of_range += 1;
                    left_out.out_of_range += 1;
                    continue;
                }
                numbers.push(i + 1);
                qsos.push(qso);
            }
            Err(e) => {
                if let Some(err) = record.cabrillo_conversion_error() {
                    env.message(Tone::Error, format_args!("{err}"));
                    return Err(Exit::InputError);
                }
                if stops_on_refusal(a) {
                    return Err(abort(env, a, i + 1, &e.to_string()));
                }
                env.message(
                    Tone::Warning,
                    format_args!("QSO {} in the log: not signed: {e}", i + 1),
                );
                refused += 1;
                left_out.invalid += 1;
            }
        }
    }

    let output = a
        .output
        .clone()
        .unwrap_or_else(|| a.log.with_extension("tq8"));
    let certs = store
        .certificates()
        .map_err(|e| store_error(env, "the certificates", &e))?;
    let candidates = signers(&certs, station.call(), station.dxcc(), env.now);
    let chosen = match &a.cert {
        Some(id) => by_id(&candidates, id, |c| &c.id).copied(),
        None => best_signer(&candidates, &qsos),
    };
    let Some(cert) = chosen else {
        env.message(
            Tone::Error,
            format_args!(
                "you have no certificate for {} ({}) in force now, with its key{}; qg-trust cert \
                 list shows what you have",
                station.call(),
                entity(station.dxcc()),
                if a.cert.is_some() {
                    ", with that ID"
                } else {
                    ""
                }
            ),
        );
        env.trace.line(format_args!(
            "Certificate: none in force for {} (DXCC {})",
            station.call(),
            station.dxcc()
        ));
        return Err(Exit::TqslError);
    };
    env.trace.line(format_args!(
        "Certificate: {} (DXCC {}), serial {}, ID {}",
        cert.certificate.callsign(),
        cert.certificate.dxcc(),
        cert.certificate
            .serial()
            .map_or_else(|| "too large to show".to_string(), |s| s.to_string()),
        short(&cert.id)
    ));
    // QSOs the certificate does not cover go first, before the log's location details are
    // carried from one QSO to the next, so one of them cannot make a later QSO fail.
    let mut i = 0;
    while i < qsos.len() {
        if covers(&cert.certificate, &qsos[i]) {
            i += 1;
            continue;
        }
        let mut reason = "outside the QSO dates the certificate covers".to_string();
        if let Some(other) = candidates
            .iter()
            .find(|c| c.id != cert.id && covers(&c.certificate, &qsos[i]))
        {
            let id = short(&other.id);
            let _ = write!(
                reason,
                "; certificate {id} covers it: sign it with --cert {id}"
            );
        }
        if stops_on_refusal(a) {
            return Err(abort(env, a, numbers[i], &reason));
        }
        env.message(
            Tone::Warning,
            format_args!("QSO {} in the log: not signed: {reason}", numbers[i]),
        );
        numbers.remove(i);
        qsos.remove(i);
        refused += 1;
        left_out.outside_certificate += 1;
    }
    if test_sign {
        crate::cli::test_sign_message(env);
    }
    let again = signs_again(a);
    let choice = if again {
        DuplicateChoice::SignAgain
    } else {
        DuplicateChoice::NewOnly
    };
    // A QSO the certificate or station cannot sign is named and left out, and the rest are signed.
    let now = env.now;
    let (signed, before, count) = loop {
        // The options-aware path, whatever the options: it is the one that does TQSL's location
        // checks (a log may fill a field the location leaves empty), as tqslconvert.cpp does.
        let plan = match store.prepare_signing_with_options(&qsos, station, &options) {
            Ok(p) => p,
            Err(StoreError::Log(e)) => match refusal(&e) {
                Some((index, reason)) => {
                    left_out.count(&e);
                    if stops_on_refusal(a) {
                        return Err(abort(env, a, numbers[index], &reason));
                    }
                    env.message(
                        Tone::Warning,
                        format_args!("QSO {} in the log: not signed: {reason}", numbers[index]),
                    );
                    numbers.remove(index);
                    qsos.remove(index);
                    refused += 1;
                    continue;
                }
                None => {
                    env.message(Tone::Error, format_args!("the log: {e}"));
                    return Err(Exit::TqslError);
                }
            },
            Err(e) => return Err(store_error(env, "the log", &e)),
        };
        let before = plan.signed_before().len();
        if before > 0 {
            match a.action {
                Some(Action::Abort) => {
                    env.message(
                        Tone::Error,
                        format_args!(
                            "{before} of {} QSOs were signed before; aborted",
                            qsos.len()
                        ),
                    );
                    return Err(Exit::UploadedAlready);
                }
                Some(Action::Ask) | None if a.action.is_some() || is_logger(a) => {
                    env.message(
                        Tone::Error,
                        format_args!(
                            "{before} of {} QSOs were signed before, and qg-trust cannot ask what to \
                             do: -a compliant signs only the new ones, -a all signs them all",
                            qsos.len()
                        ),
                    );
                    return Err(Exit::UploadedAlready);
                }
                _ => {}
            }
        }
        let Some(selection) = plan.choose(choice) else {
            return Err(Exit::Cancel);
        };
        // Each selected QSO's place in `qsos`.
        let picked: Vec<usize> = match choice {
            DuplicateChoice::NewOnly => plan.new_indices().to_vec(),
            _ => (0..qsos.len()).collect(),
        };
        if selection.qsos().is_empty() {
            left_out.signed_before = before;
            left_out.trace(records.len(), 0, env);
            if before > 0 {
                env.message(
                    Tone::Error,
                    format_args!(
                        "all {before} QSO{} were signed before; without -d they are signed again",
                        plural(before)
                    ),
                );
            } else {
                env.message(Tone::Error, format_args!("the log has no QSOs to sign"));
            }
            return Err(Exit::NoQsos);
        }
        let result = store
            .with_key(&cert.id, |key| selection.sign(&cert.certificate, key, now))
            .map_err(|e| store_error(env, &format!("{}'s key", cert.certificate.callsign()), &e))?;
        let outside = matches!(result, Err(LogError::QsoOutsideCertificate { .. }));
        if let Err(e) = &result {
            left_out.count(e);
        }
        let (index, reason) = match result {
            Ok(signed) => break (signed, before, selection.qsos().len()),
            Err(e) => match refusal(&e) {
                Some(r) => r,
                None => {
                    env.message(Tone::Error, format_args!("the log: {e}"));
                    return Err(Exit::TqslError);
                }
            },
        };
        let at = picked[index];
        // Another certificate in force may cover this QSO's date: say which.
        let reason = match candidates
            .iter()
            .find(|c| c.id != cert.id && covers(&c.certificate, &qsos[at]))
        {
            Some(other) if outside => {
                let id = short(&other.id);
                format!("{reason}; certificate {id} covers it: sign it with --cert {id}")
            }
            _ => reason,
        };
        if stops_on_refusal(a) {
            return Err(abort(env, a, numbers[at], &reason));
        }
        env.message(
            Tone::Warning,
            format_args!("QSO {} in the log: not signed: {reason}", numbers[at]),
        );
        numbers.remove(at);
        qsos.remove(at);
        refused += 1;
    };

    // write_to makes a new file and refuses the store's own names and folder. With --force, it
    // makes a new one beside the output, which then replaces it: nothing is deleted first.
    let replacing = output.exists();
    if replacing && !a.force {
        env.message(
            Tone::Error,
            format_args!("{} is there already; --force replaces it", output.display()),
        );
        return Err(Exit::OutputError);
    }
    let target = if replacing {
        match crate::cli::new_partial(&output) {
            Ok(p) => p,
            Err(e) => {
                env.message(Tone::Error, format_args!("{}: {e}", output.display()));
                return Err(Exit::OutputError);
            }
        }
    } else {
        output.clone()
    };
    let tq8 = signed.tq8().to_vec();
    // Every log written can be uploaded: checked before anything is written or recorded.
    if qso_graph_trust::upload::check_signed_log(&tq8).is_err() {
        env.message(Tone::Error, format_args!("{UNUPLOADABLE}"));
        return Err(Exit::TqslError);
    }
    if test_sign {
        signed.check_output_path(store, &output).map_err(|e| {
            env.message(Tone::Error, format_args!("{}: {e}", output.display()));
            Exit::OutputError
        })?;
    }
    let write_result = if test_sign {
        let tq7 =
            qso_graph_trust::gzip::decompress(&tq8, qso_graph_trust::upload::MAX_SIGNED_LOG_BYTES)
                .map_err(|_| {
                    env.message(Tone::Error, format_args!("{UNUPLOADABLE}"));
                    Exit::TqslError
                })?;
        write_new(&target, &tq7, false).map_err(StoreError::from)
    } else {
        signed.write_to(store, &target)
    };
    if let Err(e) = write_result {
        env.message(Tone::Error, format_args!("{}: {e}", output.display()));
        return Err(Exit::OutputError);
    }
    if replacing && let Err(e) = std::fs::rename(&target, &output) {
        env.message(
            Tone::Error,
            format_args!(
                "{}: {e}; the signed log is in {}{}",
                output.display(),
                target.display(),
                if test_sign {
                    "; its QSOs were not recorded"
                } else {
                    "; its QSOs are recorded as signed"
                }
            ),
        );
        return Err(Exit::OutputError);
    }
    if test_sign {
        crate::cli::test_sign_message(env);
    }
    let again = signs_again(a);
    if !again {
        left_out.signed_before = before;
    }
    left_out.trace(records.len(), count, env);
    env.trace.line(format_args!(
        "Signed log written: {}",
        if a.output.is_some() {
            "to -o's file"
        } else {
            "beside the log, with .tq8"
        }
    ));
    let mut summary = format!(
        "Signed {count} QSO{} for {} at {}",
        plural(count),
        station.call(),
        location.name
    );
    if before > 0 && !again {
        let _ = write!(summary, "; {before} signed before, left out by -d");
    }
    if refused > 0 {
        let _ = write!(summary, "; {refused} not signed, named above");
    }
    if out_of_range > 0 {
        let _ = write!(summary, "; {out_of_range} outside the dates given");
    }
    let _ = writeln!(env.out, "{summary}.");
    let _ = writeln!(env.out, "Written to {}", output.display());
    Ok(Signed {
        path: output,
        tq8,
        suppressed: refused > 0 || out_of_range > 0 || (before > 0 && !again),
    })
}

/// Why a signed log is not written: one LoTW's upload would not take, too large for one upload.
pub(crate) const UNUPLOADABLE: &str = "the signed log would be too large for one upload, so nothing \
    is written or recorded: sign it in parts, with --from and --to (-b and -e)";

/// A QSO the log or station cannot sign: its place in the list given, and why.
fn refusal(e: &LogError) -> Option<(usize, String)> {
    match e {
        LogError::QsoOutsideCertificate { index } => Some((
            *index,
            "outside the QSO dates the certificate covers".to_string(),
        )),
        LogError::QsoFromAnotherStation {
            index,
            field,
            value,
        } => Some((
            *index,
            format!("its {field} is {value:?}, not this station location's"),
        )),
        LogError::Location { index, error } => Some((*index, error.to_string())),
        _ => None,
    }
}

/// Whether a QSO that cannot be signed stops the run: `-a abort`, as TQSL's batch mode does, and
/// `-a ask` (a logger's default), since TQSL would ask whether to sign the rest and qg-trust
/// cannot.
fn stops_on_refusal(a: &SignArgs) -> bool {
    matches!(a.action, Some(Action::Abort | Action::Ask))
}

/// Stop at a QSO that cannot be signed: nothing is signed, written or recorded.
fn abort(env: &mut Env<'_>, a: &SignArgs, number: usize, reason: &str) -> Exit {
    env.trace.line(format_args!(
        "Stopped at the log's QSO {number}, which cannot be signed: nothing signed"
    ));
    if a.action == Some(Action::Abort) {
        env.message(
            Tone::Error,
            format_args!(
                "QSO {number} in the log cannot be signed: {reason}; aborted, nothing signed"
            ),
        );
    } else {
        env.message(
            Tone::Error,
            format_args!(
                "QSO {number} in the log cannot be signed: {reason}; qg-trust cannot ask whether to \
                 sign the rest, so nothing is signed: -a compliant signs the rest"
            ),
        );
    }
    Exit::NoQsos
}

/// The certificates that can sign for this call and entity now: in force, with their keys.
fn signers<'a>(
    certs: &'a [StoredCertificate],
    call: &str,
    dxcc: u32,
    now: SystemTime,
) -> Vec<&'a StoredCertificate> {
    certs
        .iter()
        .filter(|c| c.key_name.is_some())
        .filter(|c| c.certificate.callsign() == call && c.certificate.dxcc() == dxcc)
        .filter(|c| c.certificate.is_valid_at(now))
        .collect()
}

/// Whether a certificate's QSO dates cover this QSO.
fn covers(cert: &Certificate, qso: &Qso) -> bool {
    let (from, to) = cert.qso_dates();
    (from..=to).contains(&qso.date())
}

/// The certificate covering most of the log's QSOs; of those, the one in force longest, as a
/// renewed certificate is.
fn best_signer<'a>(
    candidates: &[&'a StoredCertificate],
    qsos: &[Qso],
) -> Option<&'a StoredCertificate> {
    candidates.iter().copied().max_by_key(|c| {
        (
            qsos.iter().filter(|q| covers(&c.certificate, q)).count(),
            c.certificate.validity().1,
        )
    })
}

/// Refuse an output named as one of the store's own files (`store.xml`, `store.xml.partial`,
/// `store.lock`, in any case), in any folder: the store holds nothing else, its keys being in the
/// credential store, so no output can replace any part of a store.
pub(crate) fn check_output(path: &Path) -> Result<(), String> {
    let reserved = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        ["store.xml", "store.xml.partial", "store.lock"]
            .iter()
            .any(|r| n.eq_ignore_ascii_case(r))
    });
    if reserved {
        return Err(format!(
            "{}: that name is QG Trust's store's own; give the output another",
            path.display()
        ));
    }
    Ok(())
}

fn send(a: &SignArgs, env: &mut Env<'_>) -> Done {
    let signed = sign(a, env)?;
    let code = upload_bytes(
        &signed.tq8,
        &signed.path.display().to_string(),
        &signed.path,
        env,
    )?;
    Ok(if signed.suppressed {
        Exit::QsosSuppressed
    } else {
        code
    })
}

/// What a logger gave, of TQSL's options.
#[derive(Clone, Copy)]
pub(crate) struct LoggerCall<'a> {
    pub log: &'a Path,
    pub location: &'a str,
    /// TQSL's -c, checked and in capitals.
    pub callsign: Option<&'a str>,
    pub begin: Option<Date>,
    pub end: Option<Date>,
    pub output: Option<&'a Path>,
    pub action: Option<Action>,
    pub verify: Option<Verify>,
    pub upload: bool,
    pub test_sign: bool,
}

/// A logger's call without -i: TQSL's options, signed from QG Trust's store as TQSL signs from its
/// own. The signed log is replaced if it is there, as TQSL replaces it; QSOs signed before are
/// handled as -a says; the exit code is TQSL's.
pub(crate) fn sign_for_logger(call: &LoggerCall<'_>, env: &mut Env<'_>) -> Exit {
    let LoggerCall {
        log,
        location,
        callsign,
        begin,
        end,
        output,
        action,
        verify,
        upload,
        test_sign,
    } = *call;
    let args = SignArgs {
        log: log.to_path_buf(),
        location: if location.is_empty() {
            None
        } else {
            Some(location.to_string())
        },
        begin,
        end,
        output: output.map(Path::to_path_buf),
        dedupe: false,
        again: false,
        cert: None,
        force: true,
        options: OptionArgs {
            ignore_seconds: false,
            allow_bad_calls: false,
            ignore_log_callsigns: false,
            qth: match verify {
                Some(Verify::Ignore) => Qth::Ignore,
                Some(Verify::Update) => Qth::FromLog,
                Some(Verify::Report) | None => Qth::Refuse,
            },
            modes: Vec::new(),
        },
        // No -a is TQSL's "ask", which qg-trust cannot do: refused with 14 if it matters.
        action: Some(action.unwrap_or(Action::Ask)),
        callsign: callsign.map(str::to_string),
    };
    let signed = match sign_inner(&args, env, test_sign) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let status = if signed.suppressed {
        Exit::QsosSuppressed
    } else {
        Exit::Success
    };
    if !upload {
        return status;
    }
    match upload_bytes(
        &signed.tq8,
        &signed.path.display().to_string(),
        &signed.path,
        env,
    ) {
        Ok(_) => status,
        Err(code) => code,
    }
}

/// Whether a logger called (the action is always set then).
fn is_logger(a: &SignArgs) -> bool {
    a.action.is_some()
}

fn upload_file(path: &Path, env: &mut Env<'_>) -> Done {
    let bytes = match read_file(path, MAX_LOG_LEN) {
        Ok(b) => b,
        Err(e) => {
            env.message(Tone::Error, format_args!("{}: {e}", path.display()));
            return Err(Exit::InputError);
        }
    };
    upload_bytes(&bytes, &path.display().to_string(), path, env)
}

/// Uploads a signed log, named `what` in messages, after checking it is one. LoTW is sent the
/// file name of `name`, never its folder, so its activity list tells uploads apart.
pub(crate) fn upload_bytes(bytes: &[u8], what: &str, name: &Path, env: &mut Env<'_>) -> Done {
    // What is sent is what was checked, gzipped afresh: never the bytes as given.
    let Ok(bytes) = qso_graph_trust::upload::check_signed_log(bytes) else {
        env.message(
            Tone::Error,
            format_args!("{what} is not a signed log (.tq8); qg-trust sign makes one"),
        );
        return Err(Exit::InputError);
    };
    let basename = name
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let request = match UploadRequest::try_named(&bytes, &basename) {
        Ok(r) => r,
        Err(_) => {
            env.message(
                Tone::Error,
                format_args!("the upload could not be prepared"),
            );
            return Err(Exit::TqslError);
        }
    };
    let _ = writeln!(env.out, "Uploading {what} to LoTW…");
    let (status, body) = match (env.upload)(&request) {
        Ok(r) => r,
        Err(UploadFailure {
            message,
            maybe_sent: true,
        }) => {
            env.trace.line(format_args!(
                "Upload: the connection failed after the log was sent"
            ));
            env.message(
                Tone::Error,
                format_args!(
                    "{message} after the log was sent, so whether LoTW has it is not known; \
                     check your LoTW account before uploading it again"
                ),
            );
            return Err(Exit::UnexpectedResponse);
        }
        Err(UploadFailure { message: e, .. }) => {
            env.trace
                .line(format_args!("Upload: LoTW could not be reached"));
            env.message(Tone::Error, format_args!("LoTW could not be reached: {e}"));
            env.message(
                Tone::Warning,
                format_args!("the signed log is kept; qg-trust upload {what} tries again"),
            );
            return Err(Exit::ConnectionFailed);
        }
    };
    let outcome = qso_graph_trust::upload::parse_response(status, &body);
    env.trace.line(format_args!(
        "Upload: HTTP {status}, LoTW's answer: {}",
        match outcome {
            UploadOutcome::Accepted { .. } => "accepted",
            UploadOutcome::Rejected { .. } => "rejected",
            UploadOutcome::Unknown => "not readable",
        }
    ));
    match outcome {
        UploadOutcome::Accepted { message } => {
            let _ = writeln!(env.out, "LoTW accepted the log for processing.");
            if let Some(m) = message {
                let _ = writeln!(env.out, "LoTW says: {m}");
            }
            Ok(Exit::Success)
        }
        UploadOutcome::Rejected { message } => {
            env.message(
                Tone::Error,
                format_args!(
                    "LoTW refused the log: {}",
                    message.as_deref().unwrap_or("it gave no reason")
                ),
            );
            Err(Exit::Rejected)
        }
        UploadOutcome::Unknown => {
            env.message(
                Tone::Error,
                format_args!(
                    "LoTW's answer (HTTP {status}) could not be read, so whether it has the log is not \
                     known; check your LoTW account before uploading it again"
                ),
            );
            Err(Exit::UnexpectedResponse)
        }
    }
}

// ---- Importing ----

fn kind_of(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default()
}

fn import(a: &ImportArgs, env: &mut Env<'_>) -> Done {
    let store = open(env)?;
    // A confirmation that nothing here can use is refused, never ignored.
    if a.trust_root.is_some()
        && !a
            .files
            .iter()
            .any(|p| matches!(kind_of(p).as_str(), "tq6" | "p12" | "pfx"))
    {
        env.message(
            Tone::Error,
            format_args!("--trust-root is for a .tq6 or .p12 that brings a root"),
        );
        return Err(Exit::CommandError);
    }
    let accept = a.trust_root.as_deref();
    let mut failed = false;
    for path in &a.files {
        let result = match kind_of(path).as_str() {
            "tbk" => import_tbk(store, path, env),
            "tq6" => import_tq6(store, path, accept, env),
            "p12" | "pfx" => import_p12(store, path, accept, env),
            _ => {
                env.message(
                    Tone::Error,
                    format_args!(
                        "{}: qg-trust imports .tbk, .tq6 and .p12 files",
                        path.display()
                    ),
                );
                Err(Exit::InputError)
            }
        };
        failed |= result.is_err();
    }
    if failed {
        Err(Exit::TqslError)
    } else {
        Ok(Exit::Success)
    }
}

/// The store's trust: the program's (LoTW's pinned roots) and the roots the store has accepted.
fn store_trust(store: &Store, env: &mut Env<'_>) -> Result<Trust, Exit> {
    store
        .trust_with(env.trust)
        .map_err(|e| store_error(env, "the trusted roots", &e))
}

/// One line for each root newly trusted.
fn report_roots(roots: &[TrustedRoot], from: &str, env: &mut Env<'_>) {
    for r in roots {
        let _ = writeln!(
            env.out,
            "  trusted ARRL root {} SHA-256 {}, {from}",
            r.subject, r.fingerprint
        );
    }
}

/// The message for a file whose certificates chain to a root it brings, not trusted yet.
fn untrusted_root(path: &Path, subject: &str, fingerprint: &str, env: &mut Env<'_>) -> Exit {
    env.message(
        Tone::Error,
        format_args!(
            "{} brings an ARRL root QG Trust does not trust yet: {subject}, SHA-256 {fingerprint}. \
             If it is ARRL's, run again with --trust-root {fingerprint}",
            path.display()
        ),
    );
    Exit::TqslError
}

fn import_tbk(store: &Store, path: &Path, env: &mut Env<'_>) -> Result<(), Exit> {
    let trust = store_trust(store, env)?;
    let bytes = read_file(path, tbk::MAX_TBK_LEN).map_err(|e| {
        env.message(Tone::Error, format_args!("{}: {e}", path.display()));
        Exit::InputError
    })?;
    let mut pending = store.inspect_tbk(&bytes, &trust).map_err(|e| {
        env.message(Tone::Error, format_args!("{}: {e}", path.display()));
        Exit::InputError
    })?;
    let entries = pending.preview().certificates.clone();
    for (index, entry) in entries.iter().enumerate() {
        if let ImportDisposition::Refused { reason } = &entry.disposition
            && entry.qso_dates.is_some()
        {
            env.message(Tone::Error, format_args!("{}: {reason}", entry.callsign));
            return Err(Exit::TqslError);
        }
        if entry.needs_password {
            let password = (env.ask_password)(&format!(
                "Password for {}'s key, as set in TQSL: ",
                entry.callsign
            ))
            .map_err(|e| {
                env.message(
                    Tone::Error,
                    format_args!("the password could not be read: {e}"),
                );
                Exit::TqslError
            })?;
            pending.unlock_key(index, &password).map_err(|e| {
                let error = match &e {
                    ImportError::KeyAt { error, .. } => error as &dyn std::fmt::Display,
                    _ => &e,
                };
                env.message(
                    Tone::Error,
                    format_args!("{}'s key: {error}", entry.callsign),
                );
                Exit::TqslError
            })?;
        }
    }
    let existing = store
        .locations()
        .map_err(|e| store_error(env, "the station locations", &e))?;
    let prefs = pending.preview().preferences.clone();
    // Preserve the command's own-backup policy. The library still requires explicit fingerprints.
    let fingerprints: Vec<String> = pending
        .preview()
        .roots
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();
    let accepted: Vec<&str> = fingerprints.iter().map(String::as_str).collect();
    let report = store
        .commit(
            pending,
            ImportChoices {
                accept_roots: &accepted,
                store_locations: true,
                skip_refused: true,
            },
        )
        .map_err(|e| {
            env.message(Tone::Error, format_args!("{}: {e}", path.display()));
            Exit::TqslError
        })?;
    report_roots(&report.roots, "from the backup", env);
    let mut installed = report.certificates.iter();
    let mut certs = 0;
    for entry in &entries {
        if entry.qso_dates.is_none() {
            let _ = writeln!(
                env.out,
                "  {}: a request still waiting for ARRL in TQSL, not imported; request again with qg-trust cert request",
                entry.callsign
            );
            continue;
        }
        let item = installed
            .next()
            .expect("one report per accepted certificate");
        if item.already_here {
            let _ = writeln!(
                env.out,
                "  {} ({}): already here",
                entry.callsign,
                entity(entry.dxcc)
            );
        } else {
            certs += 1;
            let _ = writeln!(
                env.out,
                "  {} ({}): certificate{} imported",
                entry.callsign,
                entity(entry.dxcc),
                if item.has_key {
                    " and key"
                } else {
                    ", without a key,"
                }
            );
        }
    }
    for loc in &report.locations {
        let _ = writeln!(
            env.out,
            "  location {}: {}",
            loc.name,
            if existing.iter().any(|l| l.name == loc.name) {
                "already here, kept as it is"
            } else {
                "imported"
            }
        );
    }
    let locs = report.locations_added;
    if existing.is_empty() && locs > 1 {
        let _ = writeln!(
            env.out,
            "  No default station location yet: qg-trust location default NAME sets the one used when no -l is given"
        );
    }
    let signed = report.signed_qsos_added;
    let _ = writeln!(
        env.out,
        "Imported {certs} certificate{}, {locs} location{} and {signed} signed QSO{} from {}.",
        plural(certs),
        plural(locs),
        plural(signed),
        path.display()
    );
    let mut settings = Vec::new();
    if prefs.ignore_seconds {
        settings.push("--ignore-seconds");
    }
    if prefs.allow_bad_calls {
        settings.push("--allow-bad-calls");
    }
    if prefs.ignore_log_callsigns {
        settings.push("--ignore-log-callsigns");
    }
    match prefs.qth {
        QthHandling::Refuse => {}
        QthHandling::Ignore => settings.push("--qth ignore"),
        QthHandling::FromLog => settings.push("--qth from-log"),
    }
    if !prefs.adif_modes.is_empty() {
        settings.push("--mode ADIF=LOTW");
    }
    if !settings.is_empty() {
        let _ = writeln!(
            env.out,
            "Your TQSL settings change what is signed; to sign as TQSL did, give qg-trust sign: {}",
            settings.join(" ")
        );
        for (adif, lotw) in &prefs.adif_modes {
            let _ = writeln!(env.out, "  --mode {adif}={lotw}");
        }
    }
    Ok(())
}

/// The root `accept` names, if this store did not trust it before: for saying it now does.
fn newly_trusted(store: &Store, before: &[TrustedRoot], accept: Option<&str>) -> Vec<TrustedRoot> {
    let Some(fp) = accept else {
        return Vec::new();
    };
    if before.iter().any(|r| r.fingerprint == fp) {
        return Vec::new();
    }
    store
        .trusted_roots()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.fingerprint == fp && r.kind == RootKind::Root)
        .collect()
}

/// What a refused import says about its root, when that is why.
fn root_refusal(path: &Path, e: &ImportError, env: &mut Env<'_>) -> Option<Exit> {
    match e {
        ImportError::UntrustedRoot {
            subject,
            fingerprint,
        } => Some(untrusted_root(path, subject, fingerprint, env)),
        ImportError::RootMismatch { .. } => {
            env.message(
                Tone::Error,
                format_args!(
                    "{}: {e}; nothing was imported. Run it again without --trust-root to see the \
                     root it brings",
                    path.display()
                ),
            );
            Some(Exit::TqslError)
        }
        _ => None,
    }
}

fn import_tq6(
    store: &Store,
    path: &Path,
    accept: Option<&str>,
    env: &mut Env<'_>,
) -> Result<(), Exit> {
    let bytes = match read_file(path, qso_graph_trust::import::MAX_IMPORT_LEN) {
        Ok(b) => b,
        Err(e) => {
            env.message(Tone::Error, format_args!("{}: {e}", path.display()));
            return Err(Exit::InputError);
        }
    };
    let trust = store_trust(store, env)?;
    let before = store
        .trusted_roots()
        .map_err(|e| store_error(env, "the trusted roots", &e))?;
    let imported = store.inspect_tq6(&bytes, &trust).and_then(|pending| {
        store.commit(
            pending,
            ImportChoices {
                accept_roots: &accept.into_iter().collect::<Vec<_>>(),
                ..Default::default()
            },
        )
    });
    match imported.map(|report| report.certificates) {
        Ok(imported) => {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            report_roots(
                &newly_trusted(store, &before, accept),
                &format!("from {}", name.unwrap_or_default()),
                env,
            );
            for c in &imported {
                let _ = writeln!(
                    env.out,
                    "  {}: {}",
                    short(&c.id),
                    if c.already_here {
                        "already here"
                    } else if c.attached_request {
                        "the certificate for your request, with its key: ready to sign"
                    } else if c.has_key {
                        "certificate, with its key"
                    } else {
                        "certificate, without a key: it cannot sign"
                    }
                );
            }
            let new = imported.iter().filter(|c| !c.already_here).count();
            let _ = writeln!(
                env.out,
                "Imported {new} certificate{} from {}.",
                plural(new),
                path.display()
            );
            Ok(())
        }
        Err(ImportError::Store(StoreError::AlreadyExists)) => {
            let _ = writeln!(env.out, "{}: already here", path.display());
            Ok(())
        }
        Err(e) => {
            if let Some(code) = root_refusal(path, &e, env) {
                return Err(code);
            }
            env.message(Tone::Error, format_args!("{}: {e}", path.display()));
            Err(Exit::TqslError)
        }
    }
}

fn import_p12(
    store: &Store,
    path: &Path,
    accept: Option<&str>,
    env: &mut Env<'_>,
) -> Result<(), Exit> {
    let bytes = match read_file(path, qso_graph_trust::import::MAX_IMPORT_LEN) {
        Ok(b) => b,
        Err(e) => {
            env.message(Tone::Error, format_args!("{}: {e}", path.display()));
            return Err(Exit::InputError);
        }
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let password = match (env.ask_password)(&format!("Password for {name}: ")) {
        Ok(p) => p,
        Err(e) => {
            env.message(
                Tone::Error,
                format_args!("the password could not be read: {e}"),
            );
            return Err(Exit::BadPassphrase);
        }
    };
    let trust = store_trust(store, env)?;
    let before = store
        .trusted_roots()
        .map_err(|e| store_error(env, "the trusted roots", &e))?;
    let imported = store
        .inspect_pkcs12(&bytes, &password, &trust)
        .and_then(|pending| {
            store.commit(
                pending,
                ImportChoices {
                    accept_roots: &accept.into_iter().collect::<Vec<_>>(),
                    ..Default::default()
                },
            )
        })
        .and_then(|report| {
            let imported = report
                .certificates
                .into_iter()
                .next()
                .ok_or(ImportError::Malformed)?;
            if imported.already_here {
                Err(ImportError::Store(StoreError::AlreadyExists))
            } else {
                Ok(imported)
            }
        });
    match imported {
        Ok(c) => {
            report_roots(
                &newly_trusted(store, &before, accept),
                &format!("from {name}"),
                env,
            );
            let _ = writeln!(
                env.out,
                "Imported {}'s certificate and key ({}).",
                name,
                short(&c.id)
            );
            Ok(())
        }
        Err(ImportError::Authentication) => {
            env.message(
                Tone::Error,
                format_args!("that password does not open {name}"),
            );
            Err(Exit::BadPassphrase)
        }
        Err(ImportError::Store(StoreError::AlreadyExists)) => {
            let _ = writeln!(env.out, "{}: already here", path.display());
            Ok(())
        }
        Err(e) => {
            if let Some(code) = root_refusal(path, &e, env) {
                return Err(code);
            }
            env.message(Tone::Error, format_args!("{}: {e}", path.display()));
            Err(Exit::TqslError)
        }
    }
}

// ---- Trusted roots ----

fn root(r: Root, env: &mut Env<'_>) -> Done {
    let store = open(env)?;
    match r {
        Root::List(a) => root_list(store, a.json, env),
        Root::Remove(a) => match store.remove_root(&a.fingerprint) {
            Ok(removed) => {
                let _ = writeln!(
                    env.out,
                    "No longer trusting {} SHA-256 {}.",
                    removed.subject, removed.fingerprint
                );
                Ok(Exit::Success)
            }
            Err(StoreError::NotFound) => {
                env.message(
                    Tone::Error,
                    format_args!(
                        "no root you accepted has the fingerprint {}; qg-trust root list shows them",
                        a.fingerprint
                    ),
                );
                Err(Exit::CommandError)
            }
            Err(StoreError::BuiltInRoot) => {
                env.message(
                    Tone::Error,
                    format_args!(
                        "{} is one of LoTW's roots or CAs built into QG Trust: it is always \
                         trusted and cannot be removed",
                        a.fingerprint
                    ),
                );
                Err(Exit::CommandError)
            }
            Err(e) => Err(store_error(env, "the trusted roots", &e)),
        },
    }
}

fn root_list(store: &Store, json: bool, env: &mut Env<'_>) -> Done {
    let roots = store
        .trusted_roots()
        .map_err(|e| store_error(env, "the trusted roots", &e))?;
    let kind = |r: &TrustedRoot| match r.kind {
        RootKind::Root => "root",
        RootKind::Ca => "ca",
    };
    let state = |r: &TrustedRoot| {
        if env.now < r.not_before {
            "not yet in force"
        } else if env.now > r.not_after {
            "expired"
        } else {
            "in force"
        }
    };
    if json {
        let mut s = String::from("{\"roots\":[");
        for (i, r) in roots.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let accepted = r.accepted_at.map_or("null".to_string(), |t| {
                format!(
                    "\"{}\"",
                    day(UNIX_EPOCH + std::time::Duration::from_secs(t))
                )
            });
            let _ = write!(
                s,
                "{{\"kind\":\"{}\",\"subject\":{},\"serial\":\"{}\",\"not_before\":\"{}\",\
                 \"not_after\":\"{}\",\"in_force\":{},\"sha256\":\"{}\",\"source\":\"{}\",\
                 \"accepted\":{accepted}}}",
                kind(r),
                json_str(&r.subject),
                r.serial,
                day(r.not_before),
                day(r.not_after),
                state(r) == "in force",
                r.fingerprint,
                r.source.name()
            );
        }
        s.push_str("]}");
        let _ = writeln!(env.out, "{s}");
        return Ok(Exit::Success);
    }
    for r in &roots {
        let from = match r.source {
            RootSource::BuiltIn => "built in",
            RootSource::Tq6 => "from a .tq6",
            RootSource::P12 => "from a .p12",
            RootSource::Tbk => "from a TQSL backup",
            RootSource::Part => "from a QG Trust export",
        };
        let source = match r.accepted_at {
            Some(t) => format!(
                "{from}, {}",
                day(UNIX_EPOCH + std::time::Duration::from_secs(t))
            ),
            None => from.to_string(),
        };
        let _ = writeln!(
            env.out,
            "{:<4}  {:<35} {} to {}  {}  {source}\n      SHA-256 {}   serial {}",
            kind(r).to_ascii_uppercase(),
            r.subject,
            day(r.not_before),
            day(r.not_after),
            state(r),
            r.fingerprint,
            r.serial
        );
    }
    Ok(Exit::Success)
}

// ---- Certificates ----

fn cert(c: Cert, env: &mut Env<'_>) -> Done {
    let store = open(env)?;
    match c {
        Cert::List(a) => cert_list(store, a.json, env),
        Cert::Request(a) => cert_request(store, &a, env),
        Cert::Renew(a) => cert_renew(store, &a, env),
        Cert::Delete(a) => {
            let certs = store
                .certificates()
                .map_err(|e| store_error(env, "the certificates", &e))?;
            let found = by_id(&certs, &a.id, |c| &c.id);
            let Some(found) = found else {
                env.message(
                    Tone::Error,
                    format_args!(
                        "no certificate has the ID {:?}; qg-trust cert list shows them",
                        a.id
                    ),
                );
                return Err(Exit::CommandError);
            };
            let pending = store
                .inspect_delete(&found.id)
                .map_err(|e| store_error(env, "the certificate", &e))?;
            let preview = pending.preview();
            let what = format!("{} ({})", preview.callsign, entity(preview.dxcc));
            if !a.force {
                env.message(
                    Tone::Error,
                    format_args!("deleting {what}'s certificate and key cannot be undone; give --force to delete it"),
                );
                return Err(Exit::CommandError);
            }
            store
                .commit_delete(pending)
                .map_err(|e| store_error(env, &what, &e))?;
            let _ = writeln!(
                env.out,
                "Deleted {what}'s certificate{}.",
                if found.key_name.is_some() {
                    " and key"
                } else {
                    ""
                }
            );
            Ok(Exit::Success)
        }
        Cert::Abandon(a) => {
            let pending = store
                .pending_requests()
                .map_err(|e| store_error(env, "the requests", &e))?;
            let Some(found) = by_id(&pending, &a.id, |r| &r.id) else {
                env.message(
                    Tone::Error,
                    format_args!(
                        "no request has the ID {:?}; qg-trust cert list shows them",
                        a.id
                    ),
                );
                return Err(Exit::CommandError);
            };
            if !a.force {
                env.message(
                    Tone::Error,
                    format_args!(
                        "giving up {}'s request deletes its key, so ARRL's answer can no longer be used; \
                         give --force to do it",
                        found.callsign
                    ),
                );
                return Err(Exit::CommandError);
            }
            store
                .abandon_request(&found.id)
                .map_err(|e| store_error(env, &found.callsign, &e))?;
            let _ = writeln!(env.out, "Gave up {}'s request.", found.callsign);
            Ok(Exit::Success)
        }
    }
}

/// An entry by its full ID or the short one the lists show.
fn by_id<'a, T>(items: &'a [T], given: &str, id: impl Fn(&T) -> &String) -> Option<&'a T> {
    let given = given.trim();
    if given.is_empty() {
        return None;
    }
    let matching: Vec<&T> = items
        .iter()
        .filter(|item| {
            let full = id(item);
            full == given
                || full
                    .split_once(':')
                    .is_some_and(|(_, rest)| rest.starts_with(given))
        })
        .collect();
    (matching.len() == 1).then(|| matching[0])
}

/// A certificate by ID or call: a call picks the one that signs for it now.
fn cert_by<'a>(
    certs: &'a [StoredCertificate],
    given: &str,
    now: SystemTime,
) -> Option<&'a StoredCertificate> {
    by_id(certs, given, |c| &c.id).or_else(|| {
        certs
            .iter()
            .filter(|c| {
                c.key_name.is_some() && c.certificate.callsign().eq_ignore_ascii_case(given)
            })
            .filter(|c| c.certificate.is_valid_at(now))
            .max_by_key(|c| c.certificate.validity().1)
    })
}

fn cert_list(store: &Store, json: bool, env: &mut Env<'_>) -> Done {
    let certs = store
        .certificates()
        .map_err(|e| store_error(env, "the certificates", &e))?;
    let pending = store
        .pending_requests()
        .map_err(|e| store_error(env, "the requests", &e))?;
    let expiring = store
        .expiring_certificates(env.now, 60)
        .map_err(|e| store_error(env, "the certificates", &e))?;
    let days_left = |id: &str| expiring.iter().find(|x| x.id == id).map(|x| x.days_left);
    if json {
        let mut s = String::from("{\"certificates\":[");
        for (i, c) in certs.iter().enumerate() {
            let cert = &c.certificate;
            let (qso_from, qso_to) = cert.qso_dates();
            let (_, valid_to) = cert.validity();
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"id\":{},\"call\":{},\"dxcc\":{},\"entity\":{},\"qso_from\":\"{qso_from}\",\"qso_to\":\"{qso_to}\",\
                 \"expires\":\"{}\",\"has_key\":{},\"in_force\":{}}}",
                json_str(&c.id),
                json_str(cert.callsign()),
                cert.dxcc(),
                json_str(station::dxcc_name(cert.dxcc()).unwrap_or("")),
                day(valid_to),
                c.key_name.is_some(),
                cert.is_valid_at(env.now)
            );
        }
        s.push_str("],\"requests\":[");
        for (i, r) in pending.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"id\":{},\"call\":{},\"dxcc\":{},\"created\":\"{}\"}}",
                json_str(&r.id),
                json_str(&r.callsign),
                r.dxcc,
                day(UNIX_EPOCH + std::time::Duration::from_secs(r.created_at))
            );
        }
        s.push_str("]}");
        let _ = writeln!(env.out, "{s}");
        return Ok(Exit::Success);
    }
    if certs.is_empty() && pending.is_empty() {
        let _ = writeln!(
            env.out,
            "You have no certificates yet. qg-trust import brings them from a TQSL backup (.tbk) or a \
             .p12; qg-trust cert request asks ARRL for one."
        );
        return Ok(Exit::Success);
    }
    for c in &certs {
        let cert = &c.certificate;
        let (qso_from, qso_to) = cert.qso_dates();
        let (_, valid_to) = cert.validity();
        let state = match days_left(&c.id) {
            Some(d) if d < 0 => "EXPIRED: renew with qg-trust cert renew".to_string(),
            Some(d) => format!(
                "expires in {d} day{}: renew with qg-trust cert renew",
                plural(d.unsigned_abs() as usize)
            ),
            None => format!("valid until {}", day(valid_to)),
        };
        let _ = writeln!(
            env.out,
            "{}  {:<10} {}  QSOs {qso_from} to {qso_to}  {state}{}",
            short(&c.id),
            cert.callsign(),
            entity(cert.dxcc()),
            if c.key_name.is_some() {
                ""
            } else {
                "  (no key: cannot sign)"
            }
        );
    }
    for r in &pending {
        let _ = writeln!(
            env.out,
            "{}  {:<10} {}  request sent {}, waiting for ARRL's .tq6: qg-trust import it",
            short(&r.id),
            r.callsign,
            entity(r.dxcc),
            day(UNIX_EPOCH + std::time::Duration::from_secs(r.created_at))
        );
    }
    Ok(Exit::Success)
}

fn request_from(
    person: &Person,
    call: &str,
    dxcc: u32,
    from: Date,
    to: Option<Date>,
    kind: Kind,
) -> CertificateRequest {
    CertificateRequest {
        callsign: call.trim().to_ascii_uppercase(),
        dxcc,
        qso_not_before: from,
        qso_not_after: to,
        name: person.name.clone(),
        address1: person.address.clone(),
        address2: person.address2.clone(),
        city: person.city.clone(),
        state: person.state.clone(),
        postal_code: person.postcode.clone(),
        country: person.country.clone(),
        email: person.email.clone(),
        provider: String::new(),
        provider_unit: String::new(),
        kind: match kind {
            Kind::Personal => CallKind::Personal,
            Kind::Club => CallKind::Club,
            Kind::Dxpedition => CallKind::Dxpedition,
            Kind::SpecialEvent => CallKind::SpecialEvent,
            Kind::Former => CallKind::Former,
            Kind::Replacing => CallKind::Replacing,
            Kind::QslManager => CallKind::QslManager,
        },
    }
}

fn cert_request(store: &Store, a: &RequestArgs, env: &mut Env<'_>) -> Done {
    if let Err(e) = check_output(&a.output) {
        env.message(Tone::Error, format_args!("{e}"));
        return Err(Exit::OutputError);
    }
    if !a.force && a.output.exists() {
        env.message(
            Tone::Error,
            format_args!(
                "{} is there already; --force replaces it",
                a.output.display()
            ),
        );
        return Err(Exit::OutputError);
    }
    let request = request_from(&a.person, &a.call, a.dxcc, a.begin, a.end, a.kind);
    let generated = match &a.signed_by {
        None => request.generate(Authorization::New),
        Some(by) => {
            let certs = store
                .certificates()
                .map_err(|e| store_error(env, "the certificates", &e))?;
            let Some(signer) = cert_by(&certs, by, env.now) else {
                env.message(Tone::Error, format_args!("no certificate in force with a key matches {by:?}; qg-trust cert list shows them"));
                return Err(Exit::CommandError);
            };
            store
                .with_key(&signer.id, |key| {
                    request.generate(Authorization::Additional {
                        certificate: &signer.certificate,
                        key,
                    })
                })
                .map_err(|e| store_error(env, "the signing certificate's key", &e))?
        }
    };
    finish_request(store, generated, &a.output, a.force, &request.callsign, env)
}

fn cert_renew(store: &Store, a: &RenewArgs, env: &mut Env<'_>) -> Done {
    if let Err(e) = check_output(&a.output) {
        env.message(Tone::Error, format_args!("{e}"));
        return Err(Exit::OutputError);
    }
    if !a.force && a.output.exists() {
        env.message(
            Tone::Error,
            format_args!(
                "{} is there already; --force replaces it",
                a.output.display()
            ),
        );
        return Err(Exit::OutputError);
    }
    let certs = store
        .certificates()
        .map_err(|e| store_error(env, "the certificates", &e))?;
    // A certificate past its end can still be renewed: pick by ID, or the newest for the call.
    let found = by_id(&certs, &a.cert, |c| &c.id).or_else(|| {
        certs
            .iter()
            .filter(|c| {
                c.key_name.is_some() && c.certificate.callsign().eq_ignore_ascii_case(&a.cert)
            })
            .max_by_key(|c| c.certificate.validity().1)
    });
    let Some(found) = found else {
        env.message(
            Tone::Error,
            format_args!(
                "no certificate with a key matches {:?}; qg-trust cert list shows them",
                a.cert
            ),
        );
        return Err(Exit::CommandError);
    };
    let cert: &Certificate = &found.certificate;
    // Renewal asks for the QSO dates this certificate has, unless told otherwise.
    let (from, to) = cert.qso_dates();
    let end = if a.no_end_date {
        None
    } else {
        Some(a.end.unwrap_or(to))
    };
    let request = request_from(
        &a.person,
        cert.callsign(),
        cert.dxcc(),
        from,
        end,
        Kind::Personal,
    );
    let generated = store
        .with_key(&found.id, |key| {
            request.generate(Authorization::Renewal {
                certificate: cert,
                key,
            })
        })
        .map_err(|e| store_error(env, "the certificate's key", &e))?;
    finish_request(store, generated, &a.output, a.force, cert.callsign(), env)
}

fn finish_request(
    store: &Store,
    generated: Result<
        qso_graph_trust::request::GeneratedRequest,
        qso_graph_trust::request::RequestError,
    >,
    output: &Path,
    force: bool,
    call: &str,
    env: &mut Env<'_>,
) -> Done {
    let generated = match generated {
        Ok(g) => g,
        Err(e) => {
            env.message(Tone::Error, format_args!("the request: {e}"));
            return Err(Exit::CommandError);
        }
    };
    // The key is in the store before the .tq5 exists, so ARRL's answer always has its key.
    let id = store
        .store_request(&generated)
        .map_err(|e| store_error(env, "the request's key", &e))?;
    if let Err(e) = write_new(output, generated.tq5().as_bytes(), force) {
        env.message(Tone::Error, format_args!("{}: {e}", output.display()));
        env.message(
            Tone::Warning,
            format_args!(
                "the request's key is kept ({}); qg-trust cert abandon {} removes it",
                short(&id),
                short(&id)
            ),
        );
        return Err(Exit::OutputError);
    }
    let _ = writeln!(
        env.out,
        "Request for {call} written to {}.",
        output.display()
    );
    let _ = writeln!(
        env.out,
        "Next: upload it at https://lotw.arrl.org/lotw/load-cert. When ARRL emails the .tq6, \
         qg-trust import it."
    );
    Ok(Exit::Success)
}

// ---- Station locations ----

fn location(l: Location, env: &mut Env<'_>) -> Done {
    if let Location::Fields(a) = &l {
        let Some(name) = station::dxcc_name(a.dxcc) else {
            env.message(
                Tone::Error,
                format_args!("{} is not a DXCC entity number ARRL lists", a.dxcc),
            );
            return Err(Exit::CommandError);
        };
        let _ = writeln!(env.out, "Fields for {name} ({}):", a.dxcc);
        for f in station::fields_for(a.dxcc) {
            let _ = writeln!(env.out, "  {f}");
        }
        return Ok(Exit::Success);
    }
    let store = open(env)?;
    let locations = store
        .locations()
        .map_err(|e| store_error(env, "the station locations", &e))?;
    let default = store
        .default_location()
        .map_err(|e| store_error(env, "the default station location", &e))?;
    let find = |name: &str| locations.iter().find(|l| l.name == name);
    match l {
        Location::Fields(_) => unreachable!("answered above"),
        Location::Tqsl(a) => tqsl_locations_command(a, store, &locations, env),
        Location::List(a) => {
            if a.json {
                let mut s = String::from("[");
                for (i, l) in locations.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&location_json(
                        &l.name,
                        &l.station,
                        default.as_deref() == Some(&l.name),
                    ));
                }
                s.push(']');
                let _ = writeln!(env.out, "{s}");
            } else if locations.is_empty() {
                let _ = writeln!(
                    env.out,
                    "You have no station locations yet. qg-trust import brings them from a TQSL backup; \
                     qg-trust location add makes one."
                );
            } else {
                // As wide as the longest name, so the columns line up whatever the names.
                let width = locations
                    .iter()
                    .map(|l| l.name.chars().count())
                    .max()
                    .unwrap_or(0)
                    .max(20);
                for l in &locations {
                    let _ = writeln!(
                        env.out,
                        "{:<width$} {:<10} {}{}{}",
                        l.name,
                        l.station.call(),
                        entity(l.station.dxcc()),
                        l.station
                            .get("GRIDSQUARE")
                            .map(|g| format!("  {g}"))
                            .unwrap_or_default(),
                        if default.as_deref() == Some(&l.name) {
                            "  (default)"
                        } else {
                            ""
                        }
                    );
                }
            }
            Ok(Exit::Success)
        }
        Location::Show(a) => {
            let Some(l) = find(&a.name) else {
                return Err(no_location(env, &a.name));
            };
            if a.json {
                let _ = writeln!(
                    env.out,
                    "{}",
                    location_json(&l.name, &l.station, default.as_deref() == Some(&l.name))
                );
            } else {
                let _ = writeln!(
                    env.out,
                    "{}: {} ({}){}",
                    l.name,
                    l.station.call(),
                    entity(l.station.dxcc()),
                    if default.as_deref() == Some(&l.name) {
                        " (default)"
                    } else {
                        ""
                    }
                );
                for (k, v) in l.station.fields() {
                    let _ = writeln!(env.out, "  {k}={v}");
                }
            }
            Ok(Exit::Success)
        }
        Location::Default(a) => {
            if find(&a.name).is_none() {
                let names: Vec<&str> = locations.iter().map(|l| l.name.as_str()).collect();
                env.message(
                    Tone::Error,
                    format_args!(
                        "there is no station location called {:?}; you have: {}",
                        a.name,
                        names.join(", ")
                    ),
                );
                return Err(Exit::CommandError);
            }
            store
                .set_default_location(&a.name)
                .map_err(|e| store_error(env, "the default station location", &e))?;
            let _ = writeln!(env.out, "Default station location: {}", a.name);
            Ok(Exit::Success)
        }
        Location::Add(a) => {
            if find(&a.name).is_some() {
                env.message(Tone::Error, format_args!("there is a location called {:?} already; qg-trust location edit changes it", a.name));
                return Err(Exit::CommandError);
            }
            let mut fields = vec![
                ("CALL".to_string(), a.call.trim().to_ascii_uppercase()),
                ("DXCC".to_string(), a.dxcc.to_string()),
            ];
            if let Some(g) = &a.grid {
                fields.push(("GRIDSQUARE".to_string(), g.clone()));
            }
            fields.extend(
                a.fields
                    .iter()
                    .map(|(k, v)| (k.to_ascii_uppercase(), v.clone())),
            );
            let station = make_station(&fields, env)?;
            store
                .add_location(&a.name, &station)
                .map_err(|e| store_error(env, &a.name, &e))?;
            let _ = writeln!(
                env.out,
                "Added {}: {} ({}).",
                a.name,
                station.call(),
                entity(station.dxcc())
            );
            Ok(Exit::Success)
        }
        Location::Edit(a) => {
            let Some(l) = find(&a.name) else {
                return Err(no_location(env, &a.name));
            };
            let mut fields: Vec<(String, String)> = l
                .station
                .fields()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut set = |name: &str, value: &str| {
                fields.retain(|(k, _)| k != name);
                if !value.is_empty() {
                    fields.push((name.to_string(), value.to_string()));
                }
            };
            if let Some(c) = &a.call {
                set("CALL", &c.trim().to_ascii_uppercase());
            }
            if let Some(g) = &a.grid {
                set("GRIDSQUARE", g);
            }
            for (k, v) in &a.fields {
                set(&k.to_ascii_uppercase(), v);
            }
            let station = make_station(&fields, env)?;
            store
                .replace_location(&a.name, &station)
                .map_err(|e| store_error(env, &a.name, &e))?;
            let _ = writeln!(env.out, "Changed {}.", a.name);
            Ok(Exit::Success)
        }
        Location::Delete(a) => {
            if find(&a.name).is_none() {
                return Err(no_location(env, &a.name));
            }
            if !a.force {
                env.message(
                    Tone::Error,
                    format_args!("give --force to delete {:?}", a.name),
                );
                return Err(Exit::CommandError);
            }
            store
                .delete_location(&a.name)
                .map_err(|e| store_error(env, &a.name, &e))?;
            let _ = writeln!(env.out, "Deleted {}.", a.name);
            Ok(Exit::Success)
        }
    }
}

fn tqsl_locations_command(
    a: TqslLocationArgs,
    store: &Store,
    stored: &[qso_graph_trust::store::StoredLocation],
    env: &mut Env<'_>,
) -> Done {
    use tqsl_locations::Status;
    let folder = a.folder.unwrap_or_else(tqsl_locations::default_folder);
    let locations = tqsl_locations::read(&folder).map_err(|e| {
        env.message(Tone::Error, format_args!("{e}"));
        Exit::CommandError
    })?;
    let statuses: Vec<_> = locations
        .iter()
        .map(|l| tqsl_locations::compare(l, stored))
        .collect();
    for name in &a.add {
        if !locations
            .iter()
            .zip(&statuses)
            .any(|(l, s)| &l.name == name && *s == Status::New)
        {
            env.message(
                Tone::Error,
                format_args!("{name:?} is not a new TQSL station location"),
            );
            return Err(Exit::CommandError);
        }
    }
    if a.json {
        let mut out = String::from("[");
        for (index, (l, status)) in locations.iter().zip(&statuses).enumerate() {
            if index != 0 {
                out.push(',');
            }
            let (label, detail) = match status {
                Status::New => ("new", String::new()),
                Status::Same => ("same", String::new()),
                Status::Refused(reason) => ("refused", format!(",\"reason\":{}", json_str(reason))),
                Status::Differs(diffs) => {
                    let fields = diffs
                        .iter()
                        .map(|d| {
                            format!(
                                "{{\"field\":{},\"tqsl\":{},\"stored\":{}}}",
                                json_str(&d.field),
                                d.tqsl.as_deref().map_or_else(|| "null".into(), json_str),
                                d.stored.as_deref().map_or_else(|| "null".into(), json_str)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    ("differs", format!(",\"differences\":[{fields}]"))
                }
            };
            let _ = write!(
                out,
                "{{\"name\":{},\"status\":{}{}}}",
                json_str(&l.name),
                json_str(label),
                detail
            );
        }
        out.push(']');
        let _ = writeln!(env.out, "{out}");
    } else if locations.is_empty() {
        let _ = writeln!(env.out, "TQSL has no station locations here.");
    } else {
        for (l, status) in locations.iter().zip(&statuses) {
            match status {
                Status::New => {
                    let _ = writeln!(env.out, "{}: new", l.name);
                }
                Status::Same => {
                    let _ = writeln!(env.out, "{}: same", l.name);
                }
                Status::Refused(reason) => {
                    let _ = writeln!(env.out, "{}: refused: {reason}", l.name);
                }
                Status::Differs(diffs) => {
                    let _ = writeln!(env.out, "{}: differs", l.name);
                    for d in diffs {
                        let _ = writeln!(
                            env.out,
                            "  {}: TQSL {:?}, stored {:?}",
                            d.field, d.tqsl, d.stored
                        );
                    }
                }
            }
        }
    }
    for (l, status) in locations.iter().zip(&statuses) {
        if *status == Status::New
            && (a.all || a.add.contains(&l.name))
            && let Ok(station) = &l.station
        {
            store
                .add_location(&l.name, station)
                .map_err(|e| store_error(env, "the station location", &e))?;
            if !a.json {
                let _ = writeln!(env.out, "Added {}.", l.name);
            }
        }
    }
    Ok(Exit::Success)
}

fn make_station(fields: &[(String, String)], env: &mut Env<'_>) -> Result<StationLocation, Exit> {
    let given: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    StationLocation::new(&given).map_err(|e| {
        env.message(Tone::Error, format_args!("{e}"));
        if let Some(dxcc) = given
            .iter()
            .find(|(k, _)| *k == "DXCC")
            .and_then(|(_, v)| v.parse::<u32>().ok())
            && station::dxcc_name(dxcc).is_some()
        {
            env.message(
                Tone::Warning,
                format_args!("qg-trust location fields {dxcc} lists the fields it takes"),
            );
        }
        Exit::CommandError
    })
}

fn no_location(env: &mut Env<'_>, name: &str) -> Exit {
    env.message(
        Tone::Error,
        format_args!(
            "there is no station location called {name:?}; qg-trust location list shows them"
        ),
    );
    Exit::CommandError
}

fn location_json(name: &str, station: &StationLocation, default: bool) -> String {
    let mut s = format!(
        "{{\"name\":{},\"default\":{},\"fields\":{{",
        json_str(name),
        default
    );
    for (i, (k, v)) in station.fields().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{}:{}", json_str(k), json_str(v));
    }
    s.push_str("}}");
    s
}

// ---- Small helpers ----

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// "United States (291)", or the number alone for one ARRL does not list.
fn entity(dxcc: u32) -> String {
    match station::dxcc_name(dxcc) {
        Some(name) => format!("{name} ({dxcc})"),
        None => format!("DXCC {dxcc}"),
    }
}

/// The short ID the lists show: the first eight characters after the kind.
fn short(id: &str) -> &str {
    let rest = id.split_once(':').map_or(id, |(_, r)| r);
    rest.get(..8).unwrap_or(rest)
}

/// A UTC calendar date, YYYY-MM-DD.
fn day(t: SystemTime) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = secs.div_euclid(86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A new file, refused if it is there unless `force`; written beside it, then renamed.
fn write_new(path: &Path, bytes: &[u8], force: bool) -> std::io::Result<()> {
    use std::io::Write as _;
    if force {
        return crate::cli::write_whole(path, bytes);
    }
    // Made new or not at all: an existing file, or a link, is never written through.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                std::io::Error::other("it is there already; --force replaces it")
            }
            _ => e,
        })?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    written
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Prepare a signed log for LoTW and interpret its answer. Nothing here opens a connection,
//! reads configuration, or performs file I/O. The caller supplies its own HTTP/TLS transport
//! (Desktop uses its credential core), always verifies the server certificate and hostname,
//! sets a finite timeout, refuses redirects to another host or to HTTP, and never takes proxy
//! settings from a file. TLS verification must remain enabled on every attempt.
//!
//! Send [`UploadRequest::body`] unchanged, with the supplied method, URL and headers. Bound the
//! response while receiving it to [`MAX_RESPONSE_BYTES`], then call [`parse_response`]. A transport
//! failure is not an HTTP response and must be reported by the caller. An unknown answer does
//! not establish whether LoTW received the log; automatic retries can submit it twice.
//!
//! Protocol source: TQSL 2.8.7, `apps/tqsl_prefs.h:68–73`, `apps/tqsl.cpp:2933–2943,
//! 3156–3161, 3214–3273`, and `apps/tqslapp.h:78–82`. The provider website in tqsllib's
//! `config.xml` (`providers/provider/url`) is not the upload endpoint. QGT fixes the endpoint
//! here; neither an imported backup nor a caller can override it on a request.

use std::time::{SystemTime, UNIX_EPOCH};

use qso_graph_trust_awslc::{Error, random};

use crate::lotw;
use x509_cert::der::DateTime;

/// LoTW's HTTPS upload endpoint, TQSL 2.8.7's `DEFAULT_UPL_URL` (`apps/tqsl_prefs.h:68`).
pub const UPLOAD_URL: &str = "https://lotw.arrl.org/lotw/upload";

/// Maximum response size in bytes (1 MiB), checked before decoding or searching for markers.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum returned LoTW message size in UTF-8 bytes, after removing control characters.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// Why bytes are not a signed log to upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotASignedLog;

impl std::fmt::Display for NotASignedLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a signed log (.tq8)")
    }
}

impl std::error::Error for NotASignedLog {}

/// The largest signed log, decompressed, that [`check_signed_log`] reads.
pub const MAX_SIGNED_LOG_BYTES: usize = 64 * 1024 * 1024;

/// Check, before anything is sent, that `tq8` is a signed log and nothing else, as QG Trust and
/// TQSL write one: gzip of a `TQSL_IDENT` line, then `tCERT`, `tSTATION` and `tCONTACT` records
/// only, each of only the fields its kind has, with nothing between them but white space; at least
/// one QSO; every certificate an X.509 certificate; every other value printable text within its
/// bound and every signature the size a LoTW key makes. A TQSL backup (gzip too, holding private
/// keys) or any other file is refused. [`UploadRequest`] does not check its input; call this first,
/// and upload what it returns: the checked log, gzipped afresh, so nothing the check did not read
/// (gzip's name, comment and extra fields, or data after the stream) can be sent with it.
/// Bounded by [`MAX_SIGNED_LOG_BYTES`] only, so whatever QG Trust signs passes.
pub fn check_signed_log(tq8: &[u8]) -> Result<Vec<u8>, NotASignedLog> {
    let tq7 = crate::gzip::decompress(tq8, MAX_SIGNED_LOG_BYTES).map_err(|_| NotASignedLog)?;
    let mut fields = Fields { text: &tq7, at: 0 };
    match fields.next()? {
        Some(Token::Field("TQSL_IDENT", v)) if printable(v, 256) => {}
        _ => return Err(NotASignedLog),
    }
    let (mut certs, mut contacts) = (0usize, 0usize);
    let mut stations: std::collections::HashMap<&[u8], Record<'_>> = Default::default();
    let mut record: Option<(Kind, Record<'_>)> = None;
    while let Some(token) = fields.next()? {
        match (&mut record, token) {
            (None, Token::Field(name, value)) if name.eq_ignore_ascii_case("Rec_Type") => {
                let kind = match value {
                    b"tCERT" => Kind::Cert,
                    b"tSTATION" => Kind::Station,
                    b"tCONTACT" => Kind::Contact,
                    _ => return Err(NotASignedLog),
                };
                record = Some((kind, Vec::new()));
            }
            (Some((kind, got)), Token::Field(name, value)) => {
                if !allowed(*kind, name, value) || got.iter().any(|(n, _)| *n == name) {
                    return Err(NotASignedLog);
                }
                got.push((name, value));
            }
            (Some(_), Token::End) => {
                let Some((kind, got)) = record.take() else {
                    return Err(NotASignedLog);
                };
                let get = |n: &str| got.iter().find(|(f, _)| *f == n).map(|(_, v)| *v);
                match kind {
                    Kind::Cert => {
                        get("CERTIFICATE").ok_or(NotASignedLog)?;
                        certs += 1;
                    }
                    Kind::Station => {
                        let uid = get("STATION_UID").ok_or(NotASignedLog)?;
                        stations.insert(uid, got);
                    }
                    Kind::Contact => {
                        // Before any QSO, a certificate that signs it.
                        if certs == 0 || get(lotw::SIGNATURE_FIELD).is_none() {
                            return Err(NotASignedLog);
                        }
                        let station = get("STATION_UID")
                            .and_then(|uid| stations.get(uid))
                            .ok_or(NotASignedLog)?;
                        // What was signed is exactly this QSO's and its station's fields, in
                        // ARRL's order, as the signer builds it: nothing else can be carried here.
                        let mut expected = Vec::new();
                        for name in lotw::SIGN_STATION {
                            if let Some((_, v)) = station.iter().find(|(f, _)| f == name) {
                                expected.extend_from_slice(v);
                            }
                        }
                        for (name, _) in lotw::SIGN_CONTACT {
                            expected.extend_from_slice(get(name).unwrap_or_default());
                        }
                        expected.make_ascii_uppercase();
                        if get("SIGNDATA") != Some(expected.as_slice()) {
                            return Err(NotASignedLog);
                        }
                        contacts += 1;
                    }
                }
            }
            _ => return Err(NotASignedLog),
        }
    }
    if record.is_some() || contacts == 0 {
        return Err(NotASignedLog);
    }
    Ok(crate::signed_log::tq8(&tq7))
}

/// One record's fields, by name, in the order given.
type Record<'a> = Vec<(&'a str, &'a [u8])>;

#[derive(Clone, Copy)]
enum Kind {
    Cert,
    Station,
    Contact,
}

enum Token<'a> {
    /// A field's name (with any data type after a second colon dropped) and value.
    Field(&'a str, &'a [u8]),
    /// `<eor>`.
    End,
}

/// The fields of a `.tq7`, strictly: `<NAME:LEN>` or `<NAME:LEN:TYPE>` and exactly LEN bytes, or
/// `<eor>`, with only white space between. Anything else is an error.
struct Fields<'a> {
    text: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn next(&mut self) -> Result<Option<Token<'a>>, NotASignedLog> {
        while self.text.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
        if self.at == self.text.len() {
            return Ok(None);
        }
        if self.text[self.at] != b'<' {
            return Err(NotASignedLog);
        }
        let close = self.text[self.at..]
            .iter()
            .take(80)
            .position(|&b| b == b'>')
            .ok_or(NotASignedLog)?;
        let tag = std::str::from_utf8(&self.text[self.at + 1..self.at + close])
            .map_err(|_| NotASignedLog)?;
        self.at += close + 1;
        if tag.eq_ignore_ascii_case("eor") {
            return Ok(Some(Token::End));
        }
        let mut parts = tag.split(':');
        let name = parts.next().filter(|n| {
            !n.is_empty()
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        });
        let len = parts.next().and_then(|l| l.parse::<usize>().ok());
        let typed = parts.next();
        let (Some(name), Some(len), None) = (name, len, parts.next()) else {
            return Err(NotASignedLog);
        };
        if typed.is_some_and(|t| t.is_empty() || !t.bytes().all(|b| b.is_ascii_alphanumeric())) {
            return Err(NotASignedLog);
        }
        let end = self
            .at
            .checked_add(len)
            .filter(|&e| e <= self.text.len())
            .ok_or(NotASignedLog)?;
        let value = &self.text[self.at..end];
        self.at = end;
        Ok(Some(Token::Field(name, value)))
    }
}

/// Text with no control characters but the line breaks base64 holds, at most `max` bytes. UTF-8,
/// not only ASCII: a call need not be ASCII when bad calls are allowed.
fn printable(value: &[u8], max: usize) -> bool {
    value.len() <= max
        && std::str::from_utf8(value)
            .is_ok_and(|t| t.chars().all(|c| !c.is_control() || c == '\n' || c == '\r'))
}

const CONTACT_FIELDS: &[&str] = &[
    "STATION_UID",
    "CALL",
    "BAND",
    "MODE",
    "FREQ",
    "FREQ_RX",
    "PROP_MODE",
    "SAT_NAME",
    "BAND_RX",
    "QSO_DATE",
    "QSO_TIME",
    "SIGNDATA",
];

fn allowed(kind: Kind, name: &str, value: &[u8]) -> bool {
    match kind {
        Kind::Cert => match name {
            "CERT_UID" => value.len() <= 10 && value.iter().all(u8::is_ascii_digit),
            "CERTIFICATE" => {
                printable(value, 8 * 1024)
                    && std::str::from_utf8(value).is_ok_and(|b64| {
                        let pem = format!(
                            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                            b64.trim()
                        );
                        crate::certificate::Certificate::from_pem_or_der(pem.as_bytes()).is_ok()
                    })
            }
            _ => false,
        },
        Kind::Station => match name {
            "STATION_UID" | "CERT_UID" => value.len() <= 10 && value.iter().all(u8::is_ascii_digit),
            _ => lotw::loc_field(name).is_some() && printable(value, crate::station::MAX_LEN),
        },
        Kind::Contact => {
            if name == lotw::SIGNATURE_FIELD {
                // An RSA-1024 signature in TQSL's base64: 172 characters and its line break.
                value.len() <= 180 && printable(value, 180)
            } else if name == "SIGNDATA" {
                printable(value, 1024)
            } else {
                CONTACT_FIELDS.contains(&name) && printable(value, 128)
            }
        }
    }
}

/// An immutable multipart POST of already-signed `.tq8` bytes. No transport or I/O methods.
/// Constructing this neither validates nor changes the signed log.
pub struct UploadRequest {
    headers: [(&'static str, String); 2],
    body: Vec<u8>,
}

impl UploadRequest {
    /// Prepare a log with a fresh random multipart boundary, checked absent from the payload.
    /// The `upfile` part has type `application/octet-stream`, as in TQSL's curl MIME post.
    /// Its filename follows TQSL's `<TQSLUpl YYYYMMDD-HHMM> basename.tq8` UTC format, with `log.tq8`
    /// as the basename; [`Self::try_named`] names the file. No path is read or disclosed.
    /// An unrepresentable system clock uses the Unix epoch for the filename timestamp.
    ///
    /// # Panics
    /// Panics if the binding cannot obtain random bytes. Use [`Self::try_new`] to handle this.
    pub fn new(tq8: &[u8]) -> Self {
        Self::try_new(tq8).expect("could not generate an upload boundary")
    }

    /// Fallible form of [`Self::new`]; returns the binding's randomness error without a request.
    pub fn try_new(tq8: &[u8]) -> Result<Self, Error> {
        Self::try_named(tq8, "log.tq8")
    }

    /// [`Self::try_new`], with `basename` as the file's name in TQSL's filename format, so LoTW's
    /// activity list tells uploads apart. Only the name is sent, never a folder: it is cut at the
    /// last `/` or `\`, every character but ASCII letters, digits, `.`, `-` and `_` becomes `_`,
    /// it is cut to 64 characters, and `.tq8` is added unless it ends so. An empty name is `log.tq8`.
    pub fn try_named(tq8: &[u8], basename: &str) -> Result<Self, Error> {
        let boundary = boundary_with(tq8, random)?;
        let filename = filename(SystemTime::now(), &upload_name(basename));
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"upfile\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).into_bytes();
        body.extend_from_slice(tq8);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        Ok(Self {
            headers: [
                (
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                ),
                ("User-Agent", format!("QSO Graph Trust/{}", crate::VERSION)),
            ],
            body,
        })
    }

    /// HTTP method: always `POST`.
    pub fn method(&self) -> &'static str {
        "POST"
    }

    /// Fixed HTTPS destination: always [`UPLOAD_URL`].
    pub fn url(&self) -> &'static str {
        UPLOAD_URL
    }

    /// Content-Type (including the boundary) and truthful QG Trust User-Agent.
    pub fn headers(&self) -> &[(&'static str, String)] {
        &self.headers
    }

    /// Complete multipart body; transmit these bytes without text conversion or recompression.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

fn boundary_with(
    tq8: &[u8],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<String, Error> {
    loop {
        let mut bytes = [0; 16];
        fill(&mut bytes)?;
        let mut boundary = String::from("qgt-");
        for byte in bytes {
            use std::fmt::Write;
            write!(boundary, "{byte:02x}").expect("write to String");
        }
        if !tq8
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
        {
            return Ok(boundary);
        }
    }
}

/// A basename as [`UploadRequest::try_named`] sends it.
fn upload_name(basename: &str) -> String {
    let name = basename.rsplit(['/', '\\']).next().unwrap_or("");
    let mut name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if name.trim_matches(['.', '_']).is_empty() {
        name = "log.tq8".to_string();
    }
    if !name.to_ascii_lowercase().ends_with(".tq8") {
        name.push_str(".tq8");
    }
    name
}

fn filename(now: SystemTime, basename: &str) -> String {
    let date = now
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| DateTime::from_unix_duration(d).ok())
        .unwrap_or(DateTime::from_unix_duration(std::time::Duration::ZERO).expect("Unix epoch"));
    format!(
        "<TQSLUpl {:04}{:02}{:02}-{:02}{:02}> {basename}",
        date.year(),
        date.month(),
        date.day(),
        date.hour(),
        date.minutes()
    )
}

/// LoTW's upload decision. Acceptance means receipt for processing, not QSO confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadOutcome {
    /// The status marker says `accepted` (case-insensitive, surrounding whitespace ignored).
    Accepted {
        /// Optional bounded LoTW message, with control characters removed. Untrusted text;
        /// callers displaying HTML must escape it.
        message: Option<String>,
    },
    /// A recognized status marker has any value other than `accepted`.
    Rejected {
        /// Optional bounded LoTW message, with control characters removed. Untrusted text;
        /// callers displaying HTML must escape it.
        message: Option<String>,
    },
    /// No status match, oversized response, invalid UTF-8 or NUL-containing binary response.
    Unknown,
}

impl UploadOutcome {
    /// Matching TQSL 2.8.7 exit code (`apps/tqslapp.h:78–82`): `TQSL_EXIT_SUCCESS` (0),
    /// `TQSL_EXIT_REJECTED` (2), or `TQSL_EXIT_UNEXP_RESP` (3).
    /// Transport errors (for example `TQSL_EXIT_CONNECTION_FAILED`, 11) belong to the caller.
    pub fn tqsl_exit_code(&self) -> u8 {
        match self {
            Self::Accepted { .. } => 0,
            Self::Rejected { .. } => 2,
            Self::Unknown => 3,
        }
    }
}

/// Interpret TQSL's default `UPL` status and `UPLMESSAGE` comment markers without executing HTML.
/// Like TQSL's upload path (which does not set curl's `FAILONERROR`), a completed HTTP response
/// is classified by its body, independently of `status`; HTTP 200 alone never means accepted.
/// The caller must supply a complete response from a verified TLS connection.
///
/// TQSL's expressions are `<!-- .UPL.\s*([^-]+)\s*-->` and
/// `<!-- .UPLMESSAGE.\s*(.+)\s*-->`. The dots match any single character (normally brackets),
/// marker names are case-sensitive, status cannot contain a hyphen, and the message match is
/// greedy. The first matching status decides; any value other than `accepted` is rejection.
/// The wildcard also lets a standalone `UPLMESSAGE` comment match the status expression,
/// yielding rejection, as in TQSL.
/// Certificate-request-specific message checks in TQSL do not apply to signed-log uploads.
/// Bodies exceeding [`MAX_RESPONSE_BYTES`] are refused before scanning. Messages are trimmed,
/// stripped of Unicode control characters, and truncated at a UTF-8 boundary.
pub fn parse_response(_status: u16, body: &[u8]) -> UploadOutcome {
    if body.len() > MAX_RESPONSE_BYTES {
        return UploadOutcome::Unknown;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return UploadOutcome::Unknown;
    };
    if text.contains('\0') {
        return UploadOutcome::Unknown;
    }
    let Some(status) = capture(text, "UPL", false) else {
        return UploadOutcome::Unknown;
    };
    let message = capture(text, "UPLMESSAGE", true).map(clean_message);
    if status.trim().eq_ignore_ascii_case("accepted") {
        UploadOutcome::Accepted { message }
    } else {
        UploadOutcome::Rejected { message }
    }
}

// Implement the two fixed TQSL expressions without a regex dependency. Status stops at the
// first hyphen; message uses the last closing delimiter, matching POSIX's greedy .+.
fn capture<'a>(text: &'a str, marker: &str, message: bool) -> Option<&'a str> {
    // Compute the greedy message endpoint once, even for many unterminated markers.
    let last_close = if message { text.rfind("-->") } else { None };
    for (start, _) in text.match_indices("<!-- ") {
        let mut chars = text[start + 5..].chars();
        chars.next(); // First wildcard.
        let Some(tail) = chars.as_str().strip_prefix(marker) else {
            continue;
        };
        let mut chars = tail.chars();
        if chars.next().is_none() {
            // Second wildcard.
            continue;
        }
        let value = chars.as_str();
        let end = if message {
            last_close.and_then(|end| end.checked_sub(text.len() - value.len()))
        } else {
            value.find('-')
        };
        if let Some(end) = end
            && end > 0
            && value[end..].starts_with("-->")
        {
            return Some(&value[..end]);
        }
    }
    None
}

fn clean_message(raw: &str) -> String {
    let mut result = String::new();
    for ch in raw.trim().chars().filter(|c| !c.is_control()) {
        if result.len() + ch.len_utf8() > MAX_MESSAGE_BYTES {
            break;
        }
        result.push(ch);
    }
    result
}

#[cfg(test)]
mod tests;

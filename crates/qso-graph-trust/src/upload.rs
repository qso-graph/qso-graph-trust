// SPDX-License-Identifier: GPL-3.0-only
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

/// Check, before anything is sent, that `tq8` is a signed log and nothing else: gzip holding only
/// TQSL's signed-log records (`tCERT`, `tSTATION`, `tCONTACT`), with at least one QSO. A TQSL
/// backup, which is gzip too and holds private keys, or any other file is refused.
/// [`UploadRequest`] does not check its input; call this first.
pub fn check_signed_log(tq8: &[u8]) -> Result<(), NotASignedLog> {
    let tq7 = crate::gzip::decompress(tq8, MAX_SIGNED_LOG_BYTES).map_err(|_| NotASignedLog)?;
    let records = crate::records::parse(&tq7).map_err(|_| NotASignedLog)?;
    let mut contacts = 0usize;
    for record in &records {
        match record.get("REC_TYPE") {
            Some(b"tCONTACT") => contacts += 1,
            Some(b"tCERT" | b"tSTATION") => {}
            _ => return Err(NotASignedLog),
        }
    }
    if contacts == 0 {
        return Err(NotASignedLog);
    }
    Ok(())
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
    /// Its filename follows TQSL's `<TQSLUpl YYYYMMDD-HHMM> basename.tq8` UTC format;
    /// this byte-only API uses `log.tq8` as its basename. No path is read or disclosed.
    /// An unrepresentable system clock uses the Unix epoch for the filename timestamp.
    ///
    /// # Panics
    /// Panics if the binding cannot obtain random bytes. Use [`Self::try_new`] to handle this.
    pub fn new(tq8: &[u8]) -> Self {
        Self::try_new(tq8).expect("could not generate an upload boundary")
    }

    /// Fallible form of [`Self::new`]; returns the binding's randomness error without a request.
    pub fn try_new(tq8: &[u8]) -> Result<Self, Error> {
        let boundary = boundary_with(tq8, random)?;
        let filename = filename(SystemTime::now());
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

fn filename(now: SystemTime) -> String {
    let date = now
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| DateTime::from_unix_duration(d).ok())
        .unwrap_or(DateTime::from_unix_duration(std::time::Duration::ZERO).expect("Unix epoch"));
    format!(
        "<TQSLUpl {:04}{:02}{:02}-{:02}{:02}> log.tq8",
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

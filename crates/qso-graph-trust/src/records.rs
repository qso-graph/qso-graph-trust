// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! tqsllib's record format: fields written as `<NAME:LENGTH>VALUE` or `<NAME:LENGTH:TYPE>VALUE`, the
//! value exactly LENGTH bytes, and records ended by `<eor>`. Key files (`keys/<call>`) and signed
//! logs (`.tq7`, and `.tq8` once decompressed) are written this way, as ADIF is.
//!
//! This reads untrusted input. Every length is checked against the bytes actually present, a name
//! must be a plain identifier, and a field or record past the stated limits is refused, never cut.
//! A value can be a private key, so every value is wiped from memory when it is dropped.

use std::fmt;

use zeroize::Zeroizing;

/// The longest value accepted: larger than any key, certificate or signature tqsllib writes.
pub const MAX_VALUE_LEN: usize = 64 * 1024;
/// The longest tag accepted, `<` and `>` aside: the longest tqsllib writes is far shorter, and no
/// name or type is allocated before this is checked (found in review).
pub const MAX_TAG_LEN: usize = 64;
/// The most fields in one record.
pub const MAX_FIELDS: usize = 256;
/// The most records in one input: a signed log of 100,000 QSOs, plus its header records.
pub const MAX_RECORDS: usize = 100_010;
/// The most fields in all records together, so input made of many tiny records cannot make memory
/// grow without bound (found in review): 20 for each of [`MAX_RECORDS`].
pub const MAX_TOTAL_FIELDS: usize = 20 * MAX_RECORDS;

/// One field: its name as written, its type letter if it has one, and its value's bytes, wiped
/// when dropped.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Field {
    /// The field's name, as written.
    pub(crate) name: String,
    /// The field's type letter, if it has one.
    pub(crate) kind: Option<String>,
    /// The value's bytes, wiped when dropped.
    pub(crate) value: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Field {
    // A field can hold a key, so its value is never printed: only its name and length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// One record: its fields in the order written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// The fields, in the order written.
    pub(crate) fields: Vec<Field>,
    /// Physical Cabrillo line, when this record came from Cabrillo.
    pub(crate) source_line: Option<usize>,
}

impl Record {
    /// The one-based physical source line for a Cabrillo QSO; absent for ADIF records.
    pub fn source_line(&self) -> Option<usize> {
        self.source_line
    }

    /// A content-free, line-numbered refusal if a Cabrillo record cannot become a signing QSO.
    /// Callers must refuse the whole Cabrillo log on conversion failure, before writing output.
    pub fn cabrillo_conversion_error(&self) -> Option<RecordError> {
        self.source_line.map(|line| RecordError::Cabrillo {
            line,
            problem: CabrilloError::QsoConversion,
        })
    }

    /// The first field with this name, compared without regard to case, as tqsllib compares them.
    /// The value is returned as the input gave it: parse logs with this, never key material.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value.as_slice())
    }

    /// The first field with this name, as UTF-8 text.
    pub fn text(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| std::str::from_utf8(v).ok())
    }
}

/// A fixed Cabrillo refusal reason. Contains positions only, never input text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CabrilloError {
    /// Input must be at most 67108864 bytes.
    InputLimit,
    /// Log must have at most 200020 lines, each at most 65536 bytes.
    LineLimit,
    /// Header text must be UTF-8.
    Encoding,
    /// END-OF-LOG must be the last nonempty line.
    AfterEnd,
    /// Each header or QSO line must have a tag followed by a colon.
    Separator,
    /// Tags must contain only ASCII letters, digits, or hyphens, at most 64 bytes.
    Tag,
    /// Header values must be at most 65536 bytes.
    ValueLimit,
    /// START-OF-LOG must be 2.0 or 3.0 and precede all headers and QSOs.
    Start,
    /// START-OF-LOG must appear only once.
    RepeatedStart,
    /// END-OF-LOG must have an empty value.
    End,
    /// CONTEST must appear once, before every QSO.
    ContestOrder,
    /// CONTEST must contain 1 to 32 ASCII letters, digits, or hyphens.
    Contest,
    /// QSO must follow CONTEST.
    BeforeContest,
    /// Log must contain at most 100010 QSOs.
    RecordLimit,
    /// Log must emit at most 2000200 ADIF fields.
    FieldLimit,
    /// Log must begin with START-OF-LOG: 2.0 or 3.0.
    MissingStart,
    /// Log must have one CONTEST header before its QSOs.
    MissingContest,
    /// Log must end with an empty END-OF-LOG:.
    MissingEnd,
    /// QSO must have at most 256 fields, each at most 64 bytes.
    QsoFields,
    /// QSO must contain frequency, mode, UTC date, UTC time, sent call, and sent and received exchanges.
    IncompleteQso,
    /// Received exchange must have one call candidate: letters, digits, or slash, at least four letters or digits including one of each, excluding four-character locators.
    NoCall,
    /// Received exchange must have exactly one call candidate; remove ambiguity or use an ADIF Contest_ID with a documented exchange.
    AmbiguousCall,
    /// Received-call field must match the guessed ADIF Contest_ID exchange; correct the exchange or supply ADIF.
    GuessedCall,
    /// QSO must include the received-call field required by the contest exchange.
    MissingCall,
    /// QSO sent and received calls must contain only ASCII letters, digits, or slash.
    Call,
    /// QSO date must be a valid UTC YYYY-MM-DD and time must be a valid UTC HHMM.
    DateTime,
    /// QSO mode must be one of CW, PH, FM, RY, DG.
    Mode,
    /// QSO frequency must be numeric kHz with at most three decimal places, or a WWROF band designator.
    Frequency,
    /// QSO frequency must fall within an ADIF 3.1.8 band.
    Band,
    /// QSO syntax must be ASCII with space or tab field delimiters.
    QsoAscii,
    /// QSO fields must meet LoTW validation under the selected signing options.
    QsoConversion,
    /// Unknown contest exchanges place the received call in different fields.
    DifferentCallField {
        /// The first QSO's one-based physical line.
        first_line: usize,
        /// The conflicting QSO's one-based physical line.
        other_line: usize,
    },
}

impl CabrilloError {
    /// Stable, content-free reason kind for offline differential classification.
    pub fn kind(self) -> &'static str {
        match self {
            Self::InputLimit => "input_limit",
            Self::LineLimit => "line_limit",
            Self::Encoding => "encoding",
            Self::AfterEnd => "after_end",
            Self::Separator => "separator",
            Self::Tag => "tag",
            Self::ValueLimit => "value_limit",
            Self::Start => "start",
            Self::RepeatedStart => "repeated_start",
            Self::End => "end",
            Self::ContestOrder => "contest_order",
            Self::Contest => "contest",
            Self::BeforeContest => "before_contest",
            Self::RecordLimit => "record_limit",
            Self::FieldLimit => "field_limit",
            Self::MissingStart => "missing_start",
            Self::MissingContest => "missing_contest",
            Self::MissingEnd => "missing_end",
            Self::QsoFields => "qso_fields",
            Self::IncompleteQso => "incomplete_qso",
            Self::NoCall => "no_received_call",
            Self::AmbiguousCall => "ambiguous_received_call",
            Self::GuessedCall => "guessed_exchange",
            Self::MissingCall => "missing_received_call",
            Self::Call => "call_syntax",
            Self::DateTime => "date_time",
            Self::Mode => "mode",
            Self::Frequency => "frequency",
            Self::Band => "band",
            Self::QsoAscii => "qso_ascii",
            Self::QsoConversion => "qso_conversion",
            Self::DifferentCallField { .. } => "different_received_call_field",
        }
    }
}

impl fmt::Display for CabrilloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit => f.write_str("input must be at most 67108864 bytes"),
            Self::LineLimit => f.write_str("log must have at most 200020 lines, each at most 65536 bytes"),
            Self::Encoding => f.write_str("header text must be UTF-8"),
            Self::AfterEnd => f.write_str("END-OF-LOG must be the last nonempty line"),
            Self::Separator => f.write_str("each header or QSO line must have a tag followed by a colon"),
            Self::Tag => f.write_str("tags must contain only ASCII letters, digits, or hyphens, at most 64 bytes"),
            Self::ValueLimit => f.write_str("header values must be at most 65536 bytes"),
            Self::Start => f.write_str("START-OF-LOG must be 2.0 or 3.0 and precede all headers and QSOs"),
            Self::RepeatedStart => f.write_str("START-OF-LOG must appear only once"),
            Self::End => f.write_str("END-OF-LOG must have an empty value"),
            Self::ContestOrder => f.write_str("CONTEST must appear once, before every QSO"),
            Self::Contest => f.write_str("CONTEST must contain 1 to 32 ASCII letters, digits, or hyphens"),
            Self::BeforeContest => f.write_str("QSO must follow CONTEST"),
            Self::RecordLimit => f.write_str("log must contain at most 100010 QSOs"),
            Self::FieldLimit => f.write_str("log must emit at most 2000200 ADIF fields"),
            Self::MissingStart => f.write_str("log must begin with START-OF-LOG: 2.0 or 3.0"),
            Self::MissingContest => f.write_str("log must have one CONTEST header before its QSOs"),
            Self::MissingEnd => f.write_str("log must end with an empty END-OF-LOG:"),
            Self::QsoFields => f.write_str("QSO must have at most 256 fields, each at most 64 bytes"),
            Self::IncompleteQso => f.write_str("QSO must contain frequency, mode, UTC date, UTC time, sent call, and sent and received exchanges"),
            Self::NoCall => f.write_str("received exchange must have one call candidate: letters, digits, or slash, at least four letters or digits including one of each, excluding four-character locators"),
            Self::AmbiguousCall => f.write_str("received exchange must have exactly one call candidate; remove ambiguity or use an ADIF Contest_ID with a documented exchange"),
            Self::GuessedCall => f.write_str("received-call field must match the guessed ADIF Contest_ID exchange; correct the exchange or supply ADIF"),
            Self::MissingCall => f.write_str("QSO must include the received-call field required by the contest exchange"),
            Self::Call => f.write_str("QSO sent and received calls must contain only ASCII letters, digits, or slash"),
            Self::DateTime => f.write_str("QSO date must be a valid UTC YYYY-MM-DD and time must be a valid UTC HHMM"),
            Self::Mode => f.write_str("QSO mode must be one of CW, PH, FM, RY, DG"),
            Self::Frequency => f.write_str("QSO frequency must be numeric kHz with at most three decimal places, or a WWROF band designator"),
            Self::Band => f.write_str("QSO frequency must fall within an ADIF 3.1.8 band"),
            Self::QsoConversion => f.write_str("QSO must meet LoTW call, band, mode, date, time, and frequency requirements under the selected signing options; a received amateur call must have 3 to 20 letters, digits, or slashes, a letter and a digit, no leading or trailing slash, and no 0, Q, or unassigned 1 prefix"),
            Self::QsoAscii => f.write_str("QSO syntax must be ASCII with space or tab field delimiters"),
            Self::DifferentCallField { first_line, other_line } => write!(f,
                "CONTEST is not in ADIF 3.1.8's Contest_ID list and no single received-call field fits every QSO (lines {first_line} and {other_line} differ); correct the exchanges or supply ADIF"),
        }
    }
}

/// Why input could not be read as records. Says where, never what a value held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// A `<` that does not open a well-formed field, at this byte offset.
    BadField {
        /// Where, in bytes from the start.
        offset: usize,
    },
    /// A field whose stated length runs past the end of the input.
    Truncated {
        /// Where, in bytes from the start.
        offset: usize,
    },
    /// A value longer than [`MAX_VALUE_LEN`].
    TooLong {
        /// Where, in bytes from the start.
        offset: usize,
    },
    /// A record with more than [`MAX_FIELDS`] fields, or input with more than
    /// [`MAX_TOTAL_FIELDS`] in all.
    TooManyFields {
        /// Where, in bytes from the start.
        offset: usize,
    },
    /// More than [`MAX_RECORDS`] records.
    TooManyRecords {
        /// Where, in bytes from the start.
        offset: usize,
    },
    /// Fields after the last `<eor>`: a record that never ended.
    Unterminated,
    /// An ADX document could not be read.
    Adx(&'static str),
    /// A Cabrillo log could not be read.
    Cabrillo {
        /// One-based physical line, including blank lines and counting CRLF once.
        line: usize,
        /// Fixed requirement and, when needed, related QSO line numbers.
        problem: CabrilloError,
    },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadField { offset } => write!(f, "a malformed field at byte {offset}"),
            Self::Truncated { offset } => write!(f, "a field at byte {offset} runs past the end"),
            Self::TooLong { offset } => write!(f, "a field at byte {offset} is too long"),
            Self::TooManyRecords { offset } => write!(f, "too many records, at byte {offset}"),
            Self::TooManyFields { offset } => {
                write!(f, "a record ending at byte {offset} has too many fields")
            }
            Self::Unterminated => write!(f, "the last record has no <eor>"),
            Self::Adx(problem) => write!(f, "ADX: {problem}"),
            Self::Cabrillo { line, problem } => write!(f, "line {line}: {problem}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// Every record in `input`, detected by content as Cabrillo, ADX, or ADI after an optional UTF-8 BOM and
/// whitespace. An ADX or Cabrillo claim that fails is not retried as ADI. In ADI, text outside fields is
/// ignored and `<eoh>` ends a header whose fields are dropped; fields after the last `<eor>` are an
/// error. ADX headers are discarded as well. Detection may look past whitespace, but ADX is
/// validated as written, apart from one leading UTF-8 BOM: whitespace before an XML declaration,
/// a misplaced BOM, and XML-forbidden characters are refused. Comments and processing instructions
/// before the ADX root are recognized within a 64 KiB format lookahead; longer prologs are refused.
pub fn parse(input: &[u8]) -> Result<Vec<Record>, RecordError> {
    // Bound all format lookahead, including whitespace and XML Misc before the root.
    let lookahead = &input[..input.len().min(MAX_PROLOG_LEN)];
    let input_start = lookahead.trim_ascii_start();
    let content = input_start
        .strip_prefix(b"\xef\xbb\xbf")
        .unwrap_or(input_start);
    let content = content.trim_ascii_start();
    if claims_adx(content, lookahead.len() == MAX_PROLOG_LEN)? {
        return crate::adx::parse(input);
    }
    // Explicit ADIF markup takes precedence over marker text inside an ADIF field value.
    if !content.starts_with(b"<") && crate::cabrillo::claims(content) {
        return crate::cabrillo::parse(input);
    }
    parse_adi(input)
}

// Detection only: preserve the original bytes for XML validation, and never classify ADI
// following XML-looking prose/comments as ADX unless its declaration or root claims it.
const MAX_PROLOG_LEN: usize = 64 * 1024;

fn claims_adx(mut content: &[u8], at_limit: bool) -> Result<bool, RecordError> {
    loop {
        content = content.trim_ascii_start();
        if content.starts_with(b"<?xml") || content.starts_with(b"<ADX") {
            return Ok(true);
        }
        let end = if content.starts_with(b"<!--") {
            b"-->".as_slice()
        } else if content.starts_with(b"<?") {
            b"?>".as_slice()
        } else if content.is_empty() && at_limit {
            return Err(RecordError::TooLong {
                offset: MAX_PROLOG_LEN,
            });
        } else {
            return Ok(false);
        };
        if let Some(at) = content.windows(end.len()).position(|w| w == end) {
            content = &content[at + end.len()..];
        } else if at_limit {
            return Err(RecordError::TooLong {
                offset: MAX_PROLOG_LEN,
            });
        } else {
            return Ok(false);
        }
    }
}

fn parse_adi(input: &[u8]) -> Result<Vec<Record>, RecordError> {
    let mut records = Vec::new();
    let mut current = Record::default();
    let mut total_fields = 0;
    let mut at = 0;
    while let Some(lt) = input[at..].iter().position(|&b| b == b'<') {
        let start = at + lt;
        let gt = input[start..]
            .iter()
            .take(MAX_TAG_LEN + 2)
            .position(|&b| b == b'>')
            .map(|p| start + p)
            .ok_or(RecordError::BadField { offset: start })?;
        let tag = std::str::from_utf8(&input[start + 1..gt])
            .map_err(|_| RecordError::BadField { offset: start })?;
        if tag.eq_ignore_ascii_case("eor") {
            if records.len() == MAX_RECORDS {
                return Err(RecordError::TooManyRecords { offset: start });
            }
            records.push(std::mem::take(&mut current));
            at = gt + 1;
            continue;
        }
        if tag.eq_ignore_ascii_case("eoh") {
            current = Record::default();
            at = gt + 1;
            continue;
        }
        let mut parts = tag.split(':');
        let name = parts.next().unwrap_or("");
        let len = parts.next();
        let kind = parts.next();
        // A name as tqsllib writes them, SIGN_LOTW_V2.0 included; a type is a letter or digit.
        let plain_name = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        };
        let plain = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric());
        let len: usize = match (len, parts.next()) {
            (Some(l), None)
                if plain_name(name) && !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()) =>
            {
                l.parse()
                    .map_err(|_| RecordError::TooLong { offset: start })?
            }
            _ => return Err(RecordError::BadField { offset: start }),
        };
        // A type is one letter or digit, as tqsllib and ADIF write it.
        if kind.is_some_and(|k| k.len() != 1 || !plain(k)) {
            return Err(RecordError::BadField { offset: start });
        }
        if len > MAX_VALUE_LEN {
            return Err(RecordError::TooLong { offset: start });
        }
        let value_start = gt + 1;
        let value_end = value_start
            .checked_add(len)
            .filter(|&end| end <= input.len())
            .ok_or(RecordError::Truncated { offset: start })?;
        if current.fields.len() == MAX_FIELDS || total_fields == MAX_TOTAL_FIELDS {
            return Err(RecordError::TooManyFields { offset: start });
        }
        total_fields += 1;
        current.fields.push(Field {
            name: name.to_string(),
            kind: kind.map(str::to_string),
            value: Zeroizing::new(input[value_start..value_end].to_vec()),
        });
        at = value_end;
    }
    if current.fields.is_empty() {
        Ok(records)
    } else {
        Err(RecordError::Unterminated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_records_and_types_are_read_exactly() {
        let input =
            b"header text\n<eoh>\n<CALL:7>QG0TEST\n<SIGN_LOTW_V2.0:4:6>ab\ncd<eor>\n<A:0><eor>";
        let records = parse(input).expect("records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].text("call"), Some("QG0TEST"));
        let sig = &records[0].fields[1];
        assert_eq!(sig.name, "SIGN_LOTW_V2.0");
        assert_eq!(sig.kind.as_deref(), Some("6"));
        assert_eq!(sig.value.as_slice(), &b"ab\ncd"[..4]);
        assert_eq!(records[1].get("A"), Some(&b""[..]));
    }

    #[test]
    fn a_value_may_hold_anything_its_length_covers() {
        // The value swallows the first <eor>; the second ends the one record.
        let records = parse(b"<K:5><eor><eor>").expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].get("K"), Some(&b"<eor>"[..]));
    }

    #[test]
    fn malformed_input_is_refused_and_says_where() {
        assert_eq!(
            parse(b"<CALL:99>QG0TEST<eor>"),
            Err(RecordError::Truncated { offset: 0 })
        );
        // Nine bytes are there, so the value is whole; it takes "<e", and the record never ends.
        assert_eq!(
            parse(b"<CALL:9>QG0TEST<eor>"),
            Err(RecordError::Unterminated)
        );
        assert_eq!(
            parse(b"x<CALL>QG0TEST<eor>"),
            Err(RecordError::BadField { offset: 1 })
        );
        assert_eq!(
            parse(b"<CALL:-1>x<eor>"),
            Err(RecordError::BadField { offset: 0 })
        );
        assert_eq!(
            parse(b"<CA LL:1>x<eor>"),
            Err(RecordError::BadField { offset: 0 })
        );
        assert_eq!(
            parse(b"<CALL:1:6:7>x<eor>"),
            Err(RecordError::BadField { offset: 0 })
        );
        assert_eq!(parse(b"<CALL:1>x"), Err(RecordError::Unterminated));
        assert_eq!(parse(b"<CALL:1"), Err(RecordError::BadField { offset: 0 }));
        let huge = format!("<K:{}>", MAX_VALUE_LEN + 1);
        assert_eq!(
            parse(huge.as_bytes()),
            Err(RecordError::TooLong { offset: 0 })
        );
        assert_eq!(
            parse(b"<K:99999999999999999999999>"),
            Err(RecordError::TooLong { offset: 0 })
        );
    }

    #[test]
    fn many_tiny_records_cannot_grow_memory_without_bound() {
        // Found in review: every ten bytes made a record, without any limit on the whole.
        let records = b"<A:0><eor>".repeat(MAX_RECORDS + 1);
        assert!(matches!(
            parse(&records),
            Err(RecordError::TooManyRecords { .. })
        ));
        let fields = b"<A:0>"
            .repeat(MAX_FIELDS - 1)
            .iter()
            .chain(b"<eor>")
            .copied()
            .collect::<Vec<u8>>();
        let many = fields.repeat(MAX_TOTAL_FIELDS / (MAX_FIELDS - 1) + 1);
        assert!(matches!(
            parse(&many),
            Err(RecordError::TooManyFields { .. })
        ));
    }

    #[test]
    fn a_long_name_or_type_is_refused_before_it_is_kept() {
        // Found in review: a 256 MiB name passed every other limit.
        let long = [b"<".as_slice(), &[b'A'; MAX_TAG_LEN + 1], b":0><eor>"].concat();
        assert_eq!(parse(&long), Err(RecordError::BadField { offset: 0 }));
        let longest = [b"<".as_slice(), &[b'A'; MAX_TAG_LEN - 2], b":0><eor>"].concat();
        assert!(parse(&longest).is_ok());
        assert_eq!(
            parse(b"<A:1:66>x<eor>"),
            Err(RecordError::BadField { offset: 0 })
        );
    }

    #[test]
    fn a_record_with_too_many_fields_is_refused() {
        let mut input = Vec::new();
        for _ in 0..=MAX_FIELDS {
            input.extend_from_slice(b"<K:1>x");
        }
        input.extend_from_slice(b"<eor>");
        assert!(matches!(
            parse(&input),
            Err(RecordError::TooManyFields { .. })
        ));
    }

    #[test]
    fn every_value_is_wiped_when_dropped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let records = parse(b"<PRIVATE_KEY:6>secret<eor>").expect("records");
        wiped(&records[0].fields[0].value);
    }

    #[test]
    fn a_field_value_is_never_printed() {
        let records = parse(b"<PRIVATE_KEY:6>secret<eor>").expect("records");
        let shown = format!("{records:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("value_len: 6"), "{shown}");
    }
}

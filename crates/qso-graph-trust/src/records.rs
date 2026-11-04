// SPDX-License-Identifier: GPL-3.0-only
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
/// name or type is allocated before this is checked (found by Codex review).
pub const MAX_TAG_LEN: usize = 64;
/// The most fields in one record.
pub const MAX_FIELDS: usize = 256;
/// The most records in one input: a signed log of 100,000 QSOs, plus its header records.
pub const MAX_RECORDS: usize = 100_010;
/// The most fields in all records together, so input made of many tiny records cannot make memory
/// grow without bound (found by Codex review): 20 for each of [`MAX_RECORDS`].
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
}

impl Record {
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
        }
    }
}

impl std::error::Error for RecordError {}

/// Every record in `input`. Text outside fields is ignored, as it is in ADIF, and `<eoh>` ends a
/// header, whose fields are dropped. A field after the last `<eor>` is an error.
pub fn parse(input: &[u8]) -> Result<Vec<Record>, RecordError> {
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
        // Codex review: every ten bytes made a record, without any limit on the whole.
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
        // Codex review: a 256 MiB name passed every other limit.
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

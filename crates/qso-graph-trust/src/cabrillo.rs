// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! WWROF Cabrillo 2/3 structure, converted to ADIF values in wiping records (decision 0016).

use crate::cabrillo_tables::{BANDS, CONTESTS, MODES};
use crate::qso::{Date, Time};
use crate::records::{
    CabrilloError, Field, MAX_FIELDS, MAX_RECORDS, MAX_TOTAL_FIELDS, MAX_VALUE_LEN, Record,
    RecordError,
};
use zeroize::Zeroizing;

pub(crate) const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_LINE: usize = MAX_VALUE_LEN;
const MAX_LINES: usize = MAX_RECORDS * 2;

pub(crate) struct Contest {
    pub(crate) id: &'static str,
    pub(crate) call: usize,
    pub(crate) short_call: Option<usize>,
    pub(crate) source: &'static str,
}

fn error(line: usize, problem: CabrilloError) -> RecordError {
    RecordError::Cabrillo { line, problem }
}

// Physical lines, counting CRLF once and accepting legacy lone CR and LF.
fn lines(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut at = 0;
    std::iter::from_fn(move || {
        if at >= input.len() {
            return None;
        }
        let start = at;
        at += input[at..]
            .iter()
            .position(|b| matches!(b, b'\r' | b'\n'))
            .unwrap_or(input.len() - at);
        let end = at;
        if input.get(at..at + 2) == Some(b"\r\n") {
            at += 2;
        } else if at < input.len() {
            at += 1;
        }
        Some(&input[start..end])
    })
}

// A misplaced structural marker still claims Cabrillo: it must not become empty ADIF.
pub(crate) fn claims(input: &[u8]) -> bool {
    lines(input).any(|line| {
        let line = line.trim_ascii_start();
        [b"START-OF-LOG:".as_slice(), b"END-OF-LOG:", b"QSO:"]
            .iter()
            .any(|tag| {
                line.get(..tag.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(tag))
            })
    })
}

fn field(record: &mut Record, name: &str, value: &str) {
    record.fields.push(Field {
        name: name.into(),
        kind: None,
        value: Zeroizing::new(value.as_bytes().to_vec()),
    });
}

// tqsllib 2.8.7's unknown-contest candidate rules, independently expressed. Search starts at
// token 6; a four-character locator is excluded. Unlike tqsllib's cached position, every QSO is
// checked, including all guessed table entries. An exchange must never silently become CALL.
fn candidate(s: &str) -> bool {
    let b = s.as_bytes();
    !(b.len() == 4
        && b[..2].iter().all(u8::is_ascii_alphabetic)
        && b[2..].iter().all(u8::is_ascii_digit))
        && b.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'/')
        && b.iter().filter(|b| b.is_ascii_alphanumeric()).count() >= 4
        && b.iter().any(u8::is_ascii_alphabetic)
        && b.iter().any(u8::is_ascii_digit)
}

fn call_position(tokens: &[&str], contest: Option<&Contest>) -> Result<usize, CabrilloError> {
    if let Some(c) = contest.filter(|c| c.source != "guessed") {
        return Ok(c.call);
    }
    let mut candidates = tokens
        .iter()
        .enumerate()
        .skip(6)
        .filter(|(_, s)| candidate(s));
    let first = candidates.next().ok_or(CabrilloError::NoCall)?.0;
    if candidates.next().is_some() {
        return Err(CabrilloError::AmbiguousCall);
    }
    if contest.is_some_and(|c| c.call != first) {
        return Err(CabrilloError::GuessedCall);
    }
    Ok(first)
}

// Hz as integers keeps both band edges exact. At most three fractional kHz digits are accepted.
fn khz(s: &str) -> Option<u64> {
    let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let fraction: u64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().ok()?
    };
    whole
        .checked_mul(1000)?
        .checked_add(fraction * 10u64.pow(3 - s.split_once('.').map_or(0, |(_, f)| f.len()) as u32))
}

fn band_frequency(s: &str) -> Result<(&'static str, Option<u64>), CabrilloError> {
    // WWROF designators name bands, not measured frequencies. Use tqsllib's representative
    // frequencies where ADIF does not decide one; 122G/134G use their ADIF band's lower edge.
    let designator = match s.to_ascii_uppercase().as_str() {
        "50" => Some(("6m", 50_000_000)),
        "70" => Some(("4m", 70_000_000)),
        "144" => Some(("2m", 144_000_000)),
        "222" => Some(("1.25m", 222_000_000)),
        "432" => Some(("70cm", 432_000_000)),
        "902" => Some(("33cm", 902_000_000)),
        "1.2G" => Some(("23cm", 1_240_000_000)),
        "2.3G" => Some(("13cm", 2_300_000_000)),
        "3.4G" => Some(("9cm", 3_300_000_000)),
        "5.7G" => Some(("6cm", 5_650_000_000)),
        "10G" => Some(("3cm", 10_000_000_000)),
        "24G" => Some(("1.25cm", 24_000_000_000)),
        "47G" => Some(("6mm", 47_000_000_000)),
        "75G" => Some(("4mm", 75_500_000_000)),
        "122G" => Some(("2.5mm", 119_980_000_000)),
        "134G" => Some(("2mm", 134_000_000_000)),
        "241G" => Some(("1mm", 241_000_000_000)),
        "LIGHT" => return Ok(("submm", None)),
        _ => None,
    };
    if let Some((band, hz)) = designator {
        return Ok((band, Some(hz)));
    }
    let hz = khz(s).ok_or(CabrilloError::Frequency)?;
    BANDS
        .iter()
        .find(|(_, low, high)| (*low..=*high).contains(&hz))
        .map(|(band, _, _)| (*band, Some(hz)))
        .ok_or(CabrilloError::Band)
}

fn qso(
    value: &str,
    contest: Option<&Contest>,
    position: Option<usize>,
) -> Result<(Record, usize), CabrilloError> {
    if !value.is_ascii() || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
        return Err(CabrilloError::QsoAscii);
    }
    let tokens: Vec<_> = value
        .split_ascii_whitespace()
        .take(MAX_FIELDS + 1)
        .collect();
    if tokens.len() > MAX_FIELDS || tokens.iter().any(|s| s.len() > crate::qso::MAX_VALUE_LEN) {
        return Err(CabrilloError::QsoFields);
    }
    if tokens.len() < 7 {
        return Err(CabrilloError::IncompleteQso);
    }
    let pos = match position {
        Some(pos) => pos,
        None => call_position(&tokens, contest)?,
    };
    let call = tokens.get(pos).ok_or(CabrilloError::MissingCall)?;
    let valid_call =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/');
    if !valid_call(call) || !valid_call(tokens[4]) {
        return Err(CabrilloError::Call);
    }
    if !tokens[2].is_ascii()
        || Date::from_iso(tokens[2]).is_none()
        || tokens[3].len() != 4
        || Time::from_adif(tokens[3]).is_none()
    {
        return Err(CabrilloError::DateTime);
    }
    let mode = match tokens[1].to_ascii_uppercase().as_str() {
        "CW" => "CW",
        "PH" => "SSB",
        "FM" => "FM",
        "RY" => "RTTY",
        "DG" => "MFSK",
        _ => return Err(CabrilloError::Mode),
    };
    debug_assert!(MODES.contains(&mode));
    let (band, hz) = band_frequency(tokens[0])?;
    let date = Zeroizing::new(tokens[2].replace('-', ""));
    let mut record = Record::default();
    for (name, value) in [
        ("CALL", *call),
        ("STATION_CALLSIGN", tokens[4]),
        ("QSO_DATE", date.as_str()),
        ("TIME_ON", tokens[3]),
        ("BAND", band),
        ("MODE", mode),
    ] {
        field(&mut record, name, value);
    }
    if let Some(hz) = hz {
        let frequency = Zeroizing::new(format!("{}.{:06}", hz / 1_000_000, hz % 1_000_000));
        field(&mut record, "FREQ", &frequency);
    }
    Ok((record, pos))
}

pub(crate) fn parse(input: &[u8]) -> Result<Vec<Record>, RecordError> {
    if input.len() > MAX_INPUT {
        return Err(error(1, CabrilloError::InputLimit));
    }
    let mut start = false;
    let mut ended = false;
    let mut contest_line = None;
    let mut contest = None;
    let mut first_guess = None;
    let mut alternatives = [0usize, 0usize];
    let mut conflict_line = None;
    let mut alternative_values = Vec::new();
    let mut records = Vec::new();
    let mut fields = 0;
    let mut last_line = 1;
    for (index, bytes) in lines(input).enumerate() {
        let number = index + 1;
        last_line = number;
        let fail = |problem| error(number, problem);
        if index >= MAX_LINES || bytes.len() > MAX_LINE {
            return Err(fail(CabrilloError::LineLimit));
        }
        let line = std::str::from_utf8(bytes).map_err(|_| fail(CabrilloError::Encoding))?;
        let line = line.trim_matches([' ', '\t']);
        let line = if !start {
            line.strip_prefix('\u{feff}')
                .unwrap_or(line)
                .trim_matches([' ', '\t'])
        } else {
            line
        };
        if line.is_empty() {
            continue;
        }
        if ended {
            return Err(fail(CabrilloError::AfterEnd));
        }
        let (tag, value) = line
            .split_once(':')
            .ok_or_else(|| fail(CabrilloError::Separator))?;
        if tag.is_empty()
            || tag.len() > crate::records::MAX_TAG_LEN
            || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(fail(CabrilloError::Tag));
        }
        let value = value.trim_matches([' ', '\t']);
        if value.len() > MAX_VALUE_LEN {
            return Err(fail(CabrilloError::ValueLimit));
        }
        if !start {
            if !tag.eq_ignore_ascii_case("START-OF-LOG") || !matches!(value, "2.0" | "3.0") {
                return Err(fail(CabrilloError::Start));
            }
            start = true;
            continue;
        }
        if tag.eq_ignore_ascii_case("START-OF-LOG") {
            return Err(fail(CabrilloError::RepeatedStart));
        }
        if tag.eq_ignore_ascii_case("END-OF-LOG") {
            if !value.is_empty() {
                return Err(fail(CabrilloError::End));
            }
            ended = true;
        } else if tag.eq_ignore_ascii_case("CONTEST") {
            if contest_line.is_some() || !records.is_empty() || !alternative_values.is_empty() {
                return Err(fail(CabrilloError::ContestOrder));
            }
            // WWROF CONTEST:text explicitly limits its alphabet and length. Unknown identifiers
            // inside that grammar use inference, regardless of ADIF membership.
            if value.is_empty()
                || value.len() > 32
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(fail(CabrilloError::Contest));
            }
            contest_line = Some(number);
            contest = CONTESTS.iter().find(|c| c.id.eq_ignore_ascii_case(value));
        } else if tag.eq_ignore_ascii_case("QSO") {
            let contest_line = contest_line.ok_or_else(|| fail(CabrilloError::BeforeContest))?;
            if records.len() + alternative_values.len() >= MAX_RECORDS {
                return Err(fail(CabrilloError::RecordLimit));
            }
            if let Some(c) = contest.filter(|c| c.short_call.is_some() && c.source != "guessed") {
                let positions = [c.short_call.unwrap(), c.call];
                let tokens: Vec<_> = value
                    .split_ascii_whitespace()
                    .take(MAX_FIELDS + 1)
                    .collect();
                let plausible = positions.map(|pos| tokens.get(pos).is_some_and(|s| candidate(s)));
                for (count, matches) in alternatives.iter_mut().zip(plausible) {
                    *count += usize::from(matches);
                }
                if plausible[0] != plausible[1] {
                    conflict_line = Some(number);
                }
                alternative_values.push((value, number));
                continue;
            }
            let (mut record, pos) = qso(value, contest, None).map_err(fail)?;
            record.source_line = Some(number);
            if contest.is_none() {
                if let Some((first_pos, first_line)) = first_guess {
                    if first_pos != pos {
                        return Err(error(
                            contest_line,
                            CabrilloError::DifferentCallField {
                                first_line,
                                other_line: number,
                            },
                        ));
                    }
                } else {
                    first_guess = Some((pos, number));
                }
            }
            fields += record.fields.len();
            if fields > MAX_TOTAL_FIELDS {
                return Err(fail(CabrilloError::FieldLimit));
            }
            records.push(record);
        }
    }
    if !start {
        return Err(error(last_line, CabrilloError::MissingStart));
    }
    if contest_line.is_none() {
        return Err(error(last_line, CabrilloError::MissingContest));
    }
    if !ended {
        return Err(error(last_line, CabrilloError::MissingEnd));
    }
    if !alternative_values.is_empty() {
        let total = alternative_values.len();
        let position_index = (0..2)
            .find(|&i| alternatives[i] > total / 2 && alternatives[1 - i] < total.div_ceil(2));
        let Some(index) = position_index else {
            let problem = if alternatives == [0, 0] {
                CabrilloError::NoCall
            } else {
                CabrilloError::AmbiguousCall
            };
            return Err(error(
                conflict_line.unwrap_or(alternative_values.last().unwrap().1),
                problem,
            ));
        };
        let c = contest.unwrap();
        let position = [c.short_call.unwrap(), c.call][index];
        for (value, number) in alternative_values {
            let (mut record, _) =
                qso(value, contest, Some(position)).map_err(|problem| error(number, problem))?;
            record.source_line = Some(number);
            fields += record.fields.len();
            if fields > MAX_TOTAL_FIELDS {
                return Err(error(number, CabrilloError::FieldLimit));
            }
            records.push(record);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records;

    fn log(contest: &str, value: &str) -> Vec<u8> {
        format!("START-OF-LOG: 3.0\nCONTEST: {contest}\nQSO: {value}\nEND-OF-LOG:\n").into_bytes()
    }

    #[test]
    fn equivalent_adi_values_and_content_detection() {
        let input = log(
            " cq-ww-cw ",
            "14042 CW 2026-11-03 1830 QG0TEST 599 4 Z0TEST 599 5",
        );
        let expected = records::parse(b"<CALL:6>Z0TEST<STATION_CALLSIGN:7>QG0TEST<QSO_DATE:8>20261103<TIME_ON:4>1830<BAND:3>20m<MODE:2>CW<FREQ:9>14.042000<eor>").unwrap();
        assert_eq!(
            records::parse(&input).unwrap()[0].fields,
            expected[0].fields
        );
        assert_eq!(records::parse(&input).unwrap()[0].source_line(), Some(3));
        for prefix in [b" \t\n\xef\xbb\xbf ".as_slice(), b"\xef\xbb\xbf "] {
            assert_eq!(
                records::parse(&[prefix, &input].concat()).unwrap()[0].fields,
                expected[0].fields
            );
        }
        assert!(records::parse(&input).unwrap()[0].get("CALL").is_some());
        let v2 = String::from_utf8(input)
            .unwrap()
            .replace("3.0", "2.0")
            .replace("QSO:", "X-QSO:");
        assert!(records::parse(v2.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn misplaced_markers_claim_cabrillo_instead_of_empty_adi() {
        let comment = "synthetic\nQSO: text inside an ADIF field\nEND-OF-LOG:";
        let adi = format!("<COMMENT:{}>{comment}<eor>", comment.len());
        assert_eq!(
            records::parse(adi.as_bytes()).unwrap()[0].text("COMMENT"),
            Some(comment)
        );
        let valid = log("CQ-WW-CW", VALID);
        for prefix in ["END-OF-LOG:", "END-OF-LOG:\n", "SOAPBOX: synthetic\n"] {
            let input = [prefix.as_bytes(), &valid].concat();
            assert_eq!(records::parse(&input), Err(error(1, CabrilloError::Start)));
        }
        assert_eq!(
            records::parse(b"QSO: invalid"),
            Err(error(1, CabrilloError::Start))
        );
    }

    #[test]
    fn ambiguous_guess_is_refused_on_every_line() {
        let ambiguous = "14042 CW 2026-11-03 1830 QG0TEST 599 QG0ONE QG0TWO 599 5";
        assert!(records::parse(&log("UNKNOWN", ambiguous)).is_err());
        let valid = "14042 CW 2026-11-03 1830 QG0TEST 599 4 Z0TEST 599 5";
        let text = String::from_utf8(log("UNKNOWN", valid))
            .unwrap()
            .replace("END-OF-LOG:", &format!("QSO: {ambiguous}\nEND-OF-LOG:"));
        assert!(records::parse(text.as_bytes()).is_err());
        assert_eq!(records::parse(&log("UNKNOWN", valid)).unwrap().len(), 1);
        assert_eq!(
            records::parse(&log(
                "ARRL-SS-CW",
                "14042 CW 2026-11-03 1830 QG0TEST 12 A 26 KS Z0TEST 13 B 25 KS"
            ))
            .unwrap()[0]
                .text("CALL"),
            Some("Z0TEST")
        );
    }

    #[test]
    fn arrl_160_positions_are_resolved_across_the_log() {
        let wve = "1800 CW 2026-11-03 1830 QG0TEST 599 9AA Z0TEST 599 5";
        let wve_second = "1800 CW 2026-11-03 1831 QG0TEST 599 AA9 Z0NEXT 599 5";
        let dx = "1800 CW 2026-11-03 1830 QG0TEST 599 Z0TEST 599 5";
        let with_second = |first: &str, second: &str| {
            format!(
                "START-OF-LOG: 3.0\nCONTEST: ARRL-160\nQSO: {first}\nQSO: {second}\nEND-OF-LOG:\n"
            )
        };
        let records = parse(with_second(wve, wve_second).as_bytes()).unwrap();
        assert_eq!(records[0].text("CALL"), Some("Z0TEST"));
        assert_eq!(records[1].text("CALL"), Some("Z0NEXT"));
        assert_eq!(
            parse(&log("ARRL-160", dx)).unwrap()[0].text("CALL"),
            Some("Z0TEST")
        );
        assert_eq!(
            parse(with_second(wve, dx).as_bytes()),
            Err(error(4, CabrilloError::AmbiguousCall))
        );
        let both = "1800 CW 2026-11-03 1830 QG0TEST 599 Z0FIRST Z0TEST 599 5";
        assert_eq!(
            parse(&log("ARRL-160", both)),
            Err(error(3, CabrilloError::AmbiguousCall))
        );
        assert_eq!(
            parse(with_second(both, wve).as_bytes()),
            Err(error(4, CabrilloError::AmbiguousCall))
        );
    }

    #[test]
    fn arrl_160_majority_reads_a_one_by_one_call_from_the_chosen_position() {
        // With a sent section on every line the call is at the later position. A 1x1
        // special-event call there is too short to be a plausible call, but the position is
        // chosen by majority, so the line is read and its call left to LoTW validation.
        let input = "START-OF-LOG: 3.0\nCONTEST: ARRL-160\n\
            QSO: 1800 CW 2026-11-03 1830 QG0TEST 599 AA Z0TEST 599 5\n\
            QSO: 1800 CW 2026-11-03 1831 QG0TEST 599 AA Z1A 599 5\n\
            QSO: 1800 CW 2026-11-03 1832 QG0TEST 599 AA Z0NEXT 599 5\n\
            END-OF-LOG:\n";
        let records = parse(input.as_bytes()).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].text("CALL"), Some("Z1A"));
    }

    #[test]
    fn adif_band_edges_are_inclusive_and_exact() {
        for &(band, low, high) in BANDS {
            for hz in [low, high] {
                let khz = format!("{}.{:03}", hz / 1000, hz % 1000);
                assert_eq!(band_frequency(&khz).unwrap().0, band);
            }
        }
        assert!(band_frequency("14350.001").is_err());
        assert!(band_frequency("13999.999").is_err());
        for (token, band) in [
            ("144", "2m"),
            ("1.2G", "23cm"),
            ("122G", "2.5mm"),
            ("134G", "2mm"),
            ("LIGHT", "submm"),
        ] {
            assert_eq!(band_frequency(token).unwrap().0, band);
        }
    }

    #[test]
    fn a_cabrillo_claim_is_never_retried_as_adi() {
        assert!(records::parse(b"START-OF-LOG: 3.0\n<CALL:6>Z0TEST<eor>").is_err());
    }

    #[test]
    fn malformed_and_oversized_logs_are_refused() {
        for value in [
            "14000 XX 2026-11-03 1830 QG0TEST 599 4 Z0TEST",
            "14000 CW 2026-02-30 1830 QG0TEST 599 4 Z0TEST",
            "14000 CW 2026-11-03 2500 QG0TEST 599 4 Z0TEST",
        ] {
            assert!(records::parse(&log("CQ-WW-CW", value)).is_err());
        }
        assert!(parse(&vec![b' '; MAX_INPUT + 1]).is_err());
        assert!(
            parse(&format!("START-OF-LOG: 3.0\nSOAPBOX: {}", "x".repeat(MAX_LINE)).into_bytes())
                .is_err()
        );
        assert!(parse(&b"\n".repeat(MAX_LINES + 1)).is_err());
        assert!(qso(&"x ".repeat(MAX_FIELDS + 1), None, None).is_err());
        assert_eq!(CONTESTS.len(), 258);
        assert_eq!(
            CONTESTS.iter().filter(|c| c.source != "guessed").count(),
            24
        );
        for (code, mode) in [("PH", "SSB"), ("DG", "MFSK"), ("RY", "RTTY"), ("FM", "FM")] {
            let value = format!("14000 {code} 2026-11-03 1830 QG0TEST 599 4 Z0TEST");
            let r = records::parse(&log("CQ-WW-CW", &value)).unwrap();
            assert_eq!(r[0].text("MODE"), Some(mode));
            assert!(
                crate::qso::Qso::from_adif(&r[0]).is_ok(),
                "{code}: {:?}",
                crate::qso::Qso::from_adif(&r[0])
            );
        }
    }

    const VALID: &str = "14042 CW 2026-11-03 1830 QG0TEST 599 4 Z0TEST 599 5";

    #[test]
    fn contest_specification_boundary_and_sampled_values() {
        for value in [
            "CQ WPX RTTY CONTEST",
            "CQ- WW- CW",
            "2011 CQ World Wide DX Contest, CW",
            "2018 WRTC Y83P",
            "2018 WRTC Y83U",
            "",
            "UNKNOWN,CONTEST",
            "UNKNOWN.CONTEST",
            "UNKNOWN_CONTEST",
            "UNKNOWN\tCONTEST",
            "ÉVENT",
            "123456789012345678901234567890123",
        ] {
            assert_eq!(
                parse(&log(value, VALID)),
                Err(error(2, CabrilloError::Contest))
            );
        }
        for value in [
            "UNKNOWN",
            "2026-UNKNOWN",
            "123",
            "-",
            "UNKNOWN\t",
            "12345678901234567890123456789012",
            "CQ-WPSSB",
        ] {
            assert_eq!(parse(&log(value, VALID)).unwrap().len(), 1);
            let missing = VALID.replace("Z0TEST", "599");
            assert_eq!(
                parse(&log(value, &missing)),
                Err(error(3, CabrilloError::NoCall))
            );
        }
        // A syntactically valid unknown CONTEST must reach inference, even on later QSOs.
        let shifted = "14042 CW 2026-11-03 1830 QG0TEST 599 Z0TEST 599 5";
        let text = format!(
            "START-OF-LOG: 3.0\nCONTEST: UNKNOWN\nQSO: {VALID}\nQSO: {shifted}\nEND-OF-LOG:\n"
        );
        let err = records::parse(text.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            error(
                2,
                CabrilloError::DifferentCallField {
                    first_line: 3,
                    other_line: 4
                }
            )
        );
        assert_eq!(
            err.to_string(),
            "line 2: CONTEST is not in ADIF 3.1.7's Contest_ID list and no single received-call field fits every QSO (lines 3 and 4 differ); correct the exchanges or supply ADIF"
        );
    }

    #[test]
    fn refusals_name_physical_lines_and_never_echo_values() {
        for version in [
            "2.1",
            "2.18",
            "2.2",
            "2.3",
            "2.5",
            "3.00",
            "3.1",
            "30",
            "v2.0",
            "V2.0",
            "",
            "version-number 03",
        ] {
            let text = format!("START-OF-LOG: {version}\nCONTEST: UNKNOWN\nEND-OF-LOG:");
            assert_eq!(
                records::parse(text.as_bytes()).unwrap_err().to_string(),
                "line 1: START-OF-LOG must be 2.0 or 3.0 and precede all headers and QSOs"
            );
        }
        for code in ["LS", "SB"] {
            let err = records::parse(&log(
                "CQ-WW-CW",
                &VALID.replace(" CW ", &format!(" {code} ")),
            ))
            .unwrap_err();
            assert_eq!(
                err.to_string(),
                "line 3: QSO mode must be one of CW, PH, FM, RY, DG"
            );
            assert!(!err.to_string().contains(code));
        }
        for separator in ["\n", "\r\n", "\r"] {
            let text = format!(
                "{separator} \t\u{feff} START-OF-LOG: 3.0{separator}SOAPBOX: PRIVATE-SENTINEL{separator}CONTEST: CQ-WW-CW{separator}QSO: {}{separator}END-OF-LOG:",
                VALID.replace(" CW ", " LS ")
            );
            assert_eq!(
                records::parse(text.as_bytes()),
                Err(error(5, CabrilloError::Mode))
            );
            let bytes = format!("START-OF-LOG: 3.0{separator}CONTEST: UNKNOWN{separator}SOAPBOX: ")
                .into_bytes();
            assert_eq!(
                records::parse(&[bytes, vec![0xff]].concat()),
                Err(error(3, CabrilloError::Encoding))
            );
        }
        for (text, line, problem) in [
            (
                "START-OF-LOG: 3.0\nCONTEST: UNKNOWN\nEND-OF-LOG:\nPRIVATE-SENTINEL",
                4,
                CabrilloError::AfterEnd,
            ),
            (
                "START-OF-LOG: 3.0\nPRIVATE-SENTINEL",
                2,
                CabrilloError::Separator,
            ),
            (
                "START-OF-LOG: 3.0\nPRIVATE_SENTINEL: value",
                2,
                CabrilloError::Tag,
            ),
            (
                "START-OF-LOG: 3.0\nSTART-OF-LOG: 3.0",
                2,
                CabrilloError::RepeatedStart,
            ),
            (
                "START-OF-LOG: 3.0\nEND-OF-LOG: PRIVATE-SENTINEL",
                2,
                CabrilloError::End,
            ),
            (
                "START-OF-LOG: 3.0\nCONTEST: UNKNOWN\nCONTEST: PRIVATE-SENTINEL",
                3,
                CabrilloError::ContestOrder,
            ),
            (
                "START-OF-LOG: 3.0\nQSO: PRIVATE-SENTINEL",
                2,
                CabrilloError::BeforeContest,
            ),
            (
                "START-OF-LOG: 3.0\nEND-OF-LOG:",
                2,
                CabrilloError::MissingContest,
            ),
            (
                "START-OF-LOG: 3.0\nCONTEST: UNKNOWN",
                2,
                CabrilloError::MissingEnd,
            ),
        ] {
            let err = records::parse(text.as_bytes()).unwrap_err();
            assert_eq!(err, error(line, problem));
            assert!(!format!("{err} {err:?}").contains("PRIVATE"));
        }
        for (value, problem) in [
            ("PRIVATE-SENTINEL", CabrilloError::IncompleteQso),
            (
                "14000 CW 2026-11-03 1830 QG0TEST 599",
                CabrilloError::IncompleteQso,
            ),
            (
                "14000 CW 2026-11-03 1830 QG0TEST 599 4",
                CabrilloError::MissingCall,
            ),
            (
                "14000 CW 2026-11-03 1830 QG0TEST 599 4 PRIVATE-SENTINEL",
                CabrilloError::Call,
            ),
            (
                "14000 CW 2026-02-30 1830 QG0TEST 599 4 Z0TEST",
                CabrilloError::DateTime,
            ),
            (
                "PRIVATE-SENTINEL CW 2026-11-03 1830 QG0TEST 599 4 Z0TEST",
                CabrilloError::Frequency,
            ),
            (
                "14350.001 CW 2026-11-03 1830 QG0TEST 599 4 Z0TEST",
                CabrilloError::Band,
            ),
            (
                "14000 CW 2026-11-03 1830 QG0TEST 599 4 Z0TEST\u{000b}",
                CabrilloError::QsoAscii,
            ),
        ] {
            let err = records::parse(&log("CQ-WW-CW", value)).unwrap_err();
            assert_eq!(err, error(3, problem));
            let shown = format!("{err} {err:?}");
            for secret in ["PRIVATE", "QG0TEST", "Z0TEST", "2026-02-30", "14350.001"] {
                assert!(!shown.contains(secret));
            }
        }
        assert_eq!(parse(b""), Err(error(1, CabrilloError::MissingStart)));
        assert!(std::mem::size_of::<RecordError>() <= 64);
    }

    #[test]
    fn every_refusal_kind_has_fixed_actionable_wording() {
        for (problem, kind, requirement) in [
            (
                CabrilloError::InputLimit,
                "input_limit",
                "input must be at most 67108864 bytes",
            ),
            (
                CabrilloError::LineLimit,
                "line_limit",
                "log must have at most 200020 lines, each at most 65536 bytes",
            ),
            (
                CabrilloError::Encoding,
                "encoding",
                "header text must be UTF-8",
            ),
            (
                CabrilloError::AfterEnd,
                "after_end",
                "END-OF-LOG must be the last nonempty line",
            ),
            (
                CabrilloError::Separator,
                "separator",
                "each header or QSO line must have a tag followed by a colon",
            ),
            (
                CabrilloError::Tag,
                "tag",
                "tags must contain only ASCII letters, digits, or hyphens, at most 64 bytes",
            ),
            (
                CabrilloError::ValueLimit,
                "value_limit",
                "header values must be at most 65536 bytes",
            ),
            (
                CabrilloError::Start,
                "start",
                "START-OF-LOG must be 2.0 or 3.0 and precede all headers and QSOs",
            ),
            (
                CabrilloError::RepeatedStart,
                "repeated_start",
                "START-OF-LOG must appear only once",
            ),
            (
                CabrilloError::End,
                "end",
                "END-OF-LOG must have an empty value",
            ),
            (
                CabrilloError::ContestOrder,
                "contest_order",
                "CONTEST must appear once, before every QSO",
            ),
            (
                CabrilloError::Contest,
                "contest",
                "CONTEST must contain 1 to 32 ASCII letters, digits, or hyphens",
            ),
            (
                CabrilloError::BeforeContest,
                "before_contest",
                "QSO must follow CONTEST",
            ),
            (
                CabrilloError::RecordLimit,
                "record_limit",
                "log must contain at most 100010 QSOs",
            ),
            (
                CabrilloError::FieldLimit,
                "field_limit",
                "log must emit at most 2000200 ADIF fields",
            ),
            (
                CabrilloError::MissingStart,
                "missing_start",
                "log must begin with START-OF-LOG: 2.0 or 3.0",
            ),
            (
                CabrilloError::MissingContest,
                "missing_contest",
                "log must have one CONTEST header before its QSOs",
            ),
            (
                CabrilloError::MissingEnd,
                "missing_end",
                "log must end with an empty END-OF-LOG:",
            ),
            (
                CabrilloError::QsoFields,
                "qso_fields",
                "QSO must have at most 256 fields, each at most 64 bytes",
            ),
            (
                CabrilloError::IncompleteQso,
                "incomplete_qso",
                "QSO must contain frequency, mode, UTC date, UTC time, sent call, and sent and received exchanges",
            ),
            (
                CabrilloError::NoCall,
                "no_received_call",
                "received exchange must have one call candidate: letters, digits, or slash, at least four letters or digits including one of each, excluding four-character locators",
            ),
            (
                CabrilloError::AmbiguousCall,
                "ambiguous_received_call",
                "received exchange must have exactly one call candidate; remove ambiguity or use an ADIF Contest_ID with a documented exchange",
            ),
            (
                CabrilloError::GuessedCall,
                "guessed_exchange",
                "received-call field must match the guessed ADIF Contest_ID exchange; correct the exchange or supply ADIF",
            ),
            (
                CabrilloError::MissingCall,
                "missing_received_call",
                "QSO must include the received-call field required by the contest exchange",
            ),
            (
                CabrilloError::Call,
                "call_syntax",
                "QSO sent and received calls must contain only ASCII letters, digits, or slash",
            ),
            (
                CabrilloError::DateTime,
                "date_time",
                "QSO date must be a valid UTC YYYY-MM-DD and time must be a valid UTC HHMM",
            ),
            (
                CabrilloError::Mode,
                "mode",
                "QSO mode must be one of CW, PH, FM, RY, DG",
            ),
            (
                CabrilloError::Frequency,
                "frequency",
                "QSO frequency must be numeric kHz with at most three decimal places, or a WWROF band designator",
            ),
            (
                CabrilloError::Band,
                "band",
                "QSO frequency must fall within an ADIF 3.1.7 band",
            ),
            (
                CabrilloError::QsoConversion,
                "qso_conversion",
                "QSO must meet LoTW call, band, mode, date, time, and frequency requirements under the selected signing options; a received amateur call must have 3 to 20 letters, digits, or slashes, a letter and a digit, no leading or trailing slash, and no 0, Q, or unassigned 1 prefix",
            ),
            (
                CabrilloError::QsoAscii,
                "qso_ascii",
                "QSO syntax must be ASCII with space or tab field delimiters",
            ),
        ] {
            assert_eq!(problem.kind(), kind);
            assert_eq!(
                error(14, problem).to_string(),
                format!("line 14: {requirement}")
            );
        }
    }
}

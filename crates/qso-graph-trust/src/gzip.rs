// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! gzip (RFC 1952), one member, over `miniz_oxide`'s deflate: a signed log's `.tq8` written, and a
//! TQSL backup's `.tbk` read.
//!
//! Reading takes untrusted input that can hold private keys. The output is decompressed into one
//! buffer, made at the size the trailer states and never grown, so no copy of what it holds is left
//! in a freed block; it is wiped when dropped. The size is checked against a limit before anything
//! is made, and the CRC and length afterwards.

use std::fmt;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress as inflate, inflate_flags};
use zeroize::Zeroizing;

/// Why gzip input could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GzipError {
    /// Not gzip: no magic, a method other than deflate, reserved flags set, or a header cut short.
    NotGzip,
    /// Larger, decompressed, than the limit the caller set.
    TooLarge,
    /// The deflate data is damaged, ends early, or is followed by more than its trailer.
    Damaged,
    /// The CRC or length in the trailer is not the data's.
    WrongChecksum,
}

impl fmt::Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotGzip => "this is not a gzip file",
            Self::TooLarge => "this is larger than it may be once decompressed",
            Self::Damaged => "the compressed data is damaged",
            Self::WrongChecksum => "the compressed data does not match its checksum",
        })
    }
}

impl std::error::Error for GzipError {}

const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Data gzipped: one member, with no name and no time in its header, so the same data always gives
/// the same bytes.
pub fn compress(data: &[u8]) -> Vec<u8> {
    // ID1 ID2, deflate, no flags, no modification time, no extra flags, OS unknown.
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 9));
    out.extend(crc32(data).to_le_bytes());
    // ISIZE is the length modulo 2^32, as RFC 1952 defines it.
    out.extend((data.len() as u32).to_le_bytes());
    out
}

/// Whether these bytes begin as gzip does.
pub fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

/// One gzip member decompressed, no larger than `limit` bytes (at most 4 GiB, which the trailer can
/// state). Header fields are skipped as RFC 1952 lays them out; the trailer's CRC and length must be
/// the data's, and nothing may follow it.
pub fn decompress(bytes: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>, GzipError> {
    if bytes.len() < 18 || !is_gzip(bytes) || bytes[2] != 8 || bytes[3] & 0xe0 != 0 {
        return Err(GzipError::NotGzip);
    }
    let flags = bytes[3];
    let mut at = 10;
    let take = |at: &mut usize, n: usize| -> Result<(), GzipError> {
        *at = at
            .checked_add(n)
            .filter(|&end| end <= bytes.len() - 8)
            .ok_or(GzipError::NotGzip)?;
        Ok(())
    };
    if flags & FEXTRA != 0 {
        take(&mut at, 2)?;
        let len = usize::from(u16::from_le_bytes([bytes[at - 2], bytes[at - 1]]));
        take(&mut at, len)?;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let end = bytes[at..bytes.len() - 8]
                .iter()
                .position(|&b| b == 0)
                .ok_or(GzipError::NotGzip)?;
            take(&mut at, end + 1)?;
        }
    }
    if flags & FHCRC != 0 {
        take(&mut at, 2)?;
    }
    let (body, trailer) = bytes[at..].split_at(bytes.len() - at - 8);
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]) as usize;
    if size > limit {
        return Err(GzipError::TooLarge);
    }
    // One buffer at the stated size, plus a byte, so data longer than the trailer says is seen
    // rather than cut. It is never grown.
    let mut out = Zeroizing::new(vec![0u8; size + 1]);
    let mut state = Box::<DecompressorOxide>::default();
    let (status, read, written) = inflate(
        &mut state,
        body,
        &mut out,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    if status != TINFLStatus::Done || read != body.len() {
        return Err(GzipError::Damaged);
    }
    if written != size || crc32(&out[..written]) != crc {
        return Err(GzipError::WrongChecksum);
    }
    out.truncate(written);
    Ok(out)
}

/// The CRC-32 gzip carries (RFC 1952 section 8: polynomial 0xEDB88320, reflected).
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_is_gzips() {
        // RFC 1952's CRC-32 of "123456789", the standard check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn what_is_compressed_decompresses_to_itself() {
        let data = b"<TQSL_IDENT:4>test\n<Rec_Type:5>tCERT\n<eor>\n".repeat(50);
        let gz = compress(&data);
        assert_eq!(gz[..4], [0x1f, 0x8b, 8, 0]);
        assert_eq!(
            decompress(&gz, data.len()).as_deref().map(|v| v.as_slice()),
            Ok(&data[..])
        );
        assert_eq!(compress(&data), gz, "the same data, the same bytes");
    }

    #[test]
    fn a_header_with_a_name_comment_extra_and_crc_is_read() {
        let data = b"tqslconfig".repeat(20);
        let plain = compress(&data);
        let mut gz = plain[..10].to_vec();
        gz[3] = FHCRC | FEXTRA | FNAME | FCOMMENT;
        gz.extend([3, 0, b'a', b'b', b'c']);
        gz.extend(b"tqslconfig.tbk\0a comment\0");
        gz.extend([0, 0]);
        gz.extend(&plain[10..]);
        assert_eq!(
            decompress(&gz, 1 << 20).as_deref().map(|v| v.as_slice()),
            Ok(&data[..])
        );
    }

    #[test]
    fn damaged_lying_or_oversized_input_is_refused() {
        let data = b"abcdefgh".repeat(100);
        let gz = compress(&data);
        assert_eq!(
            decompress(b"not gzip at all, really", 1 << 20),
            Err(GzipError::NotGzip)
        );
        assert_eq!(decompress(&gz, data.len() - 1), Err(GzipError::TooLarge));
        // The trailer says less than there is: seen, not cut.
        let mut short = gz.clone();
        let n = short.len();
        short[n - 4..].copy_from_slice(&10u32.to_le_bytes());
        assert!(decompress(&short, 1 << 20).is_err());
        // A wrong CRC.
        let mut crc = gz.clone();
        crc[n - 8] ^= 1;
        assert_eq!(decompress(&crc, 1 << 20), Err(GzipError::WrongChecksum));
        // A damaged body.
        let mut body = gz.clone();
        body[12] ^= 0xff;
        assert!(decompress(&body, 1 << 20).is_err());
        // Reserved flags, and a name that never ends.
        let mut reserved = gz.clone();
        reserved[3] = 0x20;
        assert_eq!(decompress(&reserved, 1 << 20), Err(GzipError::NotGzip));
        let mut unended = gz[..10].to_vec();
        unended[3] = FNAME;
        unended.extend([b'x'; 20]);
        assert_eq!(decompress(&unended, 1 << 20), Err(GzipError::NotGzip));
        // A huge stated size is refused before anything is made.
        let mut huge = gz;
        huge[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decompress(&huge, 1 << 20), Err(GzipError::TooLarge));
    }
}

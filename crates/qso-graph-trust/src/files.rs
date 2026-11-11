// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Bounded reads of regular files, shared by the library and command line.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

/// Read at most `limit` bytes from a regular file. Symlinks to regular files are accepted.
/// On Unix the open is nonblocking, so a FIFO without a writer is refused without waiting.
/// The opened handle's type and size are checked before reading; the actual read is capped too,
/// even if the file grows. Special files return `InvalidInput`; excess bytes return `InvalidData`.
pub fn read_regular_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: Linux UAPI asm-generic/fcntl.h (x86-64 and ARM64), octal 00004000;
        // Darwin and the BSDs, sys/fcntl.h, 0x0004. Another Unix has its own value, so it
        // fails to build here rather than open with the wrong flag.
        #[cfg(target_os = "linux")]
        options.custom_flags(0o4000);
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        options.custom_flags(0x0004);
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        )))]
        compile_error!("O_NONBLOCK is not known for this Unix; add its value from its fcntl.h");
    }
    read_opened(options.open(path)?, limit)
}

fn read_opened(file: File, limit: usize) -> io::Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > limit as u64 {
        return Err(too_large());
    }
    read_bounded(file, limit)
}

fn read_bounded(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(too_large());
    }
    Ok(bytes)
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "file exceeds the byte limit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_reads_are_bounded_even_after_a_size_check() {
        // Model a reader whose contents exceed the metadata size checked by its caller.
        // Counting bytes read also proves we do not allocate or read the whole oversized input.
        let bytes = [b'x'; 2048];
        let mut reader = &bytes[..];
        assert_eq!(
            read_bounded(&mut reader, 1024).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.len(), bytes.len() - 1025);
        assert_eq!(read_bounded(&bytes[..1024], 1024).unwrap(), &bytes[..1024]);
        assert!(read_bounded(&b""[..], 0).unwrap().is_empty());
        assert!(read_bounded(&b"x"[..], 0).is_err());
    }
}

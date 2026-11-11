// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

#![forbid(unsafe_code)]
#[cfg(unix)]
mod unix {

    use qso_graph_trust::{
        files::read_regular_file,
        store::{KeyBackend, Listing, Store},
        tqsl_locations,
    };
    use std::{
        path::Path,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    #[test]
    fn review_fifo_reader_child() {
        let Some(folder) = std::env::var_os("QGT_REVIEW_FIFO_DIR") else {
            return;
        };
        let folder = Path::new(&folder);
        match std::env::var("QGT_REVIEW_FIFO_READER").unwrap().as_str() {
            "shared" => assert!(read_regular_file(&folder.join("input"), 1024).is_err()),
            "station" => assert!(tqsl_locations::read(folder).is_err()),
            "store" => assert!(Store::open(folder, KeyBackend::Memory).is_err()),
            "listing" => assert!(Listing::read(folder).is_err()),
            _ => panic!("unknown reader"),
        }
    }

    #[test]
    fn review_all_library_path_readers_refuse_fifos_without_waiting() {
        let folder = std::env::temp_dir().join(format!("qgt-file-readers-{}", std::process::id()));
        std::fs::create_dir(&folder).unwrap();
        for (reader, name) in [
            ("shared", "input"),
            ("station", "station_data"),
            ("store", "store.xml"),
            ("listing", "store.xml"),
        ] {
            let path = folder.join(name);
            // As in the review: a regular file is a successful control before planting the FIFO.
            std::fs::write(
                &path,
                if reader == "station" {
                    b"<StationDataFile/>".as_slice()
                } else {
                    b"test"
                },
            )
            .unwrap();
            assert!(read_regular_file(&path, 1024).is_ok());
            if reader == "station" {
                assert!(tqsl_locations::read(&folder).is_ok());
            }
            std::fs::remove_file(&path).unwrap();
            assert!(
                Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "unix::review_fifo_reader_child", "--nocapture"])
                .env("QGT_REVIEW_FIFO_DIR", &folder)
                .env("QGT_REVIEW_FIFO_READER", reader)
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let start = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break Some(status);
                }
                if start.elapsed() > Duration::from_secs(10) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            std::fs::remove_file(path).unwrap();
            if !status.is_some_and(|s| s.success()) {
                std::fs::remove_dir_all(&folder).unwrap();
                panic!("{reader} reader blocked or accepted a FIFO");
            }
        }
        std::fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn regular_files_have_byte_limits_and_special_files_are_refused() {
        let path = std::env::temp_dir().join(format!("qgt-file-bound-{}", std::process::id()));
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read_regular_file(&path, 4).unwrap(), b"1234");
        assert_eq!(
            read_regular_file(&path, 3).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let link = path.with_extension("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_regular_file(&link, 4).unwrap(), b"1234");
        assert!(read_regular_file(Path::new("/dev/null"), 1024).is_err());
        assert!(read_regular_file(&std::env::temp_dir(), 1024).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

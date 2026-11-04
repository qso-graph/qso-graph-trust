// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! TQSL-compatible duplicate records. Preparing and signing are read-only; only a successful
//! output write records the selection. Plans are snapshots: another writer may sign the same
//! QSO after inspection. Recording merges under the store lock, without losing its writes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Store, StoreError, format, owner_file, sync_directory};
use crate::certificate::Certificate;
use crate::lotw;
use crate::qso::Qso;
use crate::signed_log::{LogError, sign_log, tq8};
use crate::signing::TqslKey;
use crate::station::StationLocation;
use crate::tbk::Backup;

/// Maximum record count, also subject to the store's 32 MiB file limit.
pub const MAX_SIGNED_QSOS: usize = 100_000;
/// Maximum distinct station descriptions in the record.
pub const MAX_SIGNED_STATIONS: usize = 4096;
/// Maximum bytes in an imported opaque key (including older TQSL key formats).
pub const MAX_SIGNED_KEY_LEN: usize = 1024;
/// Maximum bytes in a station description.
pub const MAX_SIGNED_STATION_LEN: usize = 2048;

/// One signed QSO. Imported records have no signing timestamp: TQSL does not keep one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedQso {
    /// TQSL's exact, case-sensitive duplicate key, without hashing or encoding.
    pub key: String,
    /// Station fields as recorded, not a mutable location name.
    pub station: String,
    /// Signing time in Unix seconds, if recorded by QGT.
    pub signed_at: Option<u64>,
}

/// The operator's choice after inspecting a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateChoice {
    /// Sign only new QSOs, including updates that add station details as TQSL permits.
    NewOnly,
    /// Sign every QSO in input order, including those signed before.
    SignAgain,
    /// Produce nothing and change no records.
    Cancel,
}

/// An input QSO identified as signed before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviouslySigned {
    /// Its zero-based index in the input log.
    pub index: usize,
    /// The previous station and signing time (if known).
    pub previous: SignedQso,
}

/// An immutable snapshot of a log partitioned against the record, in input order.
#[derive(Clone, Debug)]
pub struct SigningPlan {
    qsos: Vec<Qso>,
    station: StationLocation,
    new: Vec<usize>,
    signed_before: Vec<PreviouslySigned>,
}
impl SigningPlan {
    /// Input indices which can be signed as new.
    pub fn new_indices(&self) -> &[usize] {
        &self.new
    }

    /// Input indices signed before, with the previous station and optional time.
    pub fn signed_before(&self) -> &[PreviouslySigned] {
        &self.signed_before
    }

    /// Select the QSOs. Cancellation returns `None`. An empty new-only selection will report
    /// `LogError::Empty` if signed, just as `sign_log` does.
    pub fn choose(&self, choice: DuplicateChoice) -> Option<SigningSelection> {
        let qsos = match choice {
            DuplicateChoice::Cancel => return None,
            DuplicateChoice::SignAgain => self.qsos.clone(),
            DuplicateChoice::NewOnly => self.new.iter().map(|&i| self.qsos[i].clone()).collect(),
        };
        Some(SigningSelection {
            qsos,
            station: self.station.clone(),
        })
    }
}

/// A selected log; its QSOs and station cannot change between signing and recording.
pub struct SigningSelection {
    qsos: Vec<Qso>,
    station: StationLocation,
}
impl SigningSelection {
    /// Selected QSOs, in input order.
    pub fn qsos(&self) -> &[Qso] {
        &self.qsos
    }

    /// Sign with the existing byte-for-byte `sign_log` path, then gzip as a `.tq8`.
    /// This alone never records a QSO as signed.
    pub fn sign(
        &self,
        cert: &Certificate,
        key: &TqslKey,
        now: SystemTime,
    ) -> Result<SignedLog, LogError> {
        let bytes = tq8(&sign_log(cert, key, &self.station, &self.qsos, now)?);
        let signed_at = now.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
        let station = station_details(&self.station);
        let records = self
            .qsos
            .iter()
            .map(|q| SignedQso {
                key: duplicate_key(q, &self.station),
                station: station.clone(),
                signed_at,
            })
            .collect();
        Ok(SignedLog { bytes, records })
    }
}

/// A signed `.tq8` and the exact selection it represents. Not yet in the store's record.
pub struct SignedLog {
    bytes: Vec<u8>,
    records: Vec<SignedQso>,
}
impl SignedLog {
    /// The signed `.tq8` bytes. Inspecting them does not record anything.
    pub fn tq8(&self) -> &[u8] {
        &self.bytes
    }

    /// Create and sync a new output file, then atomically merge the record under the store lock.
    /// Preflight validates the resulting record and file size before creating output. A failed
    /// output write records nothing. If store replacement fails after output was written, the
    /// output remains; report the error and retain it for recovery. Existing output and reserved
    /// store filenames (`store.xml`, `store.xml.partial`, `store.lock`) are refused.
    ///
    /// TQSL stages entries during conversion (tqslconvert.cpp:1956) and commits explicitly
    /// (2097–2108), not on upload. The corpus driver commits after closing successful output
    /// (tests/tqsllib/qgt-tqsllib.cpp:230–241). Here the write is synced before record replacement.
    pub fn write_to(&self, store: &Store, path: &Path) -> Result<(), StoreError> {
        if path.file_name().is_some_and(|name| {
            matches!(
                name.to_str(),
                Some("store.xml" | "store.xml.partial" | "store.lock")
            )
        }) {
            return Err(StoreError::Invalid("reserved output name"));
        }
        let _lock = store.lock()?;
        let mut data = store.read()?;
        merge(&mut data.signed_qsos, &self.records, true)?;
        let xml = format::write(&data)?;
        let mut output = owner_file().create_new(true).open(path)?;
        output.write_all(&self.bytes)?;
        output.sync_all()?;
        drop(output);
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory(parent)?;
        store.replace(&xml)
    }
}

/// TQSL 2.8.7's key: local call + contact fields in ARRL's signature-specification order.
/// Includes frequency text, mapped LoTW mode and exact seconds; excludes station fields,
/// certificate serial and station name. TQSL's `snprintf` limits the result to 127 bytes
/// (tqslconvert.cpp:1836–1839). Qso's normalized fields are ASCII, so truncation is safe.
/// No seconds are rounded here: any ignore-seconds setting must also affect what is signed.
pub fn duplicate_key(qso: &Qso, station: &StationLocation) -> String {
    let mut key = format!("{}{}", station.call(), qso.sign_data());
    key.truncate(127);
    key
}

fn station_details(station: &StationLocation) -> String {
    lotw::SIGN_STATION
        .iter()
        .filter_map(|name| {
            station
                .get(name)
                .filter(|v| !v.is_empty())
                .map(|value| format!("{name}: {value}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// TQSL permits enriching station details when no previously nonempty, shared field changes.
// Equality (ignoring case) or a conflicting shared field is a duplicate. Comma splitting and
// ASCII-space removal follow tqslconvert.cpp:1892–1942, including multi-grid descriptions.
fn signed_before(previous: &str, current: &str) -> bool {
    if previous.eq_ignore_ascii_case(current) {
        return true;
    }
    let old = previous.replace(' ', "");
    let new = current.replace(' ', "");
    old.split(',').any(|entry| {
        let key_end = entry.find(':').map_or(0, |i| i + 1);
        let key = &entry[..key_end];
        new.split(',')
            .find(|v| &v[..v.find(':').map_or(0, |i| i + 1)] == key)
            .is_some_and(|value| entry != key && entry != value)
    })
}

pub(super) fn validate(records: &BTreeMap<String, SignedQso>) -> Result<(), StoreError> {
    if records.len() > MAX_SIGNED_QSOS {
        return Err(StoreError::Limit("signed QSOs"));
    }
    let mut stations = BTreeSet::new();
    for (key, record) in records {
        check_record(record)?;
        if key != &record.key {
            return Err(StoreError::Invalid("signed QSO key"));
        }
        stations.insert(&record.station);
        if stations.len() > MAX_SIGNED_STATIONS {
            return Err(StoreError::Limit("signed stations"));
        }
    }
    Ok(())
}

pub(super) fn check_record(record: &SignedQso) -> Result<(), StoreError> {
    if record.key.len() > MAX_SIGNED_KEY_LEN || record.station.len() > MAX_SIGNED_STATION_LEN {
        return Err(StoreError::Limit("signed QSO bytes"));
    }
    if record.key.is_empty() || !record.key.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return Err(StoreError::Invalid("signed QSO key"));
    }
    if record.station.chars().any(|c| {
        (c < ' ' && !matches!(c, '\t' | '\n' | '\r')) || matches!(c, '\u{fffe}' | '\u{ffff}')
    }) {
        return Err(StoreError::Invalid("signed station character"));
    }
    // Values remain opaque so older backup formats survive.
    Ok(())
}

fn merge(
    target: &mut BTreeMap<String, SignedQso>,
    entries: &[SignedQso],
    overwrite: bool,
) -> Result<usize, StoreError> {
    if entries.len() > MAX_SIGNED_QSOS {
        return Err(StoreError::Limit("signed QSOs"));
    }
    let before = target.len();
    for entry in entries {
        check_record(entry)?;
        if overwrite || !target.contains_key(&entry.key) {
            target.insert(entry.key.clone(), entry.clone());
        }
        if target.len() > MAX_SIGNED_QSOS {
            return Err(StoreError::Limit("signed QSOs"));
        }
    }
    validate(target)?;
    Ok(target.len() - before)
}

impl Store {
    /// List signed QSOs in key order, from a single locked snapshot.
    pub fn signed_qsos(&self) -> Result<Vec<SignedQso>, StoreError> {
        let _lock = self.lock()?;
        Ok(self.read()?.signed_qsos.into_values().collect())
    }

    /// Look up an exact TQSL key, independent of any current station location name.
    pub fn signed_qso(&self, key: &str) -> Result<Option<SignedQso>, StoreError> {
        let _lock = self.lock()?;
        Ok(self.read()?.signed_qsos.remove(key))
    }

    /// Merge public signed-QSO records, retaining existing entries and their richer timestamps.
    /// Returns the number added. Invalid input or limits leave the file unchanged.
    pub fn add_signed_qsos(&self, entries: &[SignedQso]) -> Result<usize, StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let count = merge(&mut data.signed_qsos, entries, false)?;
        if count != 0 {
            self.replace(&format::write(&data)?)?;
        }
        Ok(count)
    }

    /// Import only TQSL's signed-QSO record, merging without replacing other store contents.
    pub fn import_signed_qsos(&self, backup: &Backup) -> Result<usize, StoreError> {
        if backup.signed_qsos.len() > MAX_SIGNED_QSOS {
            return Err(StoreError::Limit("signed QSOs"));
        }
        self.add_signed_qsos(
            &backup
                .signed_qsos
                .iter()
                .map(|q| SignedQso {
                    key: q.key.clone(),
                    station: q.station.clone(),
                    signed_at: None,
                })
                .collect::<Vec<_>>(),
        )
    }

    /// Wipe just the signed-QSO record. Returns the number removed.
    pub fn wipe_signed_qsos(&self) -> Result<usize, StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let count = data.signed_qsos.len();
        data.signed_qsos.clear();
        self.replace(&format::write(&data)?)?;
        Ok(count)
    }

    /// Partition a log against a locked snapshot. Repeats within the input are checked against
    /// earlier new entries too, as TQSL's uncommitted transaction does during conversion.
    pub fn prepare_signing(
        &self,
        qsos: &[Qso],
        station: &StationLocation,
    ) -> Result<SigningPlan, StoreError> {
        if qsos.len() > MAX_SIGNED_QSOS {
            return Err(StoreError::Limit("signing QSOs"));
        }
        let mut seen = {
            let _lock = self.lock()?;
            self.read()?.signed_qsos
        };
        let details = station_details(station);
        let mut plan = SigningPlan {
            qsos: qsos.to_vec(),
            station: station.clone(),
            new: Vec::new(),
            signed_before: Vec::new(),
        };
        for (index, qso) in qsos.iter().enumerate() {
            let key = duplicate_key(qso, station);
            if let Some(previous) = seen
                .get(&key)
                .filter(|p| signed_before(&p.station, &details))
            {
                plan.signed_before.push(PreviouslySigned {
                    index,
                    previous: previous.clone(),
                });
            } else {
                seen.insert(
                    key.clone(),
                    SignedQso {
                        key,
                        station: details.clone(),
                        signed_at: None,
                    },
                );
                plan.new.push(index);
            }
        }
        Ok(plan)
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::time::SystemTime;

use zeroize::Zeroizing;

use super::roots::{self, RootSource};
use super::{
    Data, MAX_KEY_LEN, Store, StoreError, StoredCertificate, StoredLocation, format, keys,
};
use crate::certificate::{Certificate, CertificateError, FoundRoot, Trust, parse_fingerprint};
use crate::import::{self, ImportError, ImportRefusal, ImportedCertificate};
use crate::qso::Date;
use crate::signing::{KeyEntry, KeyError, TqslKey};
use crate::station::StationLocation;
use crate::tbk::{self, BackedUpLocation, Preferences};

/// The effect of importing one preview entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportDisposition {
    /// Added, or an existing keyless certificate receives a key.
    New,
    /// Kept as it is in the store.
    Present,
    /// Cannot be imported; the explanation contains no private input.
    Refused {
        /// Why the item is refused.
        reason: String,
    },
}

/// Public certificate and key details, without a certificate's email or encoded contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportCertificate {
    /// Callsign from the certificate or pending request.
    pub callsign: String,
    /// ARRL DXCC entity number.
    pub dxcc: u32,
    /// Certificate serial, big-endian; empty for a request without a certificate.
    pub serial: Vec<u8>,
    /// Allowed QSO date range, absent for an unanswered request.
    pub qso_dates: Option<(Date, Date)>,
    /// X.509 validity range, absent for an unanswered request.
    pub validity: Option<(SystemTime, SystemTime)>,
    /// Planned effect on the store.
    pub disposition: ImportDisposition,
    /// The file contains a key for this entry.
    pub file_has_key: bool,
    /// A matching key is already in the credential store.
    pub key_present: bool,
    /// Supply a password with `PendingImport::unlock_key` before committing.
    pub needs_password: bool,
}

/// A new root that must be explicitly accepted at commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRoot {
    /// Root subject common name.
    pub subject: String,
    /// Canonical SHA-256 fingerprint.
    pub fingerprint: String,
}

/// A checked backup location and its disposition in this store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportLocation {
    /// Station location name from the backup.
    pub name: String,
    /// Checked station fields, ready for the caller to place.
    pub station: StationLocation,
    /// Whether this name is new or already present in this store. Existing names are retained.
    pub disposition: ImportDisposition,
}

/// Public, immutable view of an inspected import. No email, password or private key is exposed.
#[derive(Debug)]
pub struct ImportPreview {
    /// Entries in file order, including unanswered backup requests.
    pub certificates: Vec<ImportCertificate>,
    /// Roots the file needs that the store does not yet trust.
    pub roots: Vec<ImportRoot>,
    /// Checked station locations; the caller chooses where to place them.
    pub locations: Vec<ImportLocation>,
    /// Number of signed-QSO records in the file.
    pub signed_qsos: usize,
    /// Total UTF-8 bytes in the backup signed-QSO keys and station records.
    pub signed_qso_bytes: usize,
    /// Backup signing preferences, if any.
    pub preferences: Preferences,
}

/// Commit decisions. Every new root must be named explicitly, for every file format.
#[derive(Default)]
pub struct ImportChoices<'a> {
    /// SHA-256 fingerprints from the preview (colonless or lowercase forms also accepted).
    pub accept_roots: &'a [&'a str],
    /// Place backup locations in this store, retaining existing names. Otherwise return them.
    pub store_locations: bool,
    /// Explicitly omit refused entries, such as unanswered backup requests. Defaults to false.
    pub skip_refused: bool,
}

/// The public result of one complete commit.
#[derive(Debug)]
pub struct ImportReport {
    /// Installed or already-present certificates, in preview order, excluding skipped entries.
    pub certificates: Vec<ImportedCertificate>,
    /// Newly accepted roots.
    pub roots: Vec<super::TrustedRoot>,
    /// Backup locations for the caller to place (also returned when stored here).
    pub locations: Vec<BackedUpLocation>,
    /// Number of station locations added to this store.
    pub locations_added: usize,
    /// Number of signed-QSO records added.
    pub signed_qsos_added: usize,
}

struct PendingKey {
    locked: Option<KeyEntry>,
    der: Option<Zeroizing<Vec<u8>>>,
    spki: Vec<u8>,
    target: Option<String>,
}

/// An inspected import bound to its Store. Consuming commit never reads the source file again.
/// Secret buffers are private and zeroized on drop, including cancellation and failed commits.
/// This type deliberately implements neither Debug, Clone nor Serialize.
///
/// ```compile_fail
/// use qso_graph_trust::store::PendingImport;
/// fn log_pending(pending: &PendingImport) { println!("{pending:?}"); }
/// ```
///
/// ```compile_fail
/// use qso_graph_trust::store::PendingImport;
/// fn change_preview(pending: &PendingImport) { pending.preview().certificates.clear(); }
/// ```
///
/// Protected backup keys being installed require `unlock_key` to complete inspection. Present
/// entries keep their stored keys and need no backup password. A password failure names its
/// preview index, changes neither store, and leaves this value available to retry.
pub struct PendingImport {
    owner: std::sync::Arc<()>,
    before: String,
    after: Data,
    preview: ImportPreview,
    keys: Vec<PendingKey>,
    presence: Vec<(String, bool)>,
    request_keys: Vec<(String, Zeroizing<Vec<u8>>)>,
    refusals: Vec<(usize, ImportRefusal)>,
    reports: Vec<ImportedCertificate>,
    added_roots: Vec<super::TrustedRoot>,
    signed_added: usize,
}

impl PendingImport {
    /// Read the public preview. The caller cannot modify what commit will install.
    pub fn preview(&self) -> &ImportPreview {
        &self.preview
    }

    /// Complete inspection of the protected key at this preview index. The password is borrowed,
    /// never retained. Wrong passwords and key/certificate mismatches identify this entry only.
    pub fn unlock_key(&mut self, index: usize, password: &[u8]) -> Result<(), ImportError> {
        if password.len() > import::MAX_PASSWORD_LEN {
            return Err(ImportError::Limit);
        }
        let key = self.keys.get_mut(index).ok_or(ImportError::Malformed)?;
        let Some(locked) = key.locked.as_ref() else {
            return Err(ImportError::Malformed);
        };
        let der = checked_key(locked, Some(password), &key.spki)
            .map_err(|error| ImportError::KeyAt { index, error })?;
        key.der = Some(der);
        key.locked = None;
        self.preview.certificates[index].needs_password = false;
        Ok(())
    }
}

fn checked_key(
    key: &KeyEntry,
    password: Option<&[u8]>,
    spki: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let der = key.pkcs8_der(password)?;
    if der.len() > MAX_KEY_LEN {
        return Err(KeyError::FileTooLarge);
    }
    TqslKey::from_pkcs8_der(&der, spki)?;
    Ok(der)
}

impl PendingImport {
    fn new(owner: &Store, data: Data) -> Result<Self, ImportError> {
        let mut presence = Vec::new();
        for name in data
            .certificates
            .iter()
            .filter_map(|c| c.key_name.as_ref())
            .chain(data.pending_requests.iter().map(|r| &r.key_name))
        {
            presence.push((
                name.clone(),
                owner.keys.exists(name).map_err(StoreError::from)?,
            ));
        }
        Ok(Self {
            owner: std::sync::Arc::clone(&owner.import_identity),
            before: format::write(&data)?,
            after: data,
            preview: ImportPreview {
                certificates: Vec::new(),
                roots: Vec::new(),
                locations: Vec::new(),
                signed_qsos: 0,
                signed_qso_bytes: 0,
                preferences: Preferences::default(),
            },
            keys: Vec::new(),
            presence,
            request_keys: Vec::new(),
            refusals: Vec::new(),
            reports: Vec::new(),
            added_roots: Vec::new(),
            signed_added: 0,
        })
    }

    fn roots(&mut self, found: &[FoundRoot], source: RootSource) -> Result<(), ImportError> {
        self.preview.roots = found
            .iter()
            .map(|r| ImportRoot {
                subject: r.subject.clone(),
                fingerprint: r.fingerprint.clone(),
            })
            .collect();
        self.added_roots = roots::add(&mut self.after, found, source)?;
        Ok(())
    }

    fn certificate(
        &mut self,
        owner: &Store,
        certificate: Certificate,
        refusal: Option<CertificateError>,
        key: Option<KeyEntry>,
        der: Option<Zeroizing<Vec<u8>>>,
        attach_request: bool,
    ) -> Result<(), ImportError> {
        let index = self.keys.len();
        let file_has_key = key.is_some() || der.is_some();
        let mut material = PendingKey {
            locked: key,
            der,
            spki: certificate.public_key_der().to_vec(),
            target: None,
        };
        let existing = self
            .after
            .certificates
            .iter()
            .position(|c| c.certificate.der() == certificate.der());
        let mut key_present = existing
            .and_then(|i| self.after.certificates[i].key_name.as_ref())
            .is_some_and(|name| {
                self.presence
                    .iter()
                    .any(|(n, present)| n == name && *present)
            });
        let request = attach_request
            .then(|| {
                self.after.pending_requests.iter().position(|r| {
                    r.public_key_der == certificate.public_key_der()
                        && r.callsign == certificate.callsign()
                        && r.dxcc == certificate.dxcc()
                })
            })
            .flatten();
        key_present |= request.is_some_and(|i| {
            let name = &self.after.pending_requests[i].key_name;
            self.presence
                .iter()
                .any(|(n, present)| n == name && *present)
        });
        let already_here = existing.is_some_and(|i| {
            self.after.certificates[i].key_name.is_some() || (!file_has_key && request.is_none())
        });
        let refusal = refusal.map(|_| ImportRefusal::Certificate).or_else(|| {
            (existing.is_none() && self.after.certificates.len() >= super::MAX_CERTIFICATES)
                .then_some(ImportRefusal::CertificateLimit)
        });
        let disposition = if let Some(category) = refusal {
            let reason = category.to_string();
            self.refusals.push((index, category));
            ImportDisposition::Refused { reason }
        } else if already_here {
            // Present means keep the stored certificate and credential exactly as they are.
            // The file's unused key needs neither a password nor key validation.
            material.locked = None;
            material.der = None;
            let existing = &self.after.certificates[existing.expect("existing certificate")];
            self.reports.push(ImportedCertificate {
                id: existing.id.clone(),
                has_key: existing.key_name.is_some(),
                attached_request: false,
                already_here: true,
            });
            ImportDisposition::Present
        } else {
            if let Some(key) = &material.locked
                && !key.is_encrypted()
            {
                material.der = Some(
                    checked_key(key, None, &material.spki)
                        .map_err(|error| ImportError::KeyAt { index, error })?,
                );
                material.locked = None;
            }
            let key_name = if file_has_key {
                let name = keys::new_name("key:")?;
                if owner.keys.exists(&name).map_err(StoreError::from)? {
                    return Err(StoreError::AlreadyExists.into());
                }
                material.target = Some(name.clone());
                Some(name)
            } else if let Some(i) = request {
                let name = self.after.pending_requests[i].key_name.clone();
                let der = owner
                    .keys
                    .get(&name)
                    .map_err(StoreError::from)?
                    .ok_or(StoreError::NotFound)?;
                if der.len() > MAX_KEY_LEN {
                    return Err(StoreError::Limit("credential bytes").into());
                }
                TqslKey::from_pkcs8_der(&der, certificate.public_key_der())?;
                self.request_keys.push((name.clone(), der));
                self.after.pending_requests.remove(i);
                Some(name)
            } else {
                None
            };
            let id = if let Some(i) = existing {
                self.after.certificates[i].key_name = key_name.clone();
                self.after.certificates[i].id.clone()
            } else {
                let id = keys::new_name("cert:")?;
                if self.after.certificates.iter().any(|c| c.id == id) {
                    return Err(StoreError::AlreadyExists.into());
                }
                self.after.certificates.push(StoredCertificate {
                    id: id.clone(),
                    certificate: certificate.clone(),
                    key_name: key_name.clone(),
                });
                id
            };
            self.reports.push(ImportedCertificate {
                id,
                has_key: key_name.is_some(),
                attached_request: request.is_some(),
                already_here: false,
            });
            ImportDisposition::New
        };
        self.preview.certificates.push(ImportCertificate {
            callsign: certificate.callsign().into(),
            dxcc: certificate.dxcc(),
            serial: certificate.serial_number().to_vec(),
            qso_dates: Some(certificate.qso_dates()),
            validity: Some(certificate.validity()),
            disposition,
            file_has_key,
            key_present,
            needs_password: material.locked.is_some(),
        });
        self.keys.push(material);
        Ok(())
    }
}

impl Store {
    /// Inspect an ARRL `.tq6`, including possible request-key attachments, without changing either
    /// store. Invalid chains are described as refused entries. New roots need commit confirmation.
    pub fn inspect_tq6(&self, bytes: &[u8], trust: &Trust) -> Result<PendingImport, ImportError> {
        let _lock = self.lock()?;
        let data = self.read()?;
        let trust = roots::extend(trust, &data);
        let (users, authorities) = import::tq6_contents(bytes)?;
        let (certificates, found) = import::inspect_certificates(&users, &authorities, &trust)?;
        let mut pending = PendingImport::new(self, data)?;
        pending.roots(&found, RootSource::Tq6)?;
        for (certificate, refusal) in certificates {
            pending.certificate(self, certificate, refusal, None, None, true)?;
        }
        format::write(&pending.after)?;
        Ok(pending)
    }

    /// Authenticate and inspect a `.p12` without mutation. PKCS#12 encrypts certificate metadata
    /// too, so its password is required here. Decrypted keys remain private and wiped on drop.
    pub fn inspect_pkcs12(
        &self,
        bytes: &[u8],
        password: &[u8],
        trust: &Trust,
    ) -> Result<PendingImport, ImportError> {
        let _lock = self.lock()?;
        let data = self.read()?;
        let loaded = crate::pkcs12::inspect(bytes, password, &roots::extend(trust, &data))?;
        let mut pending = PendingImport::new(self, data)?;
        pending.roots(&loaded.roots, RootSource::P12)?;
        pending.certificate(
            self,
            loaded.certificate,
            loaded.refusal,
            None,
            Some(loaded.key),
            false,
        )?;
        format::write(&pending.after)?;
        Ok(pending)
    }

    /// Inspect a TQSL backup without mutation. Protected keys are identified by preview index,
    /// callsign and serial; complete their checks with `PendingImport::unlock_key` when installing
    /// them. Present entries retain their stored keys without checking unused backup keys. Unanswered
    /// requests are refused entries, which the caller can explicitly skip. Locations are returned
    /// by commit unless its choices ask to store them here.
    pub fn inspect_tbk(&self, bytes: &[u8], trust: &Trust) -> Result<PendingImport, ImportError> {
        let _lock = self.lock()?;
        let data = self.read()?;
        let trust = roots::extend(trust, &data);
        let backup = tbk::inspect(bytes, &trust).map_err(ImportError::Backup)?;
        let found = backup.found_roots(&trust);
        let trust = trust.with_found(&found);
        let mut pending = PendingImport::new(self, data)?;
        pending.roots(&found, RootSource::Tbk)?;
        for entry in backup.certificates {
            if let Some(certificate) = entry.certificate {
                let refusal = certificate.verify(&trust, &backup.authorities).err();
                pending.certificate(self, certificate, refusal, entry.key, None, false)?;
            } else {
                let index = pending.keys.len();
                pending.preview.certificates.push(ImportCertificate {
                    callsign: entry.callsign,
                    dxcc: entry.dxcc,
                    serial: Vec::new(),
                    qso_dates: None,
                    validity: None,
                    disposition: ImportDisposition::Refused {
                        reason: "a request still waiting for ARRL".into(),
                    },
                    file_has_key: entry.key.is_some(),
                    key_present: false,
                    needs_password: false,
                });
                pending.keys.push(PendingKey {
                    locked: None,
                    der: None,
                    spki: Vec::new(),
                    target: None,
                });
                pending
                    .refusals
                    .push((index, ImportRefusal::PendingRequest));
            }
        }
        let signed: Vec<super::SignedQso> = backup
            .signed_qsos
            .iter()
            .map(|q| super::SignedQso {
                key: q.key.clone(),
                station: q.station.clone(),
                signed_at: None,
            })
            .collect();
        pending.signed_added =
            super::signed::merge(&mut pending.after.signed_qsos, &signed, false)?;
        pending.preview.signed_qsos = backup.signed_qsos.len();
        pending.preview.signed_qso_bytes = backup
            .signed_qsos
            .iter()
            .map(|q| q.key.len() + q.station.len())
            .sum();
        pending.preview.locations = backup
            .locations
            .into_iter()
            .map(|location| {
                let disposition = if pending
                    .after
                    .locations
                    .iter()
                    .any(|l| l.name == location.name)
                {
                    ImportDisposition::Present
                } else {
                    ImportDisposition::New
                };
                ImportLocation {
                    name: location.name,
                    station: location.station,
                    disposition,
                }
            })
            .collect();
        pending.preview.preferences = backup.preferences;
        format::write(&pending.after)?;
        Ok(pending)
    }

    /// Consume exactly the inspected plan under the store lock. A changed public snapshot,
    /// missing/changed request key, unconfirmed root, refused entry or unchecked protected key
    /// refuses the whole commit before any write. Staged credentials roll back on publication
    /// failure. As with other Store writes, a post-replacement durability error keeps all keys;
    /// a failed credential rollback is reported explicitly as `StoreError::Rollback`.
    pub fn commit(
        &self,
        mut pending: PendingImport,
        choices: ImportChoices<'_>,
    ) -> Result<ImportReport, ImportError> {
        if !std::sync::Arc::ptr_eq(&self.import_identity, &pending.owner) {
            return Err(ImportError::Conflict);
        }
        let _lock = self.lock()?;
        if format::write(&self.read()?)? != pending.before {
            return Err(ImportError::Conflict);
        }
        for (name, present) in &pending.presence {
            if self.keys.exists(name).map_err(StoreError::from)? != *present {
                return Err(ImportError::Conflict);
            }
        }
        for (name, expected) in &pending.request_keys {
            if self.keys.get(name).map_err(StoreError::from)?.as_deref() != Some(expected) {
                return Err(ImportError::Conflict);
            }
        }
        for given in choices.accept_roots {
            let canonical = parse_fingerprint(given);
            if !pending
                .preview
                .roots
                .iter()
                .any(|r| canonical.as_deref() == Some(&r.fingerprint))
            {
                return Err(ImportError::RootMismatch {
                    given: canonical.unwrap_or_default(),
                });
            }
        }
        if !choices.skip_refused
            && let Some(&(index, reason)) = pending.refusals.first()
        {
            return Err(ImportError::Refused { index, reason });
        }
        for root in &pending.preview.roots {
            if !choices
                .accept_roots
                .iter()
                .any(|given| parse_fingerprint(given).as_deref() == Some(&root.fingerprint))
            {
                return Err(ImportError::UntrustedRoot {
                    subject: root.subject.clone(),
                    fingerprint: root.fingerprint.clone(),
                });
            }
        }
        for (index, key) in pending.keys.iter().enumerate() {
            if choices.skip_refused && pending.refusals.iter().any(|(i, _)| *i == index) {
                continue;
            }
            if key.locked.is_some() {
                return Err(ImportError::KeyAt {
                    index,
                    error: KeyError::PasswordNeeded,
                });
            }
        }
        let mut locations_added = 0;
        if choices.store_locations {
            let empty = pending.after.locations.is_empty();
            for location in &pending.preview.locations {
                if pending
                    .after
                    .locations
                    .iter()
                    .any(|l| l.name == location.name)
                {
                    continue;
                }
                if pending.after.locations.len() >= super::MAX_LOCATIONS {
                    return Err(StoreError::Limit("locations").into());
                }
                pending.after.locations.push(StoredLocation {
                    name: location.name.clone(),
                    station: location.station.clone(),
                });
                locations_added += 1;
            }
            if empty && locations_added == 1 {
                pending.after.default_location =
                    pending.after.locations.first().map(|l| l.name.clone());
            }
        }
        let xml = format::write(&pending.after)?;
        let mut names = Vec::new();
        for key in &pending.keys {
            if let Some(name) = &key.target {
                if names.contains(name) || self.keys.exists(name).map_err(StoreError::from)? {
                    return Err(ImportError::Conflict);
                }
                names.push(name.clone());
            }
        }
        let mut written = Vec::new();
        for key in &pending.keys {
            if let Some(name) = &key.target {
                let der = key.der.as_ref().ok_or(ImportError::Malformed)?;
                if let Err(error) = self.keys.put(name, der) {
                    return Err(self.rollback_import(&written, error.into()).into());
                }
                written.push(name.clone());
            }
        }
        if xml != pending.before
            && let Err(error) = self.replace(&xml)
        {
            if matches!(error, StoreError::Durability(_)) {
                return Err(error.into());
            }
            return Err(self.rollback_import(&written, error).into());
        }
        Ok(ImportReport {
            certificates: pending.reports,
            roots: pending.added_roots,
            locations: pending
                .preview
                .locations
                .into_iter()
                .map(|l| BackedUpLocation {
                    name: l.name,
                    station: l.station,
                })
                .collect(),
            locations_added,
            signed_qsos_added: pending.signed_added,
        })
    }

    fn rollback_import(&self, names: &[String], write: StoreError) -> StoreError {
        let mut failed = None;
        for name in names {
            if let Err(error) = self.keys.delete(name) {
                failed.get_or_insert(error);
            }
        }
        match failed {
            Some(cleanup) => StoreError::Rollback {
                write: Box::new(write),
                cleanup,
            },
            None => write,
        }
    }
}

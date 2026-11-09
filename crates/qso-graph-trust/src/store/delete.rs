// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

use std::sync::Arc;
use std::time::SystemTime;

use super::{Store, StoreError, format};
use crate::qso::Date;

/// Public details of the certificate to delete, without email or encoded certificate contents.
#[derive(Debug, PartialEq, Eq)]
pub struct DeletePreview {
    /// Callsign from the certificate.
    pub callsign: String,
    /// ARRL DXCC entity number.
    pub dxcc: u32,
    /// Certificate serial, big-endian.
    pub serial: Vec<u8>,
    /// Allowed QSO date range.
    pub qso_dates: (Date, Date),
    /// X.509 validity range.
    pub validity: (SystemTime, SystemTime),
    /// The certificate's referenced key is currently installed in the credential store.
    pub key_present: bool,
}

/// An inspected deletion bound to its Store instance. Dropping it cancels without changes.
/// This owned value can span UI commands. Moving the Store preserves its identity; reopening
/// the folder requires a fresh inspection. This type implements neither Debug, Clone nor Serialize.
///
/// ```compile_fail
/// use qso_graph_trust::store::PendingDelete;
/// fn log_pending(pending: &PendingDelete) { println!("{pending:?}"); }
/// ```
///
/// ```compile_fail
/// use qso_graph_trust::store::PendingDelete;
/// fn clone_pending(pending: &PendingDelete) -> PendingDelete { pending.clone() }
/// ```
///
/// ```compile_fail
/// use qso_graph_trust::store::PendingDelete;
/// fn change_preview(pending: &PendingDelete) { pending.preview().callsign.clear(); }
/// ```
pub struct PendingDelete {
    owner: Arc<()>,
    before: String,
    id: String,
    preview: DeletePreview,
}

impl PendingDelete {
    /// Read the public preview. The caller cannot change which certificate commit deletes.
    pub fn preview(&self) -> &DeletePreview {
        &self.preview
    }
}

impl Store {
    /// Inspect a certificate deletion under the store lock without changing records or credentials.
    /// Captures the same canonical public snapshot as import, plus the referenced key's presence.
    pub fn inspect_delete(&self, id: &str) -> Result<PendingDelete, StoreError> {
        let _lock = self.lock()?;
        let data = self.read()?;
        let stored = data
            .certificates
            .iter()
            .find(|c| c.id == id)
            .ok_or(StoreError::NotFound)?;
        let key_present = match &stored.key_name {
            Some(name) => self.keys.exists(name)?,
            None => false,
        };
        let certificate = &stored.certificate;
        Ok(PendingDelete {
            owner: Arc::clone(&self.import_identity),
            before: format::write(&data)?,
            id: stored.id.clone(),
            preview: DeletePreview {
                callsign: certificate.callsign().into(),
                dxcc: certificate.dxcc(),
                serial: certificate.serial_number().to_vec(),
                qso_dates: certificate.qso_dates(),
                validity: certificate.validity(),
                key_present,
            },
        })
    }

    /// Consume an inspected deletion. A different Store instance, any public-store change, or a
    /// change in the referenced credential's presence returns [`StoreError::Conflict`] without
    /// writing anything. A fresh inspection is required even for unrelated public changes.
    ///
    /// Deletes the file record first, then its credential, under one lock. A backend failure leaves
    /// an orphan reported at the next open when detection is available. A file replacement or
    /// durability failure retains the credential, as with [`Self::delete_certificate`].
    pub fn commit_delete(&self, pending: PendingDelete) -> Result<(), StoreError> {
        if !Arc::ptr_eq(&self.import_identity, &pending.owner) {
            return Err(StoreError::Conflict);
        }
        let _lock = self.lock()?;
        let mut data = self.read()?;
        if format::write(&data)? != pending.before {
            return Err(StoreError::Conflict);
        }
        let i = data
            .certificates
            .iter()
            .position(|c| c.id == pending.id)
            .ok_or(StoreError::Conflict)?;
        let key_present = match &data.certificates[i].key_name {
            Some(name) => self.keys.exists(name)?,
            None => false,
        };
        if key_present != pending.preview.key_present {
            return Err(StoreError::Conflict);
        }
        let certificate = data.certificates.remove(i);
        self.replace(&format::write(&data)?)?;
        if let Some(name) = certificate.key_name {
            self.keys.delete(&name)?;
        }
        Ok(())
    }
}

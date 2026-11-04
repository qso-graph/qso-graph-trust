// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The shared QG Trust folder. Public records live in a bounded, versioned XML file; private
//! PKCS#8 DER stays in a library-owned backend scoped to [`SERVICE`] (or [`TEST_SERVICE`] in tests).
//! Each operation reloads the file while holding its OS lock, so separate library releases and
//! processes cannot lose each other's writes. Unknown versions are refused before any mutation.
//!
//! Applications that sign must install the wiping allocator required by this crate's README.
//! Callers select a [`KeyBackend`]; raw credential access stays inside the library.

mod format;
mod keys;

pub use keys::{KeyStoreError, MAX_KEYS, SERVICE, TEST_SERVICE};

use keys::{KeyStore, MemoryKeyStore};

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::certificate::Certificate;
use crate::signing::{KeyError, TqslKey};
use crate::station::StationLocation;
use crate::tbk::BackedUpCertificate;

/// The newest store format this build reads and writes.
pub const VERSION: u32 = 1;
/// The largest store file accepted, before parsing or allocating its contents.
pub const MAX_FILE_LEN: usize = 32 * 1024 * 1024;
/// The most certificates in a store.
pub const MAX_CERTIFICATES: usize = 1024;
/// The most station locations in a store.
pub const MAX_LOCATIONS: usize = 4096;
/// The longest location name in bytes.
pub const MAX_NAME_LEN: usize = 255;
/// The largest credential secret, matching Windows Credential Manager's limit.
pub const MAX_KEY_LEN: usize = 2560;

/// Select a library-owned credential backend. No backend handle or secret reader is exposed.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum KeyBackend {
    /// A fresh, volatile backend for tests and callers' own tests. Dropping the Store wipes its
    /// secrets; reopening the folder creates another empty backend and reports missing keys.
    /// This is not persistent storage for an operator's keys.
    Memory,
    // Os and OsTest belong here once their backend dependency decision is made; they will use
    // SERVICE and TEST_SERVICE respectively, without handing a backend object to the caller.
}

/// A public certificate record; its identifier survives whole-file replacements.
#[derive(Clone, Debug)]
pub struct StoredCertificate {
    /// The store's opaque certificate identifier, used for signing and deletion.
    pub id: String,
    /// The certificate, parsed as a LoTW callsign certificate. Reading the store does not establish
    /// a new chain of trust; callers verify certificate issuers on import, as with `tbk::read`.
    pub certificate: Certificate,
    /// The credential entry's name, if this certificate has a key.
    pub key_name: Option<String>,
}

/// A named station location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredLocation {
    /// Unique within this store; compared exactly, including case.
    pub name: String,
    /// The station's fields, checked by `StationLocation::new` on read.
    pub station: StationLocation,
}

/// Inconsistencies found at open. Nothing is deleted or repaired automatically.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OpenReport {
    /// Certificate identifiers whose named credential is missing.
    pub missing_keys: Vec<String>,
    /// Credential names with no certificate in the file.
    pub orphaned_keys: Vec<String>,
}

/// Why a store operation failed. No variant carries secret bytes or a password.
#[derive(Debug)]
pub enum StoreError {
    /// An OS file operation failed before replacement.
    Io(io::Error),
    /// Replacement succeeded, but the durability sync failed. The visible file and its key must
    /// be kept together; the caller should report uncertain crash durability, not retry blindly.
    Durability(io::Error),
    /// A credential-store operation failed.
    KeyStore(KeyStoreError),
    /// A key could not be unlocked or does not match its certificate.
    Key(KeyError),
    /// The file uses a newer format; it has not been rewritten.
    NewerVersion {
        /// The version found in the file.
        found: u32,
        /// The newest version this build knows.
        supported: u32,
    },
    /// The input exceeds a documented bound.
    Limit(&'static str),
    /// Malformed or unsupported content. The explanation is fixed text, never input.
    Invalid(&'static str),
    /// A certificate or location already exists.
    AlreadyExists,
    /// The requested certificate, location or key is absent.
    NotFound,
    /// Secure randomness was unavailable.
    Random,
    /// The file write failed and the backend also refused to remove the new key. It remains an
    /// orphan, reported next time the store is opened.
    Rollback {
        /// The file-write failure.
        write: Box<StoreError>,
        /// The credential cleanup failure.
        cleanup: KeyStoreError,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "the store file: {e}"),
            Self::Durability(e) => write!(
                f,
                "the store was replaced but its durability sync failed: {e}"
            ),
            Self::KeyStore(e) => write!(f, "the credential store: {e}"),
            Self::Key(e) => write!(f, "the signing key: {e}"),
            Self::NewerVersion { found, supported } => write!(
                f,
                "store version {found} is newer than supported version {supported}"
            ),
            Self::Limit(what) => write!(f, "the store exceeds its limit for {what}"),
            Self::Invalid(what) => write!(f, "invalid store: {what}"),
            Self::AlreadyExists => f.write_str("the store entry already exists"),
            Self::NotFound => f.write_str("the store entry or its key is missing"),
            Self::Random => f.write_str("secure randomness is unavailable"),
            Self::Rollback { write, cleanup } => write!(
                f,
                "{write}; the new credential could not be removed: {cleanup}"
            ),
        }
    }
}

impl std::error::Error for StoreError {}
impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<KeyStoreError> for StoreError {
    fn from(error: KeyStoreError) -> Self {
        Self::KeyStore(error)
    }
}
impl From<KeyError> for StoreError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

#[derive(Default)]
struct Data {
    certificates: Vec<StoredCertificate>,
    locations: Vec<StoredLocation>,
}

/// A shared folder and its private, library-owned credential backend.
///
/// Raw credential access is deliberately unavailable to callers:
///
/// ```compile_fail,E0603
/// use qso_graph_trust::store::KeyStore;
/// ```
///
/// ```compile_fail,E0603
/// use qso_graph_trust::store::MemoryKeyStore;
/// ```
///
/// ```compile_fail,E0616
/// use qso_graph_trust::store::Store;
/// fn read_secret(store: &Store, name: &str) {
///     let _ = store.keys.get(name);
/// }
/// ```
///
/// ```compile_fail,E0599
/// use qso_graph_trust::store::Store;
/// fn read_secret(store: &Store, name: &str) {
///     let _ = store.get(name);
/// }
/// ```
pub struct Store {
    dir: PathBuf,
    keys: Box<dyn KeyStore>,
    // Exercise failures after rename without depending on host permissions or filesystem faults.
    #[cfg(test)]
    fail_sync: std::sync::atomic::AtomicBool,
}

impl Store {
    /// Open (or create) a folder, validate its file and report missing and orphaned credentials.
    /// An absent file is an empty store; the first successful mutation creates `store.xml`.
    pub fn open(
        dir: impl AsRef<Path>,
        backend: KeyBackend,
    ) -> Result<(Self, OpenReport), StoreError> {
        let keys: Box<dyn KeyStore> = match backend {
            KeyBackend::Memory => Box::new(MemoryKeyStore::new()),
        };
        Self::open_with_keys(dir.as_ref(), keys)
    }

    // Only the library can construct or retain a backend that can read credential bytes.
    fn open_with_keys(
        dir: &Path,
        keys: Box<dyn KeyStore>,
    ) -> Result<(Self, OpenReport), StoreError> {
        create_directory(dir, sync_directory)?;
        let store = Self {
            dir: dir.to_path_buf(),
            keys,
            #[cfg(test)]
            fail_sync: std::sync::atomic::AtomicBool::new(false),
        };
        let _lock = store.lock()?;
        let data = store.read()?;
        let mut report = OpenReport::default();
        for cert in &data.certificates {
            if let Some(name) = &cert.key_name
                && !store.keys.exists(name)?
            {
                report.missing_keys.push(cert.id.clone());
            }
        }
        let names = store.keys.names()?;
        if names.len() > keys::MAX_KEYS {
            return Err(StoreError::Limit("credential names"));
        }
        for name in names {
            if !keys::valid_name(&name, "key:") {
                return Err(StoreError::Invalid("credential name"));
            }
            if !data
                .certificates
                .iter()
                .any(|c| c.key_name.as_ref() == Some(&name))
            {
                report.orphaned_keys.push(name);
            }
        }
        report.orphaned_keys.sort();
        report.orphaned_keys.dedup();
        Ok((store, report))
    }

    /// List public certificate records from the current file, under the lock.
    pub fn certificates(&self) -> Result<Vec<StoredCertificate>, StoreError> {
        let _lock = self.lock()?;
        Ok(self.read()?.certificates)
    }

    /// List checked station locations from the current file, under the lock.
    pub fn locations(&self) -> Result<Vec<StoredLocation>, StoreError> {
        let _lock = self.lock()?;
        Ok(self.read()?.locations)
    }

    /// Add an imported certificate and its key. Unlocks and validates the key with `password`,
    /// hands only PKCS#8 DER to the backend, then publishes its name in the file.
    pub fn add_certificate_with_key(
        &self,
        entry: &BackedUpCertificate,
        password: Option<&[u8]>,
    ) -> Result<String, StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let cert = entry
            .certificate
            .as_ref()
            .ok_or(StoreError::Invalid("certificate is required"))?;
        check_certificate(&data, cert)?;
        let key = entry.key.as_ref().ok_or(StoreError::NotFound)?;
        if key.callsign() != cert.callsign() || key.request_dxcc().is_some_and(|d| d != cert.dxcc())
        {
            return Err(StoreError::Invalid(
                "key identity does not match certificate",
            ));
        }
        let der = key.pkcs8_der(password)?;
        if der.len() > MAX_KEY_LEN {
            return Err(StoreError::Limit("credential bytes"));
        }
        // Validate the private key against the actual certificate, not just the backup's metadata.
        TqslKey::from_pkcs8_der(&der, cert.public_key_der())?;
        let name = keys::new_name("key:")?;
        let id = keys::new_name("cert:")?;
        if self.keys.exists(&name)? || data.certificates.iter().any(|c| c.id == id) {
            return Err(StoreError::AlreadyExists);
        }
        data.certificates.push(StoredCertificate {
            id: id.clone(),
            certificate: cert.clone(),
            key_name: Some(name.clone()),
        });
        // Serialize before putting the key, so bad public input cannot create even a temporary orphan.
        let xml = format::write(&data)?;
        self.keys.put(&name, &der)?;
        if let Err(write) = self.replace(&xml) {
            // After rename the certificate already names the key, even when directory sync fails.
            if matches!(write, StoreError::Durability(_)) {
                return Err(write);
            }
            if let Err(cleanup) = self.keys.delete(&name) {
                return Err(StoreError::Rollback {
                    write: Box::new(write),
                    cleanup,
                });
            }
            return Err(write);
        }
        Ok(id)
    }

    /// Add a public certificate without a credential. The caller verifies its issuer on import.
    pub fn add_certificate(&self, certificate: &Certificate) -> Result<String, StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        check_certificate(&data, certificate)?;
        let id = keys::new_name("cert:")?;
        if data.certificates.iter().any(|c| c.id == id) {
            return Err(StoreError::AlreadyExists);
        }
        data.certificates.push(StoredCertificate {
            id: id.clone(),
            certificate: certificate.clone(),
            key_name: None,
        });
        self.replace(&format::write(&data)?)?;
        Ok(id)
    }

    /// Delete the file record first, then its credential. A backend failure leaves an orphan
    /// reported by the next open; it never leaves a certificate pointing to a key we deleted.
    pub fn delete_certificate(&self, id: &str) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let i = data
            .certificates
            .iter()
            .position(|c| c.id == id)
            .ok_or(StoreError::NotFound)?;
        let cert = data.certificates.remove(i);
        self.replace(&format::write(&data)?)?;
        if let Some(name) = cert.key_name {
            self.keys.delete(&name)?;
        }
        Ok(())
    }

    /// Add a location; a name already present is refused.
    pub fn add_location(&self, name: &str, station: &StationLocation) -> Result<(), StoreError> {
        self.save_location(name, station, false)
    }

    /// Replace a location; a name not present is refused.
    pub fn replace_location(
        &self,
        name: &str,
        station: &StationLocation,
    ) -> Result<(), StoreError> {
        self.save_location(name, station, true)
    }

    fn save_location(
        &self,
        name: &str,
        station: &StationLocation,
        replace: bool,
    ) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        format::check_name(name)?;
        let i = data.locations.iter().position(|l| l.name == name);
        match (i, replace) {
            (Some(_), false) => return Err(StoreError::AlreadyExists),
            (None, true) => return Err(StoreError::NotFound),
            (Some(i), true) => data.locations[i].station = station.clone(),
            (None, false) => {
                if data.locations.len() >= MAX_LOCATIONS {
                    return Err(StoreError::Limit("locations"));
                }
                data.locations.push(StoredLocation {
                    name: name.into(),
                    station: station.clone(),
                });
            }
        }
        self.replace(&format::write(&data)?)
    }

    /// Delete a location by its exact name.
    pub fn delete_location(&self, name: &str) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        let mut data = self.read()?;
        let i = data
            .locations
            .iter()
            .position(|l| l.name == name)
            .ok_or(StoreError::NotFound)?;
        data.locations.remove(i);
        self.replace(&format::write(&data)?)
    }

    /// Load and validate a key for one signing operation, then drop it. The callback can return
    /// a signature or its own result but cannot obtain private key bytes. The lock spans the
    /// callback, preventing concurrent deletion; the callback must not reenter this store.
    pub fn with_key<T>(
        &self,
        cert_id: &str,
        sign: impl FnOnce(&TqslKey) -> T,
    ) -> Result<T, StoreError> {
        let _lock = self.lock()?;
        let data = self.read()?;
        let cert = data
            .certificates
            .iter()
            .find(|c| c.id == cert_id)
            .ok_or(StoreError::NotFound)?;
        let name = cert.key_name.as_ref().ok_or(StoreError::NotFound)?;
        let der = self.keys.get(name)?.ok_or(StoreError::NotFound)?;
        if der.len() > MAX_KEY_LEN {
            return Err(StoreError::Limit("credential bytes"));
        }
        let key = TqslKey::from_pkcs8_der(&der, cert.certificate.public_key_der())?;
        drop(der);
        Ok(sign(&key))
    }

    fn lock(&self) -> Result<File, StoreError> {
        let lock = owner_file()
            .create(true)
            .truncate(false)
            .open(self.dir.join("store.lock"))?;
        lock.lock()?;
        Ok(lock)
    }

    fn read(&self) -> Result<Data, StoreError> {
        let file = match File::open(self.dir.join("store.xml")) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Data::default()),
            Err(e) => return Err(e.into()),
        };
        if file.metadata()?.len() > MAX_FILE_LEN as u64 {
            return Err(StoreError::Limit("file bytes"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE_LEN as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::Limit("file bytes"));
        }
        format::read(std::str::from_utf8(&bytes).map_err(|_| StoreError::Invalid("not UTF-8"))?)
    }

    fn replace(&self, xml: &str) -> Result<(), StoreError> {
        let partial = self.dir.join("store.xml.partial");
        // A crash may have left this name behind. Unlink first, never follow an old symlink.
        match fs::remove_file(&partial) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        let result = (|| {
            let mut file = owner_file().create_new(true).open(&partial)?;
            file.write_all(xml.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&partial, self.dir.join("store.xml"))?;
            Ok::<_, StoreError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        result?;
        #[cfg(test)]
        if self.fail_sync.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError::Durability(io::Error::other(
                "injected sync failure after rename",
            )));
        }
        sync_replacement(&self.dir).map_err(StoreError::Durability)?;
        Ok(())
    }
}

fn sync_replacement(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        // The partial's flush predates the rename, so it cannot commit that metadata change.
        // Reopen the renamed file with write access: sync_all calls FlushFileBuffers, which
        // flushes cached file metadata as well as data. On NTFS this commits the rename before
        // we delete a credential. Microsoft's File Caching and FlushFileBuffers documentation:
        // https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
        // This relies on the filesystem, drivers and hardware honoring flushes. Other filesystems
        // and network shares may differ; this is not a volume-wide or ancestor-directory flush.
        OpenOptions::new()
            .write(true)
            .open(dir.join("store.xml"))?
            .sync_all()?;
    }
    sync_directory(dir)
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn create_directory(dir: &Path, sync: impl Fn(&Path) -> io::Result<()>) -> io::Result<()> {
    const PENDING: &str = ".qgt-directory-pending";

    let dir = std::path::absolute(dir)?;
    let mut missing = Vec::new();
    let mut ancestor = dir.as_path();
    while !ancestor.try_exists()? {
        missing.push(ancestor);
        ancestor = ancestor
            .parent()
            .ok_or_else(|| io::Error::other("no existing store ancestor"))?;
    }
    // A marker identifies our unfinished work without opening an established ancestor for
    // reading. The first unmarked ancestor is the caller's existing directory boundary.
    let mut chain = Vec::new();
    // Creation can stop between mkdir and its marker. A marked parent identifies that one
    // unfinished child; its own marker was persisted before we attempted the child's mkdir.
    if !ancestor.join(PENDING).try_exists()?
        && let Some(parent) = ancestor.parent()
        && parent.join(PENDING).try_exists()?
    {
        chain.push(ancestor);
        ancestor = parent;
    }
    for path in ancestor.ancestors() {
        if !path.join(PENDING).try_exists()? {
            break;
        }
        chain.push(path);
    }
    chain.reverse();
    chain.extend(missing.into_iter().rev());

    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    for (index, path) in chain.iter().enumerate() {
        match builder.create(path) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => (),
            Err(e) => return Err(e),
        }
        match owner_file().create_new(true).open(path.join(PENDING)) {
            Ok(marker) => marker.sync_all()?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        if index > 0 {
            sync(chain[index - 1])?;
        }
        // Persist the recovery marker before creating a descendant. Keep all markers until
        // every entry below the existing boundary has been synced.
        sync(path)?;
    }
    for path in &chain {
        match fs::remove_file(path.join(PENDING)) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        // Remove markers from the top down: any remaining pending chain stays contiguous.
        sync(path)?;
    }
    if chain.is_empty() {
        sync(&dir)?;
    }
    Ok(())
}

fn check_certificate(data: &Data, cert: &Certificate) -> Result<(), StoreError> {
    if data.certificates.len() >= MAX_CERTIFICATES {
        return Err(StoreError::Limit("certificates"));
    }
    if data
        .certificates
        .iter()
        .any(|c| c.certificate.der() == cert.der())
    {
        return Err(StoreError::AlreadyExists);
    }
    Ok(())
}

fn owner_file() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// The shared data folder for this platform, or `None` when its required environment is absent.
/// Empty environment values are treated as absent; a relative XDG_DATA_HOME is ignored as XDG
/// requires an absolute path. Callers may always supply an explicit folder to `Store::open`.
pub fn default_dir() -> Option<PathBuf> {
    default_dir_from(|name| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    })
}

fn default_dir_from(env: impl Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        env("APPDATA").map(|p| p.join("qso-graph").join("trust"))
    }
    #[cfg(target_os = "macos")]
    {
        env("HOME").map(|p| p.join("Library/Application Support/io.qso-graph.trust"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        env("XDG_DATA_HOME")
            .filter(|p| p.is_absolute())
            .or_else(|| env("HOME").map(|p| p.join(".local/share")))
            .map(|p| p.join("qso-graph-trust"))
    }
}

#[cfg(test)]
mod tests;

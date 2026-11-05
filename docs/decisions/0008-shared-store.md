<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE. -->
# 0008 — One versioned folder, with credential storage owned by the library

**Status: accepted**, 2026-11-05: it does what TQSL 2.8.7 does. The OS credential store backends are decided in [0002](0002-no-c-in-the-library.md).

QGD-LTW-0007 and QGD-LTW-0008 require Desktop and the command line to share certificates, keys and
station locations even when they use different library releases. The library owns this protocol;
The OS credential backends are in [0002](0002-no-c-in-the-library.md).

- The crate-private `KeyStore` seam is scoped to `io.qso-graph.trust`, or `io.qso-graph.trust.test`
  for tests. Only the library can obtain a backend object or read its secrets.
  Its `put`, `get`, `delete`, `exists` and `names` methods use fixed error categories that cannot hold
  backend messages or secrets. `exists` and `names` never read secrets. Enumeration is necessary to
  report orphaned keys; presence checks alone cannot find them. Backends bound enumeration at 8192.
- Credentials contain PKCS#8 DER, bounded at 2560 bytes for Windows Credential Manager. A random
  UUID v4 names each key (`key:<uuid>`) and certificate (`cert:<uuid>`), so no operator input goes into
  a credential name. Randomness comes from AWS-LC through the binding's safe API.
- `Store::open(dir, KeyBackend::Memory)` creates a fresh, private in-memory backend for tests and
  callers' own tests. Its secrets and internal copies are `Zeroizing`; it has no debug output that
  could expose them. Dropping the Store wipes them; another open has an empty backend. The public,
  non-exhaustive `KeyBackend` enum leaves room for `Os` and `OsTest` after their dependency decision.
- `Store::open` owns its backend and reports certificate identifiers with missing keys and names
  of orphaned credentials. Neither is removed. A certificate intentionally imported without a key
  is not an inconsistency. No private bytes leave `Store`; `with_key` borrows a checked `TqslKey`
  for the callback and drops it afterwards. Applications still install the wiping allocator.
- `store.lock` is an OS file lock, kept for the entire reload, mutation and replacement, including
  credential handoff and cleanup. Reads use it too; there is no stale in-memory cache. A signing
  callback keeps the lock so deletion cannot race signing; callbacks must not reenter the store.
- Every mutation writes `store.xml.partial`, syncs it, closes it, renames it over `store.xml`, and
  syncs the directory on Unix. Windows reopens `store.xml` with write access and calls `sync_all`
  after rename. New files have mode 0600 and new folders 0700 on Unix. A stale partial is unlinked
  under the lock, avoiding following its symlink. The lock file is never unlinked.
- On Windows, the partial's earlier flush cannot include the later rename. `sync_all` on the
  renamed file calls `FlushFileBuffers`; Microsoft documents that a file flush persists cached
  metadata as well as data and requires write access ([File Caching][caching],
  [FlushFileBuffers][flush]). On NTFS, this post-rename metadata flush is the durability barrier
  before credential deletion. It relies on the filesystem, drivers and hardware honoring flushes;
  other filesystems and network shares may differ. It is not a volume-wide flush and does not prove
  persistence of newly created Windows ancestor directories. Power-loss testing on Windows remains
  necessary to validate the storage stack; this protocol cannot make faulty hardware durable.
- First use creates missing directories one at a time below the first existing ancestor. Temporary
  `.qgt-directory-pending` files identify unfinished creation, so retries sync that chain too. On
  Unix, only directories in this chain and the store directory itself are opened and synced;
  established ancestors need traversal permission only. The caller's existing boundary is assumed
  durable: QGT cannot flush a new entry in that boundary without read access to it. Within the
  created chain, each parent is synced after creating its child. Recovery markers are persisted
  before descending and removed from the top down only after the entire chain has been synced.
- Import validates and puts the key before publishing its name. Pre-rename failure removes the new
  key; failed cleanup is reported explicitly and leaves an orphan. Deletion publishes the file
  without its certificate before deleting the key. A durability-sync failure after rename has a
  separate `Durability` error: the new file is visible, so its key must remain. A deletion with that
  error also keeps its key, leaving at worst an orphan after a crash.
- The file is bounded at 32 MiB, 1024 certificates, 4096 locations and 255 bytes per location name;
  station field counts and lengths use the existing station bounds. Reads limit bytes even if the
  file grows after `metadata`. All XML input uses the existing bounded parser. Unknown structure,
  duplicate identifiers, shared key names, duplicate certificate DER and duplicate location names
  are refused. Locations are rebuilt with `StationLocation::new`.
- Issuer trust is checked at import by the caller, for example `tbk::read` with the chosen `Trust`.
  Store reads parse LoTW certificate structure; they do not establish issuer trust. Every key is
  checked against the certificate's public key both on import and on use.
- Version dispatch is separate from the version-1 reader. A newer root version returns
  `NewerVersion { found, supported }` before mutation, including for an already-open Store.
  Version 1 has an empty, independently versioned signed-QSO section; nonempty contents are
  refused until the duplicate-record task defines them, preventing accidental loss of data.
- Location names compare exactly. The XML writer escapes all five special characters and uses
  character references for tabs and line ends so XML normalization cannot change a name.
- `default_dir()` uses XDG data home (absolute, nonempty) or HOME on Linux, HOME on macOS and APPDATA
  on Windows. It only resolves the path; callers may supply any folder explicitly.

Certificate requests extend version 1 with an optional `pending-requests` section. Older version-1
files without it remain readable; the writer omits it when empty. Older readers refuse the new
section, preventing accidental loss. Each `request` holds `id="request:<uuid>"`, `call`, `dxcc`,
`created` (Unix seconds), and `key="key:<uuid>"` attributes, with base64 SPKI DER as text. No private
bytes are in XML. Requests are bounded at 1024, with bounded, parsed RSA SPKIs, valid calls and
DXCC entities, unique request IDs and SPKIs, and key names unique across requests and certificates.
`Store::store_request` publishes the pending record after putting the key, using the import rollback
and durability rules. Open reports missing pending keys separately and does not count them as
orphans. Response attachment matches SPKI, call and DXCC, checks the private key as on import, and
replaces the pending record with a certificate under one lock and one file replacement. Abandonment
follows deletion's file-first ordering. Applications verify response issuer trust before attachment.

Decision [0010](0010-signed-qso-record.md) extends the root to version 2 for nonempty signed-QSO
records. Version 1 below remains readable with its original empty-section rule.

An empty version-1 store is valid (a folder without `store.xml` is also empty until the first mutation):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<qgt-store version="1">
  <certificates/>
  <locations/>
  <signed-qsos version="1"/>
</qgt-store>
```

A certificate record is `<certificate id="cert:<uuid>" key="key:<uuid>">BASE64_DER</certificate>`
inside `certificates`; `key` is omitted for a public-only certificate. UUID and BASE64_DER here are
placeholders. A location uses this shape inside `locations`:

```xml
<location name="Test &amp; home">
  <field name="CALL">QG0TEST</field>
  <field name="DXCC">291</field>
  <field name="GRIDSQUARE">EM17</field>
</location>
```

Tests plant malformed and oversized files, upgrade a file behind an open Store, inject write and
post-rename sync failures, and hold the OS lock while a second thread tries to write. Compile-fail
examples guard the private credential API. Nested first-use tests check permissions, bounded parent
sync ordering, recovery after interrupted creation and cleanup, and writes beneath an execute-only
ancestor. The standard test
backup round-trips every certificate and location; signing through `with_key` matches signing
with the imported key directly for every standard location.

[caching]: https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching
[flush]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers

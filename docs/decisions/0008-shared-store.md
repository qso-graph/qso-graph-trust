<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE. -->
# 0008 — One versioned folder, with credential storage supplied by the caller

**Status: proposed**, for KI7MT to decide. The OS credential store backends wait on their own decision.

QGD-LTW-0007 and QGD-LTW-0008 require Desktop and the command line to share certificates, keys and
station locations even when they use different library releases. The library owns this protocol;
OS credential backends await their own dependency decision. No backend or new dependency is added.

- A `KeyStore` instance is scoped to `io.qso-graph.trust`, or `io.qso-graph.trust.test` for tests.
  Its `put`, `get`, `delete`, `exists` and `names` methods use fixed error categories that cannot hold
  backend messages or secrets. `exists` and `names` never read secrets. Enumeration is necessary to
  report orphaned keys; presence checks alone cannot find them. Backends bound enumeration at 8192.
- Credentials contain PKCS#8 DER, bounded at 2560 bytes for Windows Credential Manager. A random
  UUID v4 names each key (`key:<uuid>`) and certificate (`cert:<uuid>`), so no operator input goes into
  a credential name. Randomness comes from AWS-LC through the binding's safe API.
- `MemoryKeyStore` is public solely for tests. Its secret values and every returned copy are
  `Zeroizing`; it has no debug output that could expose them. It is not persistent key storage.
- `Store::open` borrows a backend and reports certificate identifiers with missing keys and names
  of orphaned credentials. Neither is removed. A certificate intentionally imported without a key
  is not an inconsistency. No private bytes leave `Store`; `with_key` borrows a checked `TqslKey`
  for the callback and drops it afterwards. Applications still install the wiping allocator.
- `store.lock` is an OS file lock, kept for the entire reload, mutation and replacement, including
  credential handoff and cleanup. Reads use it too; there is no stale in-memory cache. A signing
  callback keeps the lock so deletion cannot race signing; callbacks must not reenter the store.
- Every mutation writes `store.xml.partial`, syncs it, closes it, renames it over `store.xml`, and
  syncs the directory on Unix. New files have mode 0600 and new folders 0700 on Unix. A stale partial
  is unlinked under the lock, avoiding following its symlink. The lock file is never unlinked.
- Import validates and puts the key before publishing its name. Pre-rename failure removes the new
  key; failed cleanup is reported explicitly and leaves an orphan. Deletion publishes the file
  without its certificate before deleting the key. A directory-sync failure after rename has a
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

An empty store is valid (a folder without `store.xml` is also empty until the first mutation):

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

Tests plant malformed and oversized files, upgrade a file behind an open Store, inject a write
failure after key put, and hold the OS lock while a second thread tries to write. The standard test
backup round-trips every certificate and location; signing through `with_key` matches signing
with the imported key directly for every standard location.

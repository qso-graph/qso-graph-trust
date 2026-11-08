<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# 0014: Inspect imports before committing them

Decided 2026-11-08 for QG Trust 0.1.6 and Desktop's QGD-LTW-0003 confirmation.

## What was decided

`Store::inspect_tq6`, `inspect_pkcs12`, and `inspect_tbk` return a `PendingImport` without writing
public records or credentials. Its immutable preview names certificates by call, DXCC, serial,
QSO dates, and validity, with their new, present, or refused disposition. It also describes key
presence, protected keys that still need passwords, new roots by subject and SHA-256 fingerprint,
station locations and their disposition, and the count and size of the signed-QSO record.
The application retains the source filename for its confirmation; the library accepts bounded
bytes and never opens that file.

A PKCS#12 password is needed during inspection because its authenticated, encrypted contents
include certificate metadata. A backup can have a different password for every key. Its caller
uses each preview index, call, and serial to ask for that key's password, then calls
`PendingImport::unlock_key(index, password)`. This completes inspection of that key, including
matching its private key to its actual certificate. Failure identifies the entry, leaves both
stores unchanged, and permits another password attempt. Commit refuses unchecked protected keys.
Malformed input fails inspection; readable certificates with invalid chains appear as refused
entries with reasons. Unanswered backup requests are refused entries that callers can explicitly
skip; they do not become signing certificates.

The preview exposes no encoded certificate, email, private key, or password. Private keys and
private-key envelopes remain in library-private wiping buffers. Passwords are borrowed and never
retained. Pending imports implement neither Debug, Clone nor Serialize. Dropping one cancels the
operation and zeroizes its key buffers. The wiping allocator remains mandatory for applications;
the pending value does not replace allocator or provider-frame custody protections.

## Commit the inspected data

`Store::commit(pending, choices)` consumes the parsed plan. It never reads or parses the source
file again. Reopening a file after confirmation would let different contents be imported under
the operator's approval of the original preview. Keeping the checked data binds confirmation to
what is actually installed, even if the source file changes or disappears.

The pending import owns an opaque token binding it to its Store instance, so Desktop can keep it
between UI commands without borrowing the Store. Moving the Store retains its identity; reopening
the folder creates a new instance and requires a fresh inspection. Inspection captures a canonical public-store
snapshot under its lock. Commit reacquires the lock, compares the current snapshot, checks
referenced credential presence and the contents of any request key it will attach, and refuses a
conflict before writing anything. The snapshot comparison is conservative: even an unrelated
public-store change requires a fresh inspection. This also protects root removals and signed-QSO
or location changes. Fresh credential names and certificate IDs are allocated in the plan.

Every new root needs an explicit fingerprint in `ImportChoices::accept_roots`, including roots
from backups. No root becomes trusted during inspection. The command line preserves its existing
own-backup policy by passing those preview fingerprints explicitly; `.tq6` and `.p12` still need
`--trust-root`. Other applications make their own confirmation choices.

Commit validates all decisions and serializes the complete resulting public file before staging
credentials. A credential failure or failure before file replacement rolls back every staged
credential. Certificates, root trust, signed-QSO records, and any chosen store locations share
one atomic public-file replacement under the lock. There is no per-certificate publication loop.
As with existing Store operations, OS failures can prevent rollback: `StoreError::Rollback`
reports failed cleanup. A sync failure after replacement reports `StoreError::Durability` and
retains every installed key because the visible file already refers to them. Cross-service crash
atomicity is not provided by OS credential stores; the existing open report detects orphaned keys.

Backup locations are returned to the caller by default so Desktop can place them as Desktop
Locations. The CLI chooses `store_locations`, preserving existing names and default-location
behavior in the same transaction. The older one-step certificate methods are convenience wrappers
around inspection and commit. The CLI uses this shared path for all three formats.

## Evidence

Tests compare actual public-file bytes and every test-backend credential before and after
inspection, password attempts, and cancellation. Tests compare committed identities and key
availability with the preview, change and delete source files, plant concurrent certificate
changes, give one backup key the other key's password, plant an untrusted chain, omit or mistype
root fingerprints in each format, and refuse publication after staging several keys. Removing
each planted fault allows the operation to succeed. Existing CLI import tests run unchanged.

The Linux custody test separately scans cancellation and commit after inspecting a protected
PKCS#12 file and the standard backup, including both independently protected backup keys. It
searches all process memory for the keys and passwords, in debug and release, with the existing
live-key, unwiped-allocator and planted-secret controls. It also exercises the provider's fallback
AES path on x86_64. All certificates and keys are generated corpus data; no test contacts ARRL.

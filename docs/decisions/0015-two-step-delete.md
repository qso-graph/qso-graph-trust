<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# 0015: Inspect certificate deletions before committing them

Decided 2026-11-09 for Desktop's QGD-LTW-0003 deletion confirmation.

`Store::inspect_delete(id)` returns an owned `PendingDelete` using the two-step pattern in
[decision 0014](0014-two-step-import.md). Under the store lock it captures the same canonical
public-store snapshot as import and an immutable preview: call, DXCC, serial, QSO dates,
validity dates, and whether the referenced key is installed. Inspection changes nothing.
The preview and conflict errors expose no email or encoded certificate. The pending value
implements neither Debug, Clone nor Serialize; dropping it cancels.

`Store::commit_delete(pending)` consumes that confirmation, reacquires the lock, and compares
the snapshot and the referenced credential's presence before writing anything. Any difference,
including an unrelated public-store change or a removed certificate, requires fresh inspection.
The pending value is bound to its Store instance as in 0014: moving the Store preserves its
identity, but reopening the same folder does not.

This prevents a confirmation of a keyless `.tq6` from deleting a key attached meanwhile by a
matching `.p12` import through another Store instance. Successful deletion keeps the existing
order: replace the public file without the record, then remove its credential. File failures
retain the credential; a credential deletion failure leaves an orphan detectable at the next
open when the backend supports detection. Cross-service crash atomicity remains unchanged.

`delete_certificate(id)` remains a one-step convenience wrapper around inspect and commit.
`qg-trust cert delete` retains the pending deletion through its existing force check and keeps
its output and prompts.

Tests plant the key attachment, unrelated writes, certificate removal, a different Store
instance, and credential-only presence changes. Refusals preserve the exact public-file bytes
and all test credentials. Fresh inspections permit deletion; clean commits remove the record
before its key, and cancellation preserves both. All inputs are generated test corpus data.

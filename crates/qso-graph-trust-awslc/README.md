<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust-awslc

The one binding [`qso-graph-trust`](https://crates.io/crates/qso-graph-trust) uses to reach AWS-LC: it
makes LoTW's signature (RSA PKCS#1 v1.5 over SHA-1, which AWS-LC's safe Rust API does not sign) and
checks certificate signatures. It is the only crate in QSO Graph Trust allowed `unsafe` code, each
block carrying its reason, and its interface is safe: a key, once loaded, cannot be read back out.

Use `qso-graph-trust`; this crate is its dependency, not an API of its own.

GPL-3.0-only. Source: <https://github.com/qso-graph/qso-graph-trust>.

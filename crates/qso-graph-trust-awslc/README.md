<!-- SPDX-License-Identifier: GPL-3.0-only -->
# qso-graph-trust-awslc

[`qso-graph-trust`](https://crates.io/crates/qso-graph-trust)'s connection to AWS-LC, Amazon's
open-source cryptography library: it makes LoTW's signature (RSA PKCS#1 v1.5 over SHA-1) and checks
certificate signatures. It also generates TQSL-compatible RSA-1024 request keys and signs their
SHA-256 CSRs, operations the safe API cannot perform with 1024-bit keys. Generated PKCS#8 goes
only to the library in wiped memory for credential-store custody. Every call into AWS-LC is small, checked and documented, and a key, once
loaded, can only sign: it cannot be read back out.

Use `qso-graph-trust`; this crate is its dependency, not an API of its own.

GPL-3.0-only. Source: <https://github.com/qso-graph/qso-graph-trust>.

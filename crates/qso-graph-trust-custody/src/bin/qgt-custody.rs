// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The custody test's program, with the wiping allocator every QG Trust program installs.

#![forbid(unsafe_code)]

/// Every freed block is wiped, whichever library allocated it (AGENTS.md).
#[global_allocator]
static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

fn main() -> std::process::ExitCode {
    qso_graph_trust_custody::run()
}

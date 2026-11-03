// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The custody test's control: the same program without the wiping allocator, so the test can
//! prove it finds what an unwiped free leaves. Named in `cargo xtask policy` as the one program
//! allowed to go without it; never shipped.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    qso_graph_trust_custody::run()
}

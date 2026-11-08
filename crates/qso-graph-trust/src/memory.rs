// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Best-effort overwrite of returned provider frames, in addition to wiping owned buffers.

use zeroize::Zeroize;

// Keep the operation in a separate frame, returned before the scrub. Results containing secrets
// must own wiped heap storage, never inline secret arrays. Typed errors take the same path.
#[inline(never)]
pub(crate) fn scrub_after<T>(operation: impl FnOnce() -> T) -> T {
    let result = invoke(operation);
    scrub_stack();
    result
}

#[inline(never)]
fn invoke<T>(operation: impl FnOnce() -> T) -> T {
    operation()
}

// This covers 64 KiB below this frame on the current thread. Safe Rust cannot promise an exact
// overlap with earlier frames, erase registers, other threads, live callers or deeper frames.
// The Linux custody test measures the supported builds, including the AES-NI-disabled path.
#[inline(never)]
fn scrub_stack() {
    let mut stack = [0u8; 64 * 1024];
    stack.zeroize();
    std::hint::black_box(&mut stack);
}

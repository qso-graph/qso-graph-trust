// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]

/// Wipes every freed block.
#[global_allocator]
static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

fn main() {}

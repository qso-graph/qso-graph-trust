// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]

#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

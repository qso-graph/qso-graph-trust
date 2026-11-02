// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
#[cfg(not(debug_assertions))]
pub fn read() -> u8 {
    unsafe { core::ptr::read(&7) }
}

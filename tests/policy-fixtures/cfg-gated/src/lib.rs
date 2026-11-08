// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
#[cfg(not(debug_assertions))]
pub fn unchecked_read() -> u8 {
    unsafe { core::ptr::read(&7) }
}

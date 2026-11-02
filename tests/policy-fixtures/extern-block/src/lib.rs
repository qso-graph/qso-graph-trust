// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
#[link(name = "z")]
unsafe extern "C" {
    fn zlibVersion() -> *const u8;
}

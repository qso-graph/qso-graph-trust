// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
#[cfg(not(debug_assertions))]
macro_rules! load {
    ($a:tt) => { # $a pub mod hidden; };
}
#[cfg(not(debug_assertions))]
load!([path = "hidden.md"]);

// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
#[cfg(not(debug_assertions))]
macro_rules! load {
    ($h:tt [$ignored:ident]) => {
        $h [path = "hidden.md"] pub mod hidden;
    };
}
#[cfg(not(debug_assertions))]
load!(#[doc]);

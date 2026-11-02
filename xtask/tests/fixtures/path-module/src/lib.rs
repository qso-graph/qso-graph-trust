// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
#[cfg(not(debug_assertions))]
#[path = "release.inc"]
mod release;

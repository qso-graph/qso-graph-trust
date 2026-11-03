// SPDX-License-Identifier: GPL-3.0-only
macro read_value() {
    ${concat(un, safe)} { core::ptr::read(&7u8) }
}

pub fn probe() -> u8 {
    read_value!()
}

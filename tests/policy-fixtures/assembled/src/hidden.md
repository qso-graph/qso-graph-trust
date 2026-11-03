pub fn f() -> u8 {
    unsafe { core::ptr::read(&7) }
}

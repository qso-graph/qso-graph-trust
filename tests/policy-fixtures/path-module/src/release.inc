pub fn read() -> u8 {
    unsafe { core::ptr::read(&7) }
}

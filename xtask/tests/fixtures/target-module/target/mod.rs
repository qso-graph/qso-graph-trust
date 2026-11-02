pub fn proof() -> u8 {
    unsafe { core::ptr::read(&7) }
}

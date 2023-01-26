#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PacketBuffer {
    pub size: usize,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for PacketBuffer {}
}

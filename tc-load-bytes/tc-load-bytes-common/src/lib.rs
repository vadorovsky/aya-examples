#![no_std]

pub const MAX_MTU: usize = 1500;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PacketBuffer {
    // pub size: usize,
    pub buf: [u8; MAX_MTU],
}

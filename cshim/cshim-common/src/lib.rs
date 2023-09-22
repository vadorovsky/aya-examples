#![no_std]

use core::ffi::c_int;

#[repr(C)]
pub struct Event {
    pub pid: c_int,
    pub tgid: c_int,
}

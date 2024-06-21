#![no_std]
#![no_main]

use core::ptr;

use aya_ebpf::{helpers::bpf_loop, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

extern "C" fn callback(ctx: *mut core::ffi::c_void, index: u32) -> i32 {
    0
}

#[tracepoint]
pub fn probe_bpf_loop(ctx: TracePointContext) -> u32 {
    match try_probe_bpf_loop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_probe_bpf_loop(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        bpf_loop(5, callback as *mut _, ptr::null_mut(), 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

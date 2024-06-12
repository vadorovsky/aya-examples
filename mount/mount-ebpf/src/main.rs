#![no_std]
#![no_main]

use aya_ebpf::{macros::raw_tracepoint, programs::RawTracePointContext};
use aya_log_ebpf::info;

#[raw_tracepoint(tracepoint="sys_enter_mount")]
pub fn mount(ctx: RawTracePointContext) -> i32 {
    match try_mount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_mount(ctx: RawTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint sys_enter_mount called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

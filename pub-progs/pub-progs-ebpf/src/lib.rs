#![no_std]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint(name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_pub_progs(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_pub_progs(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sched_process_fork called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

#[lsm(hook = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    match try_task_alloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_alloc(ctx: LsmContext) -> Result<i32, i32> {
    info!(&ctx, "lsm hook task_alloc called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

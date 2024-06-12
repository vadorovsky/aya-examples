#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
// use aya_log_ebpf::info;

mod vmlinux;

use vmlinux::task_struct;

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let task = unsafe { ctx.arg::<*const task_struct>(0) };

    if unsafe { (*task).pid == 12345 } {
        return Err(-1);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

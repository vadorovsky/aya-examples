#![no_std]
#![no_main]

use aya_bpf::{cty::c_int, macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::task_struct;

#[allow(improper_ctypes)]
extern "C" {
    fn task_struct_pid(task: *const task_struct) -> c_int;
    fn task_struct_tgid(task: *const task_struct) -> c_int;
}

#[lsm(hook = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    match try_task_alloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_alloc(ctx: LsmContext) -> Result<i32, i32> {
    let task: *const task_struct = unsafe { ctx.arg(0) };
    let pid = unsafe { task_struct_pid(task) };
    let tgid = unsafe { task_struct_tgid(task) };
    info!(&ctx, "pid: {}, tgid: {}", pid, tgid);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

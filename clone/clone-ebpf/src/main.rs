#![no_std]
#![no_main]

use aya_bpf::{macros::fentry, programs::FEntryContext, BpfContext};
use aya_log_ebpf::info;

#[fentry(name = "kernel_clone")]
pub fn kernel_clone(ctx: FEntryContext) -> u32 {
    match unsafe { try_kernel_clone(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_kernel_clone(ctx: FEntryContext) -> Result<u32, u32> {
    let pid = ctx.pid();

    let command = ctx.command().map_err(|e| e as u32)?;
    let command = core::str::from_utf8_unchecked(&command[..]);

    info!(&ctx, "new process: pid: {}, command: {}", pid, command);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

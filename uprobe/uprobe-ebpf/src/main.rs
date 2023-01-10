#![no_std]
#![no_main]

use aya_bpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[uprobe(name = "uprobe")]
pub fn uprobe(ctx: ProbeContext) -> u32 {
    match try_uprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "wao");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

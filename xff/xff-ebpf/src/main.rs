#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;

const PATTERN: u64 = 0x726177726f462d58;

#[classifier(name = "xff")]
pub fn xff(ctx: TcContext) -> i32 {
    match try_xff(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_xff(ctx: TcContext) -> Result<i32, i32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    for i in 0..8010 {
        if data + i + 8 > data_end {
            break;
        }
        let h1 = unsafe { *((data + i) as *const u64) };
        if h1 == PATTERN {
            info!(&ctx, "blocking XFF");
            return Ok(TC_ACT_SHOT);
        }
    }
    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

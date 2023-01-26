#![no_std]
#![no_main]

use aya_bpf::{
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

use tc_perfbuf_simple_common::PacketBuffer;

#[map]
pub static DATA: PerfEventArray<PacketBuffer> = PerfEventArray::new(0);

#[classifier(name = "tc_perfbuf")]
pub fn tc_perfbuf(ctx: TcContext) -> i32 {
    match try_tc_perfbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_perfbuf(ctx: TcContext) -> Result<i32, i32> {
    DATA.output(
        &ctx,
        &PacketBuffer {
            size: ctx.len() as usize,
        },
        ctx.len(),
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

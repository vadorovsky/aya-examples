#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};

use xdp_perfbuf_common::PacketBuffer;

#[map]
pub static DATA: PerfEventArray<PacketBuffer> = PerfEventArray::new(0);

#[xdp(name = "xdp_perfbuf")]
pub fn xdp_perfbuf(ctx: XdpContext) -> u32 {
    match try_xdp_perfbuf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_perfbuf(ctx: XdpContext) -> Result<u32, u32> {
    let len = ctx.data_end() - ctx.data();
    DATA.output(&ctx, &PacketBuffer { size: len }, len as u32);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

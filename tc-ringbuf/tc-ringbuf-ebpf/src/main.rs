#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use aya_log_ebpf::info;

use tc_ringbuf_common::PacketBuffer;

#[map]
static DATA: RingBuf = RingBuf::with_max_entries(256 * 1024, 0); // 256 KB

#[classifier(name = "tc_ringbuf")]
pub fn tc_ringbuf(ctx: TcContext) -> i32 {
    match try_tc_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_ringbuf(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    if let Some(mut buf) = DATA.reserve::<PacketBuffer>(0) {
        let len = ctx.skb.len() as usize;
        // let buf_inner = unsafe { &mut (*buf.as_mut_ptr()).buf };

        unsafe { (*buf.as_mut_ptr()).size = len };
        // unsafe { ctx.load_bytes(0, buf_inner).map_err(|_| TC_ACT_PIPE)? };

        buf.submit(0);
    }
    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

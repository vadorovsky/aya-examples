#![no_std]
#![no_main]

use aya_bpf::{macros::cgroup_skb, programs::SkBuffContext};
use aya_log_ebpf::info;

// const PATTERN: u64 = 0x302f_7872;
// const MASK: u64 = 0xFFFF_FFFF;

const PATTERN: u64 = 0x726177726f462d58;
const MASK: u64 = 0xFFFFFFFFFFFFFFFF;

#[cgroup_skb(name = "xmrig")]
pub fn xmrig(ctx: SkBuffContext) -> i32 {
    match try_xmrig(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_xmrig(ctx: SkBuffContext) -> Result<i32, i32> {
    // info!(&ctx, "received a packet");

    let data = unsafe { (*ctx.skb.skb).data } as usize;
    let data_end = unsafe { (*ctx.skb.skb).data_end } as usize;
    let len = data_end - data;
    info!(&ctx, "len: {}", len);

    for i in 0..8100 {
        if data + i + 8 > data_end {
            break;
        }
        let h1 = unsafe { *((data + i) as *const u64) };
        if h1 & MASK == PATTERN {
            // info!(&ctx, "blocking");
            return Ok(0);
        }
    }

    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

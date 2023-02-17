#![no_std]
#![no_main]

use aya_bpf::{macros::cgroup_skb, programs::SkBuffContext};
use aya_log_ebpf::info;

const PATTERN: u64 = 0x726177726f462d58;

#[cgroup_skb(name = "xff_cgroup")]
pub fn xff_cgroup(ctx: SkBuffContext) -> i32 {
    match try_xff_cgroup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_xff_cgroup(ctx: SkBuffContext) -> Result<i32, i32> {
    let data = unsafe { (*ctx.skb.skb).data } as usize;
    let data_end = unsafe { (*ctx.skb.skb).data_end } as usize;

    for i in 0..8010 {
        if data + i + 8 > data_end {
            break;
        }
        let h1 = unsafe { *((data + i) as *const u64) };
        if h1 == PATTERN {
            info!(&ctx, "found XFF header");
            return Ok(0);
        }
    }
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

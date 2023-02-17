#![no_std]
#![no_main]

use aya_bpf::{macros::cgroup_skb, programs::SkBuffContext};
use aya_log_ebpf::info;

// const PATTERN: u64 = 0x726177726f462d58;

const FIRST_HALF: u64 = 0x7a696c6169726553;
const SECOND_HALF: u64 = 0x6b636970203a7265;

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

    for i in 0..4090 {
        if data + i + 16 > data_end {
            break;
        }
        let h1 = unsafe { *((data + i) as *const u64) };
        if h1 == FIRST_HALF {
            let h2 = unsafe { *((data + i + 8) as *const u64) };
            if h2 == SECOND_HALF {
                info!(&ctx, "found pickle header");
                return Ok(0);
            }
        }
    }
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

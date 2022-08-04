#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::SkBuffContext};
use aya_log_ebpf::info;
use memoffset::offset_of;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr};

const ETH_P_IP: u16 = 0x0800;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

#[classifier(name = "tc_srcip")]
pub fn tc_srcip(ctx: SkBuffContext) -> i32 {
    match unsafe { try_tc_srcip(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

unsafe fn try_tc_srcip(ctx: SkBuffContext) -> Result<i32, i64> {
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if h_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);

    info!(&ctx, "source address: {}", saddr);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

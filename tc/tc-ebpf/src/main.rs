#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};
use aya_log_ebpf::info;
use memoffset::offset_of;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, ipv6hdr};

#[classifier(name = "tc")]
pub fn tc(ctx: TcContext) -> i32 {
    match unsafe { try_tc(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_tc(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");

    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_OK)?,
    );

    match h_proto {
        ETH_P_IP => {
            let source = u32::from_be(
                ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))
                    .map_err(|_| TC_ACT_OK)?,
            );
            info!(
                &ctx,
                "source IPv4: {:ipv4}, {:x}, {:X}", source, source, source
            );
        }
        ETH_P_IPV6 => {
            let source = ctx
                .load::<[u8; 16]>(ETH_HDR_LEN + offset_of!(ipv6hdr, saddr))
                .map_err(|_| TC_ACT_OK)?;
            info!(&ctx, "source IPv6: {:ipv6}", source);
        }
        _ => return Ok(TC_ACT_OK),
    }

    Ok(TC_ACT_OK)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

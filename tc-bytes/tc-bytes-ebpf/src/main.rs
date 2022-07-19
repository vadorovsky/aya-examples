#![no_std]
#![no_main]

use core::{cmp, mem};

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;
use memoffset::offset_of;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, tcphdr};

const BUF_CAPACITY: usize = 9198;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; BUF_CAPACITY],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[classifier(name = "tc_bytes")]
pub fn tc_bytes(ctx: SkBuffContext) -> i32 {
    match { try_tc_bytes(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_bytes(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");

    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if h_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let protocol = ctx
        .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
        .map_err(|_| TC_ACT_PIPE)?;

    if protocol != IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
        &mut *ptr
    };

    let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    let len = ctx
        .load_bytes(offset, &mut buf.buf)
        .map_err(|_| TC_ACT_PIPE)?;

    info!(&ctx, "loaded the packet");

    // This annoys the verifier, we cannot check the whole packet. :(
    // So let's rather limit it to 128 bytes, should be enough for getting
    // HTTP headers.
    //
    // if let Some(_) = &buf.buf[..len]
    let len = cmp::min(len, 128);
    if let Some(_) = &buf.buf[..len]
        .windows(X_FORWARDED_FOR.len())
        .position(|window| window == X_FORWARDED_FOR)
    {
        info!(&ctx, "found X-Forwarded-For header");
    }

    Ok(TC_ACT_PIPE)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const IPPROTO_TCP: u8 = 6;
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const X_FORWARDED_FOR: &[u8; 15] = b"X-Forwarded-For";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

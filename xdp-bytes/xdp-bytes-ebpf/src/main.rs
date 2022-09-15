#![no_std]
#![no_main]

use core::{cmp, mem};

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};
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
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[xdp(name = "xdp_bytes")]
pub fn xdp_bytes(ctx: XdpContext) -> u32 {
    match { try_xdp_bytes(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_bytes(mut ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto)).map_err(|_| xdp_action::XDP_PASS)?
    });

    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let protocol = unsafe {
        *ptr_at::<u8>(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| xdp_action::XDP_PASS)?
    };
    info!(&ctx, "loaded protocol: {}", protocol);

    if protocol != IPPROTO_TCP {
        info!(&ctx, "not a TCP packet");
        return Ok(xdp_action::XDP_PASS);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(xdp_action::XDP_PASS)?;
        &mut *ptr
    };

    if ctx.data() > 0xffff {
        info!(&ctx, "data is too large wtf");
    }
    // let offset = 128;
    // let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    // let offset = 0usize;
    // let offset = ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    // info!(&ctx, "data: {}", ctx.data());
    let offset = ctx.data();
    // info!(&ctx, "offset: {}", offset);
    info!(
        &ctx,
        "almost offset: {}",
        ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN
    );
    // info!(&ctx, "len: {}", ctx.data_end() - offset);
    let len = ctx.load_bytes(offset, &mut buf.buf).map_err(|e| {
        error!(&ctx, "failed to load the packet: {}", e);
        xdp_action::XDP_PASS
    })?;

    info!(&ctx, "loaded the packet");

    // This annoys the verifier, we cannot check the whole packet. :(
    // So let's rather limit it to 128 bytes, should be enough for getting
    // HTTP headers.
    //
    // if let Some(_) = &buf.buf[..len]

    // let len = cmp::min(len, 128);
    // if let Some(_) = &buf.buf[..len]
    //     .windows(X_FORWARDED_FOR.len())
    //     .position(|window| window == X_FORWARDED_FOR)
    // {
    //     info!(&ctx, "found X-Forwarded-For header");
    // }

    Ok(xdp_action::XDP_PASS)
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

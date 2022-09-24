#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use memoffset::offset_of;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, tcphdr};

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const IPPROTO_TCP: u8 = 6;

#[xdp(name = "xdp_redirect")]
pub fn xdp_redirect(ctx: XdpContext) -> u32 {
    match try_xdp_redirect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn ptr_at_common<T>(ctx: &XdpContext, offset: usize) -> Result<usize, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok(start + offset)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let ptr = ptr_at_common::<T>(ctx, offset)?;
    Ok(ptr as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at_common::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

fn try_xdp_redirect(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto)).map_err(|_| xdp_action::XDP_PASS)?
    });

    if h_proto != ETH_P_IP {
        return Err(xdp_action::XDP_PASS);
    }

    let protocol = unsafe {
        *ptr_at::<u8>(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| xdp_action::XDP_PASS)?
    };

    if protocol != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))
            .map_err(|_| xdp_action::XDP_PASS)?
    });

    info!(&ctx, "dest: {}", dest);

    if dest == 8080 {
        info!(&ctx, "redirecting from 8080 to 80");
        unsafe {
            *ptr_at_mut(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))
                .map_err(|_| xdp_action::XDP_PASS)? = 80u16.to_be();
        };
        let check = unsafe {
            *ptr_at::<u16>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, check))
                .map_err(|_| xdp_action::XDP_PASS)?
        };
        unsafe {
            *ptr_at_mut(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, check))
                .map_err(|_| xdp_action::XDP_PASS)? = check + 1;
        };

        return Ok(xdp_action::XDP_TX);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

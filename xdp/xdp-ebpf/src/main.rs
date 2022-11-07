#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    ethernet::{EthHdr, EthProtocol, ETH_HDR_LEN},
    ip::{Ipv4Hdr, Ipv4Protocol, IPV4_HDR_LEN},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp(name = "log")]
pub fn log(ctx: XdpContext) -> u32 {
    match try_log(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_log(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0) }?;
    let (daddr, saddr, dport, sport) = match unsafe { *eth_hdr }.protocol()? {
        EthProtocol::Ipv4 => {
            let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN)? };
            let daddr = unsafe { *ipv4_hdr }.daddr();
            let saddr = unsafe { *ipv4_hdr }.saddr();
            match unsafe { *ipv4_hdr }.protocol()? {
                Ipv4Protocol::Tcp => {
                    let tcp_hdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN)? };
                    let dport = u16::from_be(unsafe { *tcp_hdr }.dest);
                    let sport = u16::from_be(unsafe { *tcp_hdr }.source);
                    (daddr, saddr, dport, sport)
                }
                Ipv4Protocol::Udp => {
                    let udp_hdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN)? };
                    let dport = u16::from_be(unsafe { *udp_hdr }.dest);
                    let sport = u16::from_be(unsafe { *udp_hdr }.source);
                    (daddr, saddr, dport, sport)
                }
                _ => return Ok(xdp_action::XDP_PASS),
            }
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(
        &ctx,
        "destination ip: {:ipv4}, source ip: {:ipv4}, destination port: {}, source port: {}",
        daddr,
        saddr,
        dport,
        sport
    );

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

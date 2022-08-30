#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error, info, trace, warn};

#[xdp(name = "log")]
pub fn log(ctx: XdpContext) -> u32 {
    debug!(&ctx, "foo bar");
    error!(
        &ctx,
        "some {} arguments {} {} {}", -1, 1, 3.14, "some string"
    );

    let ipv4: u32 = 167772161;
    let ipv6_1: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01,
    ];
    let ipv6_2: [u16; 8] = [
        0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001,
    ];

    info!(&ctx, "{:ipv4} {:ipv6} {:ipv6}", ipv4, ipv6_1, ipv6_2);
    trace!(&ctx, "{:x} {:X}", 200, 200);
    warn!(&ctx, "foo bar");

    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

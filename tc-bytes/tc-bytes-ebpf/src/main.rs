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

const ETH_P_IP: u16 = 0x0800;

const IPPROTO_TCP: u8 = 6;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const X_FORWARDED_FOR: &[u8; 15] = b"X-Forwarded-For";

const MAX_IP_STR_LEN: usize = 15;

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

    let len = cmp::min(len, 128);
    if let Some(pos) = buf.buf[..len]
        .windows(X_FORWARDED_FOR.len())
        .position(|window| window == X_FORWARDED_FOR)
    {
        info!(&ctx, "Found X-Forwarded-For header!");

        let end = cmp::min(pos + MAX_IP_STR_LEN, buf.buf.len());
        if end > BUF_CAPACITY {
            return Ok(TC_ACT_PIPE);
        }

        let mut ip = 0u32;
        let mut octet = 0u8;
        for n in 0..MAX_IP_STR_LEN {
            let i = pos + n;
            if i > BUF_CAPACITY {
                return Ok(TC_ACT_PIPE);
            }
            let c = buf.buf[i];
            if c >= b'0' && c <= b'9' {
                if octet > u8::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                let prev_int = octet * 10;
                if prev_int > u8::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                let zero = b'0';
                if zero > u8::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                let cur_int = c - zero;
                if cur_int > u8::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                octet = prev_int + cur_int;
                if octet > u8::MAX {
                    return Ok(TC_ACT_PIPE);
                }
            } else if c == b'.' {
                if ip > u32::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                let prev_octets = ip << 8;
                if prev_octets > u32::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                ip = prev_octets + octet as u32;
                if ip > u32::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                octet = 0;
            } else {
                if ip > u32::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                let prev_octets = ip << 8;
                if prev_octets > u32::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                ip = prev_octets + octet as u32;
                if ip > u32::MAX {
                    return Ok(TC_ACT_PIPE);
                }
                break;
            }
        }

        info!(&ctx, "ip: {}", ip);
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#![no_std]
#![no_main]

use core::{cmp, mem};

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
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

// const BUF_CAPACITY: usize = 9198;
const BUF_CAPACITY: usize = 256;

const ETH_P_IP: u16 = 0x0800;

const IPPROTO_TCP: u8 = 6;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const X_FORWARDED_FOR: &[u8; 17] = b"X-Forwarded-For: ";

const MAX_IP_STR_LEN: usize = 15;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; BUF_CAPACITY],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut ADDRESSES: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

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
    let len = cmp::min(len, BUF_CAPACITY);

    let mut found = false;
    let mut pos: usize = 0;
    for i in 0..len {
        if i + X_FORWARDED_FOR.len() >= BUF_CAPACITY {
            return Ok(TC_ACT_PIPE);
        }
        if buf.buf[i] != X_FORWARDED_FOR[0]
            || buf.buf[i + 1] != X_FORWARDED_FOR[1]
            || buf.buf[i + 2] != X_FORWARDED_FOR[2]
            || buf.buf[i + 3] != X_FORWARDED_FOR[3]
            || buf.buf[i + 4] != X_FORWARDED_FOR[4]
            || buf.buf[i + 5] != X_FORWARDED_FOR[5]
            || buf.buf[i + 6] != X_FORWARDED_FOR[6]
            || buf.buf[i + 7] != X_FORWARDED_FOR[7]
            || buf.buf[i + 8] != X_FORWARDED_FOR[8]
            || buf.buf[i + 9] != X_FORWARDED_FOR[9]
            || buf.buf[i + 10] != X_FORWARDED_FOR[10]
            || buf.buf[i + 11] != X_FORWARDED_FOR[11]
            || buf.buf[i + 12] != X_FORWARDED_FOR[12]
            || buf.buf[i + 13] != X_FORWARDED_FOR[13]
            || buf.buf[i + 14] != X_FORWARDED_FOR[14]
            || buf.buf[i + 15] != X_FORWARDED_FOR[15]
            || buf.buf[i + 16] != X_FORWARDED_FOR[16]
        {
            continue;
        }
        found = true;
        pos = i + X_FORWARDED_FOR.len();
        break;
    }

    if !found {
        return Ok(TC_ACT_PIPE);
    }

    let mut ip = 0u32;
    let mut octet = 0u8;
    for n in 0..MAX_IP_STR_LEN {
        let i = pos + n;
        if i >= BUF_CAPACITY {
            return Ok(TC_ACT_PIPE);
        }
        let c = buf.buf[i];
        if (b'0'..b'9').contains(&c) {
            octet = (octet * 10) + c - b'0';
        } else if c == b'.' {
            let prev_octets = ip << 8;
            ip = prev_octets + octet as u32;
            octet = 0;
        } else {
            let prev_octets = ip << 8;
            ip = prev_octets + octet as u32;
            break;
        }
    }

    unsafe { ADDRESSES.insert(&ip, &ip, 0) }.map_err(|e| e as i32)?;
    info!(&ctx, "ip: {}", ip);

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

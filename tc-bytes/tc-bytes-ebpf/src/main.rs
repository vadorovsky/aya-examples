#![no_std]
#![no_main]

use core::{cmp, mem};

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
    programs::SkBuffContext,
};
// use aya_log_ebpf::info;
use memoffset::offset_of;

use tc_bytes_common::{find_x_forwarded_for_header, parse_ipv4_addr};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, tcphdr};

const BUF_CAPACITY: usize = 256;

const ETH_P_IP: u16 = 0x0800;

const IPPROTO_TCP: u8 = 6;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

const MAX_IP_STR_LEN: usize = 15;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; BUF_CAPACITY],
}

#[map]
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static ADDRESSES: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

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

    let (found, pos) = find_x_forwarded_for_header(&buf.buf[..len]);

    if !found {
        return Ok(TC_ACT_PIPE);
    }

    let end = pos + MAX_IP_STR_LEN;
    if end >= BUF_CAPACITY {
        return Ok(TC_ACT_PIPE);
    }
    let ip_buf = &buf.buf[pos..pos + MAX_IP_STR_LEN];
    let ip = parse_ipv4_addr(ip_buf).map_err(|_| TC_ACT_PIPE)?;

    unsafe { ADDRESSES.insert(&ip, &ip, 0) }.map_err(|e| e as i32)?;

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

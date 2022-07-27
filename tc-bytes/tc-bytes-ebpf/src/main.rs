#![no_std]
#![no_main]

use core::{cmp, mem, slice};

use aya_bpf::{
    bindings::{__sk_buff, TC_ACT_PIPE},
    helpers::bpf_skb_pull_data,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
    programs::SkBuffContext,
    BpfContext,
};
use aya_log_ebpf::info;
use memoffset::offset_of;

use tc_bytes_common::{find_x_forwarded_for_header, parse_ipv4_addr};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, tcphdr};

const BUF_CAPACITY: usize = 128;
const MAX_CHECK: usize = 128;

const ETH_P_IP: u16 = 0x0800;

const IPPROTO_TCP: u8 = 6;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

const X_FORWARDED_FOR: &[u8; 17] = b"X-Forwarded-For: ";

const MAX_IP_STR_LEN: usize = 15;

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

    // let buf = unsafe {
    //     let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
    //     &mut *ptr
    // };

    let start = unsafe { (*ctx.skb).data as usize };
    let end = unsafe { (*ctx.skb).data_end as usize };

    let mut offset = X_FORWARDED_FOR.len();
    let mut found = false;
    if start + offset > end {
        return Ok(TC_ACT_PIPE);
    }
    while start + offset < end {
        let ret = unsafe { bpf_skb_pull_data(ctx.skb, (offset + X_FORWARDED_FOR.len()) as u32) };
        if ret != 0 {
            return Ok(TC_ACT_PIPE);
        }
        let buf = unsafe {
            slice::from_raw_parts(
                (start + offset) as *const u8 as *const _,
                X_FORWARDED_FOR.len(),
            )
        };
        if buf == X_FORWARDED_FOR {
            found = true;
            break;
        }
    }

    if found {
        info!(&ctx, "found X-Forwarded-For header");
    }

    // let len = cmp::min(end as usize - start as usize, BUF_CAPACITY);
    // let ret = unsafe { bpf_skb_pull_data(ctx.skb, len as u32) };
    // if ret != 0 {
    //     return Ok(TC_ACT_PIPE);
    // }
    // if start + len > end {
    //     return Ok(TC_ACT_PIPE);
    // }
    // // let len = end as usize - start as usize;
    // let bytes = unsafe { slice::from_raw_parts((*ctx.skb).data as usize as *const u8, len) };
    // if start + bytes.len() > end {
    //     return Ok(TC_ACT_PIPE);
    // }

    // info!(&ctx, "bytes: {}", bytes.len());

    // let (found, pos) = find_x_forwarded_for_header(&buf.buf[..len]);
    // let mut found = false;
    // let mut pos: usize = 0;
    // for i in 0..(bytes.len() - X_FORWARDED_FOR.len()) {
    //     if &bytes[i..i + X_FORWARDED_FOR.len()] == X_FORWARDED_FOR {
    //         found = true;
    //         pos = i + X_FORWARDED_FOR.len();
    //         break;
    //     }
    // }

    // if found {
    //     info!(&ctx, "found x-forwarded-for header, pos: {}", pos);
    // }

    // if !found {
    //     return Ok(TC_ACT_PIPE);
    // }

    // let end = pos + MAX_IP_STR_LEN;
    // if end >= BUF_CAPACITY {
    //     return Ok(TC_ACT_PIPE);
    // }
    // let ip_buf = &buf.buf[pos..pos + MAX_IP_STR_LEN];
    // // let ip = parse_ipv4_addr(ip_buf).map_err(|_| TC_ACT_PIPE)?;

    // if buf.len() > MAX_IP_STR_LEN {
    //     return Err(-1);
    // }

    // let mut ip = 0u32;
    // let mut octet = 0u32;
    // for c in ip_buf {
    //     if (b'0'..b'9' + 1).contains(c) {
    //         octet = (octet * 10) + *c as u32 - b'0' as u32;
    //     } else if *c == b'.' {
    //         ip = (ip << 8) + octet as u32;
    //         octet = 0;
    //     }
    // }
    // ip = (ip << 8) + octet as u32;

    // unsafe { ADDRESSES.insert(&ip, &ip, 0) }.map_err(|e| e as i32)?;

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

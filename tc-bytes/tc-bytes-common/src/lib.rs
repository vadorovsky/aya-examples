#![no_std]

#[inline(always)]
pub fn parse_ipv4_addr(buf: &[u8]) -> u32 {
    let mut ip = 0u32;
    let mut octet = 0u8;
    for i in 0..buf.len() {
        let c = buf[i];
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

    ip
}

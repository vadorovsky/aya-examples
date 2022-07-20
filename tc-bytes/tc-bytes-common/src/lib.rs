#![no_std]

const X_FORWARDED_FOR: &[u8; 17] = b"X-Forwarded-For: ";

const MAX_IP_STR_LEN: usize = 15;

#[inline(always)]
pub fn find_x_forwarded_for_header(buf: &[u8]) -> (bool, usize) {
    let mut found = false;
    let mut pos: usize = 0;
    for i in 0..buf.len() {
        if i + X_FORWARDED_FOR.len() >= buf.len() {
            return (false, 0);
        }
        if &buf[i..i + X_FORWARDED_FOR.len()] == X_FORWARDED_FOR {
            found = true;
            pos = i + X_FORWARDED_FOR.len();
            break;
        }
    }
    (found, pos)
}

#[inline(always)]
pub fn parse_ipv4_addr(buf: &[u8]) -> Result<u32, i64> {
    if buf.len() > MAX_IP_STR_LEN {
        return Err(-1);
    }

    let mut ip = 0u32;
    let mut octet = 0u32;
    for c in buf {
        if (b'0'..b'9' + 1).contains(c) {
            octet = (octet * 10) + *c as u32 - b'0' as u32;
        } else if *c == b'.' {
            ip = (ip << 8) + octet as u32;
            octet = 0;
        }
    }
    ip = (ip << 8) + octet as u32;

    Ok(ip)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_x_forwarded_for_header() {
        let buf = b"X-Forwarded-For: 10.0.0.1";
        assert_eq!(find_x_forwarded_for_header(buf), (true, 17));
        let buf = b"foo bar X-Forwarded-For: 10.0.0.1";
        assert_eq!(find_x_forwarded_for_header(buf), (true, 25));
        let buf = b"";
        assert_eq!(find_x_forwarded_for_header(buf), (false, 0));
        let buf = b"foo bar ayy lmao";
        assert_eq!(find_x_forwarded_for_header(buf), (false, 0));
    }

    #[test]
    fn test_parse_ipv4_addr() {
        assert_eq!(parse_ipv4_addr(b"127.0.0.1").unwrap(), 2130706433);
        assert_eq!(parse_ipv4_addr(b"1.1.1.1").unwrap(), 16843009);
        assert_eq!(parse_ipv4_addr(b"8.8.8.8").unwrap(), 134744072);
        assert_eq!(parse_ipv4_addr(b"10.0.0.1").unwrap(), 167772161);
        assert_eq!(parse_ipv4_addr(b"10.10.10.1").unwrap(), 168430081);
        assert_eq!(parse_ipv4_addr(b"192.168.0.1").unwrap(), 3232235521);
        assert_eq!(parse_ipv4_addr(b"192.168.100.1").unwrap(), 3232261121);
        assert_eq!(parse_ipv4_addr(b"255.255.255.0").unwrap(), 4294967040);
        assert_eq!(parse_ipv4_addr(b"255.255.255.255").unwrap(), 4294967295);

        assert!(parse_ipv4_addr(b"255.255.255.255.255").is_err());
        assert!(parse_ipv4_addr(b"somethingwhichisnotanaddressandistoolong").is_err());
    }
}

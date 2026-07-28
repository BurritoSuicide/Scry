//! CIDR / subnet parsing — expand to the first address in range.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse `addr/prefix` and return `(first_ip, original_cidr)` when the input is a real subnet
/// (prefix shorter than host-only). Host routes (/32, /128) return `None` so we keep them as plain IPs.
pub fn parse_cidr(input: &str) -> Option<(String, String)> {
    let input = input.trim();
    let (addr_part, prefix_part) = input.split_once('/')?;
    let prefix: u8 = prefix_part.parse().ok()?;
    let first = expand_cidr_to_first_ip(addr_part, prefix)?;
    // Host-only routes are not "subnets" for notification purposes.
    let is_host_only = match first.parse::<Ipv4Addr>() {
        Ok(_) => prefix >= 32,
        Err(_) => prefix >= 128,
    };
    if is_host_only {
        return None;
    }
    Some((first, input.to_string()))
}

pub fn expand_cidr_to_first_ip(addr: &str, prefix: u8) -> Option<String> {
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        if prefix > 32 {
            return None;
        }
        let ip = u32::from(v4);
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = Ipv4Addr::from(ip & mask);
        return Some(network.to_string());
    }

    if let Ok(v6) = addr.parse::<Ipv6Addr>() {
        if prefix > 128 {
            return None;
        }
        let segments = v6.segments();
        let mut bytes = [0u8; 16];
        for (i, seg) in segments.iter().enumerate() {
            bytes[i * 2] = (seg >> 8) as u8;
            bytes[i * 2 + 1] = (seg & 0xff) as u8;
        }
        // Zero host bits beyond prefix.
        let full_bytes = (prefix / 8) as usize;
        let rem = prefix % 8;
        if full_bytes < 16 {
            if rem > 0 {
                let mask = 0xffu8 << (8 - rem);
                bytes[full_bytes] &= mask;
                for b in bytes.iter_mut().skip(full_bytes + 1) {
                    *b = 0;
                }
            } else {
                for b in bytes.iter_mut().skip(full_bytes) {
                    *b = 0;
                }
            }
        }
        return Some(Ipv6Addr::from(bytes).to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_v4_subnet() {
        let (first, cidr) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(first, "192.168.1.0");
        assert_eq!(cidr, "192.168.1.0/24");

        let (first, _) = parse_cidr("10.0.0.5/24").unwrap();
        assert_eq!(first, "10.0.0.0");
    }

    #[test]
    fn ignores_host_route() {
        assert!(parse_cidr("8.8.8.8/32").is_none());
    }

    #[test]
    fn expands_v6_subnet() {
        let (first, _) = parse_cidr("2001:db8::1/64").unwrap();
        assert_eq!(first, "2001:db8::");
    }
}

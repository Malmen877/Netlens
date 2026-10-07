//! Optional IP masking: consistently map every IPv4/IPv6 address to a
//! placeholder (`IP4_1`, `IP6_1`) before text goes to a model, and map the
//! placeholders back in the model's answer. Masks, wildcards, 0.0.0.0 and
//! 255.255.255.255 are left alone; prefix lengths are kept (`IP4_3/24`).

use regex::Regex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

static RE_V4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static RE_V6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%\w+)?").unwrap());
static RE_PH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bIP([46])_(\d+)\b").unwrap());

fn is_mask_like(ip: Ipv4Addr) -> bool {
    let contiguous = |v: u32| v.checked_shl(v.leading_ones()).unwrap_or(0) == 0;
    let v = u32::from(ip);
    // Netmask (255.255.255.0) or wildcard (0.0.0.255).
    contiguous(v) || contiguous(!v)
}

#[derive(Debug, Default, Clone)]
pub struct IpMasker {
    fwd: HashMap<String, String>,
    rev: HashMap<String, String>,
    v4: usize,
    v6: usize,
}

impl IpMasker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.fwd.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fwd.is_empty()
    }

    fn map(&mut self, ip: &str, v6: bool) -> String {
        if let Some(p) = self.fwd.get(ip) {
            return p.clone();
        }
        let p = if v6 {
            self.v6 += 1;
            format!("IP6_{}", self.v6)
        } else {
            self.v4 += 1;
            format!("IP4_{}", self.v4)
        };
        self.fwd.insert(ip.to_string(), p.clone());
        self.rev.insert(p.clone(), ip.to_string());
        p
    }

    pub fn mask(&mut self, text: &str) -> String {
        // IPv6 first (it can contain dotted IPv4 tails rarely; ignore those).
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        let v6_matches: Vec<(usize, usize, String)> = RE_V6
            .find_iter(text)
            .filter_map(|m| {
                let s = m.as_str();
                let core = s.split('%').next().unwrap_or(s);
                // Must contain "::" or 7 colons, and parse as IPv6.
                let colons = core.matches(':').count();
                if (core.contains("::") || colons == 7)
                    && core.parse::<Ipv6Addr>().is_ok()
                    && core != "::"
                {
                    // Avoid matching inside words like "a::b" in prose? accept.
                    Some((m.start(), m.start() + core.len(), core.to_string()))
                } else {
                    None
                }
            })
            .collect();
        for (a, b, ip) in v6_matches {
            if a < last {
                continue;
            }
            out.push_str(&text[last..a]);
            let lower = ip.to_ascii_lowercase();
            out.push_str(&self.map(&lower, true));
            last = b;
        }
        out.push_str(&text[last..]);
        let staged = out;
        let mut out = String::with_capacity(staged.len());
        let mut last = 0;
        for m in RE_V4.find_iter(&staged) {
            let s = m.as_str();
            let Ok(ip) = s.parse::<Ipv4Addr>() else {
                continue;
            };
            if ip.is_unspecified() || ip.is_broadcast() || is_mask_like(ip) {
                continue;
            }
            out.push_str(&staged[last..m.start()]);
            out.push_str(&self.map(s, false));
            last = m.end();
        }
        out.push_str(&staged[last..]);
        out
    }

    /// Replace placeholders with the original addresses.
    pub fn unmask(&self, text: &str) -> String {
        RE_PH
            .replace_all(text, |c: &regex::Captures| {
                let k = c.get(0).map(|m| m.as_str()).unwrap_or("");
                self.rev.get(k).cloned().unwrap_or_else(|| k.to_string())
            })
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_consistently_and_unmasks() {
        let mut m = IpMasker::new();
        let a = m.mask("neighbor 198.51.100.1 remote-as 65002");
        let b = m.mask("ip route 0.0.0.0 0.0.0.0 198.51.100.1");
        assert_eq!(a, "neighbor IP4_1 remote-as 65002");
        assert_eq!(b, "ip route 0.0.0.0 0.0.0.0 IP4_1");
        assert_eq!(m.unmask("peer IP4_1 is down"), "peer 198.51.100.1 is down");
    }

    #[test]
    fn keeps_masks_wildcards_and_prefix_len() {
        let mut m = IpMasker::new();
        assert_eq!(
            m.mask("ip address 10.0.0.1 255.255.255.0"),
            "ip address IP4_1 255.255.255.0"
        );
        assert_eq!(
            m.mask("network 10.1.0.0 0.0.255.255 area 0"),
            "network IP4_2 0.0.255.255 area 0"
        );
        assert_eq!(m.mask("address 10.0.0.1/30;"), "address IP4_1/30;");
        assert_eq!(
            m.mask("permit ip any host 255.255.255.255"),
            "permit ip any host 255.255.255.255"
        );
    }

    #[test]
    fn ipv6_and_not_times_or_macs() {
        let mut m = IpMasker::new();
        assert_eq!(
            m.mask("ipv6 address 2001:db8::1/64"),
            "ipv6 address IP6_1/64"
        );
        assert_eq!(
            m.mask("Oct  7 12:30:45 r1 %BGP-5"),
            "Oct  7 12:30:45 r1 %BGP-5"
        );
        assert_eq!(m.mask("mac aa:bb:cc:dd:ee:ff"), "mac aa:bb:cc:dd:ee:ff");
        assert_eq!(
            m.mask("fe80::1%eth0 and 2001:DB8::1"),
            "IP6_2%eth0 and IP6_1"
        );
        assert_eq!(m.unmask("IP6_1"), "2001:db8::1");
    }

    #[test]
    fn invalid_octets_untouched() {
        let mut m = IpMasker::new();
        assert_eq!(m.mask("version 1.2.3.999"), "version 1.2.3.999");
        assert!(m.is_empty());
    }

    #[test]
    fn unknown_placeholder_kept() {
        let m = IpMasker::new();
        assert_eq!(m.unmask("IP4_9"), "IP4_9");
    }
}

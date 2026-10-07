//! Read-only command policy for the troubleshooting agent (phase 2).
//!
//! A command must (1) pass the hard denylist, which cannot be overridden,
//! (2) match an anchored per-vendor allowlist regex, and (3) only pipe into
//! display filters. Only then can it be turned into an [`ApprovedCommand`],
//! and only with an explicit human approval token.

use crate::vendor::Vendor;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "lowercase")]
pub enum Verdict {
    Allowed,
    Denied { reason: String },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allowed)
    }
}

/// First words that are never allowed (any vendor), even if an allowlist
/// entry would match.
pub const DENY_FIRST_WORDS: &[&str] = &[
    "configure",
    "conf",
    "config",
    "configuration",
    "write",
    "wr",
    "copy",
    "reload",
    "delete",
    "del",
    "clear",
    "debug",
    "undebug",
    "request",
    "set",
    "edit",
    "commit",
    "rollback",
    "erase",
    "format",
    "install",
    "upgrade",
    "shutdown",
    "no",
    "start",
    "restart",
    "file",
    "load",
    "save",
    "run",
    "bash",
    "python",
    "python3",
    "tclsh",
    "guestshell",
    "send",
    "ping",
    "traceroute",
    "telnet",
    "ssh",
    "terminal",
    "monitor",
    "test",
    "activate",
    "deactivate",
    "rename",
    "replace",
    "squeeze",
    "archive",
    "boot",
    "cli",
    "op",
    "event",
    "kill",
    "zerotouch",
    "cd",
    "mkdir",
];

/// Words that are never allowed anywhere in the command.
pub const DENY_ANY_WORDS: &[&str] = &[
    "configure",
    "write",
    "copy",
    "reload",
    "delete",
    "clear",
    "debug",
    "commit",
    "rollback",
    "erase",
    "redirect",
    "tee",
    "append",
    "save",
    "bash",
    "python",
    "tclsh",
    "request",
    "edit",
];

/// Display filters allowed after a pipe.
pub const SAFE_PIPE_FILTERS: &[&str] = &[
    "include", "inc", "i", "exclude", "exc", "ex", "e", "begin", "beg", "b", "section", "sec", "s",
    "count", "c", "match", "except", "find", "last", "no-more", "display", "json", "trim",
    "resolve", "hold",
];

/// Hard-coded safe subset for `| display ...` (Junos).
const SAFE_DISPLAY: &[&str] = &["set", "json", "xml", "inheritance", "detail"];

fn builtin_allow(v: Vendor) -> Vec<&'static str> {
    match v {
        Vendor::CiscoIos => vec![
            r"^show (?:ip |ipv6 )?(?:bgp|route|ospf|eigrp|interface|interfaces|arp|protocols|access-lists|prefix-list|policy|cef|nat|vrf|mroute|pim|igmp|sla|dhcp|nhrp|rip|isis|traffic|community-list|as-path-access-list|ssh|http|sockets)(?: [\w./:\-]+)*$",
            r"^show (?:version|running-config|run|startup-config|logging|clock|ntp|cdp|lldp|vlan|vlans|spanning-tree|mac|etherchannel|standby|vrrp|bfd|mpls|platform|processes|memory|inventory|environment|redundancy|module|controllers|route-map|access-lists|track|crypto|license|users|snmp|aaa|tacacs|radius|key|policy-map|class-map|hardware|boot|interfaces|ipv6|bgp|archive|object-group|errdisable|power|switch|stack|udld|dot1x|authentication|vtp|port-security|storm-control|monitor|tech-support)(?: [\w./:\-]+)*$",
        ],
        Vendor::AristaEos => vec![
            r"^show (?:ip |ipv6 )?(?:bgp|route|ospf|interface|interfaces|arp|access-lists|prefix-list|community-list|as-path|igmp|pim|mroute|dhcp|nat|virtual-router|helper-address)(?: [\w./:\-]+)*$",
            r"^show (?:version|running-config|startup-config|logging|clock|ntp|lldp|vlan|spanning-tree|mac|port-channel|lacp|mlag|vrrp|bfd|mpls|platform|processes|inventory|environment|redundancy|module|route-map|track|users|snmp|aaa|tacacs|radius|management|hardware|boot|interfaces|ipv6|bgp|vxlan|daemon|agent|extensions|reload|system|hostname|uptime|cpu|policy-map|class-map|qos|errdisable|sflow|tech-support|monitor|ptp|traffic-policy)(?: [\w./:\-]+)*$",
        ],
        Vendor::Junos => vec![
            r"^show (?:route|bgp|ospf|ospf3|isis|interfaces|configuration|system|chassis|log|lldp|arp|ethernet-switching|vlans|firewall|version|ntp|security|bfd|lacp|mpls|rsvp|ldp|policy-options|policy|snmp|services|pfe|class-of-service|dhcp|vrrp|igmp|pim|multicast|evpn|ipv6|host|krt|task|virtual-chassis|spanning-tree|bridge|mac-vrf|dhcp-relay|subscribers|lacp|link-management|oam|protection-cluster|forwarding-options|accounting)(?: [\w./:\-]+)*$",
        ],
    }
}

#[derive(Debug, Clone)]
pub struct CommandPolicy {
    allow: BTreeMap<Vendor, Vec<Regex>>,
}

impl Default for CommandPolicy {
    fn default() -> Self {
        Self::builtin()
    }
}

impl CommandPolicy {
    pub fn builtin() -> Self {
        let mut allow = BTreeMap::new();
        for v in Vendor::ALL {
            allow.insert(
                v,
                builtin_allow(v)
                    .into_iter()
                    .map(|p| Regex::new(p).expect("builtin regex"))
                    .collect(),
            );
        }
        CommandPolicy { allow }
    }

    /// Extend (or with `replace`, replace) the allowlist from config. Keys are
    /// vendor names ("ios", "junos", "eos"); patterns must be anchored `^...$`.
    pub fn with_overrides(
        mut self,
        extra: &BTreeMap<String, Vec<String>>,
        replace: bool,
    ) -> Result<Self, String> {
        for (k, pats) in extra {
            let v: Vendor = k.parse()?;
            let mut compiled = Vec::new();
            for p in pats {
                if !p.starts_with('^') || !p.ends_with('$') {
                    return Err(format!(
                        "allowlist pattern for {k} must be anchored with ^...$: {p}"
                    ));
                }
                compiled
                    .push(Regex::new(p).map_err(|e| format!("invalid allowlist regex {p}: {e}"))?);
            }
            let entry = self.allow.entry(v).or_default();
            if replace {
                *entry = compiled;
            } else {
                entry.extend(compiled);
            }
        }
        Ok(self)
    }

    pub fn patterns(&self, v: Vendor) -> Vec<String> {
        self.allow
            .get(&v)
            .map(|rs| rs.iter().map(|r| r.as_str().to_string()).collect())
            .unwrap_or_default()
    }

    pub fn check(&self, vendor: Vendor, cmd: &str) -> Verdict {
        let deny = |r: String| Verdict::Denied { reason: r };
        if cmd.trim().is_empty() {
            return deny("empty command".into());
        }
        if cmd.len() > 256 {
            return deny("command longer than 256 characters".into());
        }
        if cmd.chars().any(|c| c.is_control()) {
            return deny("command contains control characters or newlines".into());
        }
        for bad in [";", "`", "$(", "&&", "||", ">", "<", "\\"] {
            if cmd.contains(bad) {
                return deny(format!("command contains forbidden sequence '{bad}'"));
            }
        }
        let norm = cmd.split_whitespace().collect::<Vec<_>>().join(" ");
        let lower = norm.to_ascii_lowercase();
        let mut parts = lower.split('|').map(str::trim);
        let base = parts.next().unwrap_or("");
        let first = base.split(' ').next().unwrap_or("");
        if DENY_FIRST_WORDS.contains(&first) {
            return deny(format!(
                "'{first}' commands are never allowed (read-only tool)"
            ));
        }
        for w in lower.split([' ', '|']) {
            if DENY_ANY_WORDS.contains(&w) {
                return deny(format!("'{w}' is on the hard denylist"));
            }
        }
        for filt in parts {
            let mut fw = filt.split(' ');
            let f0 = fw.next().unwrap_or("");
            if !SAFE_PIPE_FILTERS.contains(&f0) {
                return deny(format!(
                    "pipe to '{f0}' is not allowed (only display filters)"
                ));
            }
            if f0 == "display" {
                let arg = fw.next().unwrap_or("");
                if !SAFE_DISPLAY.contains(&arg) {
                    return deny(format!("'| display {arg}' is not allowed"));
                }
            }
        }
        let base_orig = norm.split('|').next().unwrap_or("").trim().to_string();
        let ok = self
            .allow
            .get(&vendor)
            .map(|rs| {
                rs.iter()
                    .any(|r| r.is_match(&base_orig) || r.is_match(&base_orig.to_ascii_lowercase()))
            })
            .unwrap_or(false);
        if !ok {
            return deny(format!(
                "'{base_orig}' does not match the {} allowlist",
                vendor.key()
            ));
        }
        Verdict::Allowed
    }

    /// Turn a command into an [`ApprovedCommand`]. Requires a policy pass
    /// *and* a human approval token.
    pub fn approve(
        &self,
        vendor: Vendor,
        cmd: &str,
        _human: HumanApproval,
    ) -> Result<ApprovedCommand, String> {
        match self.check(vendor, cmd) {
            Verdict::Allowed => Ok(ApprovedCommand {
                cmd: cmd.split_whitespace().collect::<Vec<_>>().join(" "),
            }),
            Verdict::Denied { reason } => Err(reason),
        }
    }
}

/// Proof that a human said "y" at the terminal. Constructed only by the
/// interactive approval prompt (phase 2) or tests.
#[derive(Debug)]
pub struct HumanApproval(());

impl HumanApproval {
    /// Call only after an explicit interactive "y".
    pub fn confirmed_by_human() -> Self {
        HumanApproval(())
    }
}

/// A command that passed policy and human approval; the only thing the SSH
/// transport accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCommand {
    cmd: String,
}

impl ApprovedCommand {
    pub fn as_str(&self) -> &str {
        &self.cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(v: Vendor, c: &str) {
        assert_eq!(
            CommandPolicy::builtin().check(v, c),
            Verdict::Allowed,
            "{c}"
        );
    }
    fn no(v: Vendor, c: &str) {
        assert!(
            !CommandPolicy::builtin().check(v, c).is_allowed(),
            "should deny {c}"
        );
    }

    #[test]
    fn allows_show_commands() {
        ok(Vendor::CiscoIos, "show ip bgp summary");
        ok(
            Vendor::CiscoIos,
            "show ip bgp neighbors 10.0.0.2 received-routes",
        );
        ok(Vendor::CiscoIos, "show interfaces GigabitEthernet0/0/1");
        ok(Vendor::CiscoIos, "show logging | include BGP");
        ok(Vendor::CiscoIos, "show run | section router bgp");
        ok(Vendor::CiscoIos, "show  ip  route  0.0.0.0");
        ok(Vendor::AristaEos, "show ip bgp summary vrf all");
        ok(Vendor::AristaEos, "show interfaces Ethernet1 status | json");
        ok(Vendor::Junos, "show bgp neighbor 198.51.100.1");
        ok(Vendor::Junos, "show route 10.0.0.0/24 exact");
        ok(Vendor::Junos, "show log messages | match bgp | last 50");
        ok(
            Vendor::Junos,
            "show configuration protocols bgp | display set",
        );
    }

    #[test]
    fn denies_write_and_config() {
        for c in [
            "configure terminal",
            "conf t",
            "write memory",
            "copy running-config startup-config",
            "reload in 5",
            "clear ip bgp *",
            "debug ip bgp",
            "delete flash:config.text",
            "request system reboot",
            "set cli screen-length 0",
            "edit protocols bgp",
            "commit",
            "terminal length 0",
            "ping 10.0.0.1",
            "no shutdown",
            "bash ls",
            "",
        ] {
            no(Vendor::CiscoIos, c);
            no(Vendor::Junos, c);
        }
    }

    #[test]
    fn denies_injection_and_redirects() {
        no(Vendor::CiscoIos, "show run | redirect flash:x.txt");
        no(Vendor::CiscoIos, "show run | tee flash:x");
        no(Vendor::CiscoIos, "show run | append flash:x");
        no(Vendor::Junos, "show configuration | save /var/tmp/x");
        no(Vendor::Junos, "show configuration | display rollback");
        no(Vendor::CiscoIos, "show version; reload");
        no(Vendor::CiscoIos, "show version\nreload");
        no(Vendor::CiscoIos, "show version > flash:v");
        no(Vendor::CiscoIos, "show `reload`");
        no(Vendor::CiscoIos, "show $(reload)");
        no(Vendor::CiscoIos, "show clock && reload");
        no(Vendor::AristaEos, "show version | bash rm -rf /");
        no(Vendor::CiscoIos, "show ip bgp | copy");
    }

    #[test]
    fn denies_unlisted() {
        no(Vendor::CiscoIos, "dir flash:");
        no(Vendor::CiscoIos, "more flash:config.text");
        no(Vendor::Junos, "file show /etc/passwd");
        no(Vendor::Junos, "start shell");
        no(Vendor::Junos, "show \"quoted\"");
    }

    #[test]
    fn overrides_must_be_anchored() {
        let mut m = BTreeMap::new();
        m.insert("ios".to_string(), vec!["show foo".to_string()]);
        assert!(CommandPolicy::builtin().with_overrides(&m, false).is_err());
        let mut m = BTreeMap::new();
        m.insert("ios".to_string(), vec!["^dir flash:$".to_string()]);
        let p = CommandPolicy::builtin().with_overrides(&m, false).unwrap();
        assert!(p.check(Vendor::CiscoIos, "dir flash:").is_allowed());
        // The denylist still wins over any allowlist entry.
        let mut m = BTreeMap::new();
        m.insert("ios".to_string(), vec!["^.*$".to_string()]);
        let p = CommandPolicy::builtin().with_overrides(&m, true).unwrap();
        assert!(!p.check(Vendor::CiscoIos, "reload").is_allowed());
        assert!(!p
            .check(Vendor::CiscoIos, "show run | redirect x")
            .is_allowed());
        assert!(!p.check(Vendor::CiscoIos, "copy run start").is_allowed());
    }

    #[test]
    fn approve_requires_policy() {
        let p = CommandPolicy::builtin();
        let a = p
            .approve(
                Vendor::CiscoIos,
                "show  ip bgp summary",
                HumanApproval::confirmed_by_human(),
            )
            .unwrap();
        assert_eq!(a.as_str(), "show ip bgp summary");
        assert!(p
            .approve(
                Vendor::CiscoIos,
                "reload",
                HumanApproval::confirmed_by_human()
            )
            .is_err());
    }
}

//! Classify statements into semantic sections.

use crate::model::Stmt;
use crate::vendor::Vendor;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Section {
    Interfaces,
    Acl,
    RoutePolicy,
    Bgp,
    Ospf,
    StaticRoutes,
    Mgmt,
    Vlans,
    Qos,
    System,
    Other,
}

impl Section {
    pub fn as_str(&self) -> &'static str {
        match self {
            Section::Interfaces => "interfaces",
            Section::Acl => "acl",
            Section::RoutePolicy => "route-policy",
            Section::Bgp => "bgp",
            Section::Ospf => "ospf",
            Section::StaticRoutes => "static-routes",
            Section::Mgmt => "mgmt-plane",
            Section::Vlans => "vlans",
            Section::Qos => "qos",
            Section::System => "system",
            Section::Other => "other",
        }
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn classify(stmt: &Stmt, vendor: Vendor) -> Section {
    let head = stmt.path.first().map(String::as_str).unwrap_or("");
    match vendor {
        Vendor::Junos => classify_junos(head),
        _ => classify_ios(head),
    }
}

pub fn classify_ios(head: &str) -> Section {
    let h = head.to_ascii_lowercase();
    let starts = |p: &str| h == p || h.starts_with(&format!("{p} "));
    if starts("interface") {
        Section::Interfaces
    } else if starts("ip access-list")
        || starts("ipv6 access-list")
        || starts("mac access-list")
        || starts("access-list")
        || starts("object-group")
    {
        Section::Acl
    } else if starts("route-map")
        || starts("ip prefix-list")
        || starts("ipv6 prefix-list")
        || starts("ip community-list")
        || starts("ip extcommunity-list")
        || starts("ip as-path")
        || starts("peer-filter")
    {
        Section::RoutePolicy
    } else if starts("router bgp") {
        Section::Bgp
    } else if starts("router ospf") || starts("router ospfv3") || starts("ipv6 router ospf") {
        Section::Ospf
    } else if starts("ip route") || starts("ipv6 route") {
        Section::StaticRoutes
    } else if mgmt_category_ios(&h).is_some() {
        Section::Mgmt
    } else if starts("vlan") {
        Section::Vlans
    } else if starts("policy-map") || starts("class-map") || starts("qos") {
        Section::Qos
    } else if starts("hostname")
        || starts("ip domain")
        || starts("ip domain-name")
        || starts("service")
        || starts("clock")
        || starts("boot")
        || starts("version")
        || starts("ip name-server")
        || starts("dns domain")
    {
        Section::System
    } else {
        Section::Other
    }
}

/// Management-plane category for an IOS/EOS top-level line (lowercased).
pub fn mgmt_category_ios(h: &str) -> Option<&'static str> {
    let starts = |p: &str| h == p || h.starts_with(&format!("{p} "));
    if starts("aaa") {
        Some("AAA")
    } else if starts("line vty") || starts("line con") || starts("line aux") {
        Some("VTY/console lines")
    } else if starts("ip ssh") || starts("management ssh") || starts("ssh") {
        Some("SSH")
    } else if starts("username") || starts("enable secret") || starts("enable password") {
        Some("local users/enable")
    } else if starts("snmp-server") || starts("snmp") {
        Some("SNMP")
    } else if starts("tacacs-server")
        || starts("tacacs")
        || starts("radius-server")
        || starts("radius")
        || starts("ip tacacs")
        || starts("ip radius")
    {
        Some("TACACS+/RADIUS")
    } else if starts("ntp") {
        Some("NTP")
    } else if starts("logging") {
        Some("logging")
    } else if starts("ip http") || starts("management api") || starts("management telnet") {
        Some("HTTP/API/telnet")
    } else {
        None
    }
}

/// Junos statements: classify by leading words (handles `deactivate` and
/// `routing-instances X ...`).
pub fn classify_junos(stmt: &str) -> Section {
    let mut s = stmt.strip_prefix("deactivate ").unwrap_or(stmt);
    if let Some(rest) = s.strip_prefix("routing-instances ") {
        // drop the instance name
        s = rest.split_once(' ').map(|(_, r)| r).unwrap_or("");
    }
    if let Some(rest) = s.strip_prefix("logical-systems ") {
        s = rest.split_once(' ').map(|(_, r)| r).unwrap_or("");
    }
    let starts = |p: &str| s == p || s.starts_with(&format!("{p} "));
    if starts("interfaces") {
        Section::Interfaces
    } else if starts("firewall") {
        Section::Acl
    } else if starts("policy-options") {
        Section::RoutePolicy
    } else if starts("protocols bgp") {
        Section::Bgp
    } else if starts("protocols ospf") || starts("protocols ospf3") {
        Section::Ospf
    } else if starts("routing-options static") || starts("routing-options rib") {
        Section::StaticRoutes
    } else if mgmt_category_junos(s).is_some() {
        Section::Mgmt
    } else if starts("vlans") {
        Section::Vlans
    } else if starts("class-of-service") {
        Section::Qos
    } else if starts("system") || starts("chassis") || starts("version") {
        Section::System
    } else {
        Section::Other
    }
}

pub fn mgmt_category_junos(stmt: &str) -> Option<&'static str> {
    let s = stmt.strip_prefix("deactivate ").unwrap_or(stmt);
    let starts = |p: &str| s == p || s.starts_with(&format!("{p} "));
    if starts("system authentication-order") {
        Some("AAA")
    } else if starts("system login") || starts("system root-authentication") {
        Some("local users/enable")
    } else if starts("system services ssh") {
        Some("SSH")
    } else if starts("system services") {
        Some("HTTP/API/telnet")
    } else if starts("system tacplus-server")
        || starts("system radius-server")
        || starts("system accounting")
    {
        Some("TACACS+/RADIUS")
    } else if starts("snmp") {
        Some("SNMP")
    } else if starts("system ntp") {
        Some("NTP")
    } else if starts("system syslog") {
        Some("logging")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ios_sections() {
        assert_eq!(
            classify_ios("interface GigabitEthernet1"),
            Section::Interfaces
        );
        assert_eq!(classify_ios("ip access-list extended X"), Section::Acl);
        assert_eq!(classify_ios("access-list 10 permit any"), Section::Acl);
        assert_eq!(classify_ios("route-map RM permit 10"), Section::RoutePolicy);
        assert_eq!(
            classify_ios("ip prefix-list PL seq 5 permit 10.0.0.0/8"),
            Section::RoutePolicy
        );
        assert_eq!(classify_ios("router bgp 65001"), Section::Bgp);
        assert_eq!(classify_ios("router ospf 1"), Section::Ospf);
        assert_eq!(
            classify_ios("ip route 0.0.0.0 0.0.0.0 10.0.0.1"),
            Section::StaticRoutes
        );
        assert_eq!(classify_ios("line vty 0 4"), Section::Mgmt);
        assert_eq!(classify_ios("snmp-server community x RO"), Section::Mgmt);
        assert_eq!(classify_ios("vlan 10"), Section::Vlans);
        assert_eq!(classify_ios("hostname r1"), Section::System);
        assert_eq!(classify_ios("ip routing"), Section::Other);
    }

    #[test]
    fn junos_sections() {
        assert_eq!(
            classify_junos("interfaces ge-0/0/0 disable"),
            Section::Interfaces
        );
        assert_eq!(
            classify_junos("firewall family inet filter F term T then accept"),
            Section::Acl
        );
        assert_eq!(
            classify_junos("deactivate protocols bgp group G neighbor 1.1.1.1"),
            Section::Bgp
        );
        assert_eq!(
            classify_junos(
                "routing-instances VRF1 routing-options static route 0.0.0.0/0 next-hop 1.1.1.1"
            ),
            Section::StaticRoutes
        );
        assert_eq!(classify_junos("system services ssh"), Section::Mgmt);
        assert_eq!(classify_junos("system host-name r1"), Section::System);
        assert_eq!(
            classify_junos("snmp community public authorization read-only"),
            Section::Mgmt
        );
    }
}

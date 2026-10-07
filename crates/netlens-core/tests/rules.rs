//! Targeted tests: one or more per rule, across vendors.

use netlens_core::{analyze, analyze_single, Finding, Input, Severity, Vendor};

fn run(b: &str, a: &str, v: Vendor) -> Vec<Finding> {
    analyze(
        &Input::Files {
            before: b,
            after: a,
        },
        Some(v),
    )
    .unwrap()
    .findings
}

fn ids(f: &[Finding]) -> Vec<String> {
    f.iter()
        .map(|x| format!("{} {}", x.rule, x.title))
        .collect()
}

fn assert_rule(f: &[Finding], rule: &str) -> Finding {
    f.iter()
        .find(|x| x.rule == rule)
        .cloned()
        .unwrap_or_else(|| panic!("expected {rule}, got {:?}", ids(f)))
}

fn assert_no_rule(f: &[Finding], rule: &str) {
    assert!(
        !f.iter().any(|x| x.rule == rule),
        "unexpected {rule} in {:?}",
        ids(f)
    );
}

const IOS: Vendor = Vendor::CiscoIos;
const EOS: Vendor = Vendor::AristaEos;
const JUN: Vendor = Vendor::Junos;

#[test]
fn if_shutdown_and_enable() {
    let f = run(
        "interface Gi1\n ip address 10.0.0.1 255.255.255.0\n",
        "interface Gi1\n ip address 10.0.0.1 255.255.255.0\n shutdown\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-IF-001");
    assert_eq!(x.evidence[0].line, 3);
    let f = run(
        "interface Gi1\n shutdown\n",
        "interface Gi1\n no shutdown\n",
        IOS,
    );
    assert_rule(&f, "NL-IF-003");
    let f = run(
        "set interfaces ge-0/0/1 description x\n",
        "set interfaces ge-0/0/1 description x\nset interfaces ge-0/0/1 disable\n",
        JUN,
    );
    assert_rule(&f, "NL-IF-001");
}

#[test]
fn if_removed() {
    let f = run(
        "interface Gi1\n ip address 10.0.0.1 255.255.255.0\ninterface Gi2\n description x\n",
        "interface Gi2\n description x\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-IF-002");
    assert!(x.title.contains("Gi1"));
    // Junos: removing a physical interface does not also report each unit.
    let f = run("set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/30\nset interfaces ge-0/0/2 description y\n", "set interfaces ge-0/0/2 description y\n", JUN);
    assert_eq!(
        f.iter().filter(|x| x.rule == "NL-IF-002").count(),
        1,
        "{:?}",
        ids(&f)
    );
}

#[test]
fn mtu_change() {
    let f = run(
        "interface Ethernet1\n   mtu 9214\n",
        "interface Ethernet1\n   mtu 1500\n",
        EOS,
    );
    let x = assert_rule(&f, "NL-IF-004");
    assert!(x.title.contains("9214 -> 1500"));
    assert_eq!(x.severity, Severity::Medium);
}

#[test]
fn address_change() {
    let f = run(
        "interface Gi1\n ip address 10.0.0.1 255.255.255.0\n",
        "interface Gi1\n ip address 10.0.0.9 255.255.255.0\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-IF-005");
    assert!(x.title.contains("changed"));
    assert_eq!(x.evidence.len(), 2);
}

#[test]
fn trunk_vlans() {
    let f = run(
        "interface Gi3\n switchport trunk allowed vlan 10,20,30-32\n",
        "interface Gi3\n switchport trunk allowed vlan 10,30-31\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-IF-006");
    assert!(x.title.contains("20,32"), "{}", x.title);
    let f = run("interface Gi3\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n", "interface Gi3\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n switchport trunk allowed vlan remove 20\n", IOS);
    assert_rule(&f, "NL-IF-006");
    let f = run("interface Gi3\n switchport trunk allowed vlan 10,20\n", "interface Gi3\n switchport trunk allowed vlan 10,20\n switchport trunk allowed vlan add 30\n", IOS);
    assert_no_rule(&f, "NL-IF-006");
}

#[test]
fn vlan_removed() {
    let f = run(
        "vlan 10\n name A\nvlan 20\n name B\n",
        "vlan 10\n name A\n",
        IOS,
    );
    assert_rule(&f, "NL-IF-007");
}

#[test]
fn acl_entry_removed_and_reordered() {
    let b = "ip access-list extended E\n permit tcp any any eq 22\n permit tcp any any eq 443\n deny ip any any\n";
    let f = run(
        b,
        "ip access-list extended E\n permit tcp any any eq 22\n deny ip any any\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-ACL-001");
    assert_eq!(x.evidence[0].line, 3);
    let f = run(b, "ip access-list extended E\n permit tcp any any eq 443\n permit tcp any any eq 22\n deny ip any any\n", IOS);
    assert_rule(&f, "NL-ACL-002");
    assert_no_rule(&f, "NL-ACL-001");
    // Sequence-number renumbering alone is not a change in meaning.
    let f = run(
        "ip access-list E\n   10 permit ip any any\n",
        "ip access-list E\n   20 permit ip any any\n",
        EOS,
    );
    assert_no_rule(&f, "NL-ACL-001");
    assert_no_rule(&f, "NL-ACL-002");
}

#[test]
fn acl_implicit_deny() {
    let b = "ip access-list extended E\n deny ip 10.0.0.0 0.255.255.255 any\n permit ip any any\n";
    let f = run(
        b,
        "ip access-list extended E\n deny ip 10.0.0.0 0.255.255.255 any\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-ACL-003");
    assert_eq!(x.severity, Severity::Critical);
    assert_no_rule(&f, "NL-ACL-001");
    let f = run(
        "ip access-list extended E\n deny ip host 1.1.1.1 any\n",
        "ip access-list extended E\n deny ip host 1.1.1.1 any\n permit ip any any\n",
        IOS,
    );
    assert_rule(&f, "NL-ACL-004");
    let f = run(
        "ip access-list extended E\n permit tcp any any eq 22\n deny ip any any log\n",
        "ip access-list extended E\n permit tcp any any eq 22\n",
        IOS,
    );
    assert_rule(&f, "NL-ACL-008");
}

#[test]
fn acl_applied_but_undefined() {
    let b = "interface Gi1\n ip access-group E in\nip access-list extended E\n permit ip any any\n";
    let f = run(b, "interface Gi1\n ip access-group E in\n", IOS);
    let x = assert_rule(&f, "NL-ACL-005");
    assert!(x.title.contains("not defined"));
    let f = run(
        "interface Gi1\n description x\n",
        "interface Gi1\n description x\n ip access-group NEW in\n",
        IOS,
    );
    assert_rule(&f, "NL-ACL-005");
}

#[test]
fn junos_term_changed_and_unreachable() {
    let b = "set firewall filter F term A from protocol tcp\nset firewall filter F term A then accept\nset firewall filter F term Z then discard\n";
    let f = run(b, "set firewall filter F term A from protocol udp\nset firewall filter F term A then accept\nset firewall filter F term Z then discard\n", JUN);
    assert_rule(&f, "NL-ACL-006");
    let f = run(b, "set firewall filter F term Z then discard\nset firewall filter F term A from protocol tcp\nset firewall filter F term A then accept\n", JUN);
    assert_rule(&f, "NL-ACL-007");
}

#[test]
fn bgp_rules() {
    let b = "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 password 7 AAAA\n neighbor 10.0.0.2 route-map IN in\n neighbor 10.0.0.3 remote-as 65003\nroute-map IN permit 10\nroute-map IN2 permit 10\n";
    let f = run(b, "router bgp 65001\n neighbor 10.0.0.2 remote-as 65009\n neighbor 10.0.0.2 password 7 BBBB\n neighbor 10.0.0.2 route-map IN2 in\nroute-map IN permit 10\nroute-map IN2 permit 10\n", IOS);
    assert_rule(&f, "NL-BGP-001");
    assert_rule(&f, "NL-BGP-003");
    assert_rule(&f, "NL-BGP-004");
    let pw = assert_rule(&f, "NL-BGP-005");
    assert!(!pw.title.contains("BBBB") && !pw.explanation.contains("BBBB"));
    let f = run(b, &b.replace("router bgp 65001", "router bgp 65009"), IOS);
    assert_eq!(assert_rule(&f, "NL-BGP-006").severity, Severity::Critical);
    let f = run(
        "router bgp 1\n neighbor 10.0.0.2 remote-as 2\n",
        "router bgp 1\n neighbor 10.0.0.2 remote-as 2\n neighbor 10.0.0.9 remote-as 9\n",
        IOS,
    );
    assert_rule(&f, "NL-BGP-007");
    let f = run(
        "router bgp 1\n neighbor 10.0.0.2 remote-as 2\n neighbor 10.0.0.2 shutdown\n",
        "router bgp 1\n neighbor 10.0.0.2 remote-as 2\n",
        IOS,
    );
    assert_rule(&f, "NL-BGP-008");
}

#[test]
fn junos_bgp_group_policy_and_peer_as() {
    let b = "set protocols bgp group G peer-as 65002\nset protocols bgp group G import IN\nset protocols bgp group G neighbor 192.0.2.1\nset policy-options policy-statement IN then accept\n";
    let f = run(b, "set protocols bgp group G peer-as 65003\nset protocols bgp group G neighbor 192.0.2.1\nset policy-options policy-statement IN then accept\n", JUN);
    assert_rule(&f, "NL-BGP-003");
    assert_rule(&f, "NL-BGP-004");
    assert_rule(&f, "NL-REF-002");
}

#[test]
fn ospf_rules() {
    let b = "interface Gi1\n ip ospf 1 area 0\n ip ospf cost 10\ninterface Gi2\n ip ospf 1 area 0\nrouter ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n passive-interface Gi9\n";
    let a = "interface Gi1\n ip ospf 1 area 1\n ip ospf cost 100\ninterface Gi2\n description no-ospf\nrouter ospf 1\n passive-interface Gi9\n passive-interface Gi1\n";
    let f = run(b, a, IOS);
    assert_rule(&f, "NL-OSPF-001");
    assert_rule(&f, "NL-OSPF-002");
    assert_rule(&f, "NL-OSPF-003");
    assert_rule(&f, "NL-OSPF-004");
    let f = run(
        "router ospf 1\n passive-interface default\n no passive-interface Gi2\n",
        "router ospf 1\n passive-interface default\n",
        IOS,
    );
    let x = assert_rule(&f, "NL-OSPF-003");
    assert!(x.title.contains("Gi2"));
}

#[test]
fn static_routes() {
    let b = "ip route 0.0.0.0 0.0.0.0 192.0.2.1\nip route 10.9.0.0 255.255.0.0 10.0.0.254\nip route 10.8.0.0 255.255.0.0 10.0.0.254\n";
    let a = "ip route 10.8.0.0 255.255.0.0 10.0.0.253\n";
    let f = run(b, a, IOS);
    assert_eq!(assert_rule(&f, "NL-RT-002").severity, Severity::Critical);
    assert!(assert_rule(&f, "NL-RT-001").title.contains("10.9.0.0/16"));
    assert_rule(&f, "NL-RT-003");
    let f = run(
        "ip route 0.0.0.0/0 10.0.0.1\n",
        "ip route 0.0.0.0/0 10.0.0.1\n",
        EOS,
    );
    assert!(f.is_empty());
}

#[test]
fn mgmt_plane() {
    let b = "line vty 0 4\n access-class VTY in\n transport input ssh\nip access-list standard VTY\n permit 10.0.0.0 0.255.255.255\nntp server 10.0.0.1\n";
    let a = "line vty 0 4\n transport input ssh telnet\nip access-list standard VTY\n permit 10.0.0.0 0.255.255.255\nntp server 10.0.0.2\nsnmp-server community Xy9 RO\n";
    let f = run(b, a, IOS);
    let x = assert_rule(&f, "NL-MGMT-001");
    assert!(x.title.contains("VTY"));
    assert_rule(&f, "NL-MGMT-002");
    assert_rule(&f, "NL-MGMT-003");
    let f = run(
        "set system services ssh\n",
        "set system services telnet\n",
        JUN,
    );
    assert_rule(&f, "NL-MGMT-001");
}

#[test]
fn dangling_and_unused_refs() {
    let b = "route-map A permit 10\n match ip address prefix-list P\nip prefix-list P seq 5 permit 10.0.0.0/8\nrouter bgp 1\n neighbor 10.0.0.2 route-map A out\n";
    // Delete the prefix-list while route-map A still uses it.
    let a = "route-map A permit 10\n match ip address prefix-list P\nrouter bgp 1\n neighbor 10.0.0.2 route-map A out\n";
    let f = run(b, a, IOS);
    let x = assert_rule(&f, "NL-REF-001");
    assert!(x.title.contains("deleted but still referenced"));
    assert_eq!(x.evidence.len(), 2);
    // Pre-existing dangling refs are info only.
    let f = run(
        "router bgp 1\n neighbor 10.0.0.2 route-map GONE out\n description\n",
        "router bgp 1\n neighbor 10.0.0.2 route-map GONE out\n",
        IOS,
    );
    if let Some(x) = f.iter().find(|x| x.rule == "NL-REF-001") {
        assert_eq!(x.severity, Severity::Info);
    }
    // New unused definition.
    let f = run(
        "hostname r1\n",
        "hostname r1\nip prefix-list NEW seq 5 permit 10.0.0.0/8\n",
        IOS,
    );
    assert_rule(&f, "NL-REF-002");
}

#[test]
fn junos_dangling_filter_and_prefix_list() {
    let b = "set interfaces lo0 unit 0 family inet filter input RE\nset firewall family inet filter RE term A then accept\nset policy-options prefix-list MGMT 10.0.0.0/8\nset firewall family inet filter RE term A from source-prefix-list MGMT\n";
    let a = "set interfaces lo0 unit 0 family inet filter input RE\nset firewall family inet filter RE term A then accept\nset firewall family inet filter RE term A from source-prefix-list MGMT\n";
    let f = run(b, a, JUN);
    let x = assert_rule(&f, "NL-REF-001");
    assert!(x.title.contains("prefix-list MGMT"));
}

#[test]
fn secrets_rules() {
    let f = run(
        "hostname r1\n",
        "hostname r1\nusername bob password 0 hunter2\n",
        IOS,
    );
    assert_rule(&f, "NL-SEC-001");
    let f = run(
        "hostname r1\n",
        "hostname r1\nsnmp-server community private RW\n",
        IOS,
    );
    assert_rule(&f, "NL-SEC-002");
    let f = run(
        "hostname r1\n",
        "hostname r1\nusername bob secret 9 $9$abc$def\n",
        IOS,
    );
    assert_no_rule(&f, "NL-SEC-001");
}

#[test]
fn lint_single_config() {
    let cfg = "interface Gi1\n ip access-group MISSING in\nip access-list extended E\n permit ip any any\n deny tcp any any eq 23\nsnmp-server community public RO\n";
    let (_, det, f) = analyze_single(cfg, None);
    assert!(det.is_some());
    assert_rule(&f, "NL-REF-001");
    assert_rule(&f, "NL-ACL-007");
    assert_rule(&f, "NL-SEC-002");
}

#[test]
fn vendor_override_and_bad_diff() {
    assert!(analyze(&Input::Diff("not a diff"), None).is_err());
    let a = analyze(
        &Input::Files {
            before: "hostname a\n",
            after: "hostname b\n",
        },
        Some(EOS),
    )
    .unwrap();
    assert_eq!(a.vendor, EOS);
    assert!(a.detection.is_none());
}

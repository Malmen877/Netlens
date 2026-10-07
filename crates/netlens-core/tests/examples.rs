//! End-to-end checks of the shipped examples through the public API.

use netlens_core::{analyze, Analysis, Input, Severity, Vendor};
use std::path::PathBuf;

fn ex(p: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(p);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn run(b: &str, a: &str) -> Analysis {
    let (bt, at) = (ex(b), ex(a));
    analyze(
        &Input::Files {
            before: &bt,
            after: &at,
        },
        None,
    )
    .unwrap()
}

fn has(a: &Analysis, rule: &str, title_part: &str) -> bool {
    a.findings
        .iter()
        .any(|f| f.rule == rule && f.title.contains(title_part))
}

#[test]
fn ios_xe_example() {
    let a = run("ios-xe/before.cfg", "ios-xe/after.cfg");
    assert_eq!(a.vendor, Vendor::CiscoIos);
    assert!(a.detection.as_ref().unwrap().confident);
    assert!(has(&a, "NL-ACL-001", "ACL-EDGE-IN"));
    assert!(has(&a, "NL-BGP-002", "198.51.100.1"));
    assert!(has(&a, "NL-BGP-003", "198.51.100.1"));
    assert!(has(&a, "NL-REF-001", "RM-ISP-A-OUT-V2"));
    assert!(has(&a, "NL-REF-002", "RM-ISP-A-OUT"));
    assert!(has(&a, "NL-IF-006", "VLAN(s) 30"));
    assert!(has(&a, "NL-IF-004", "1500 -> 9000"));
    assert!(has(&a, "NL-SEC-002", "SNMP"));
    // Ids are F1..Fn, sorted by severity.
    for (i, f) in a.findings.iter().enumerate() {
        assert_eq!(f.id, format!("F{}", i + 1));
    }
    assert!(a
        .findings
        .windows(2)
        .all(|w| w[0].severity >= w[1].severity));
    // Evidence carries real line numbers.
    let shut = a.findings.iter().find(|f| f.rule == "NL-BGP-002").unwrap();
    assert_eq!(shut.evidence[0].line, 87);
    assert_eq!(shut.evidence[0].text, "neighbor 198.51.100.1 shutdown");
    let rb = a.rollback.text();
    assert!(rb.contains(" no neighbor 198.51.100.1 shutdown"));
    assert!(rb.contains("  neighbor 198.51.100.1 route-map RM-ISP-A-OUT out"));
    assert!(rb.contains(" switchport trunk allowed vlan 10,20,30"));
    assert!(rb.contains("no snmp-server community public RO"));
    assert!(rb.contains(" permit tcp any host 203.0.113.10 eq 443"));
}

#[test]
fn junos_curly_example() {
    let a = run("junos/before.conf", "junos/after.conf");
    assert_eq!(a.vendor, Vendor::Junos);
    assert!(has(&a, "NL-ACL-001", "PROTECT-RE"));
    assert!(has(&a, "NL-BGP-002", "192.0.2.1 deactivated"));
    assert!(has(&a, "NL-REF-001", "ISP-B-OUT-V2"));
    assert!(has(&a, "NL-OSPF-003", "ge-0/0/1.0"));
    let rb = a.rollback.text();
    assert!(rb.contains("activate protocols bgp group ISP-B neighbor 192.0.2.1"));
    assert!(rb.contains(
        "insert firewall family inet filter PROTECT-RE term ALLOW-BGP before term ALLOW-OSPF"
    ));
    assert!(rb.contains("delete protocols bgp group ISP-B export ISP-B-OUT-V2"));
}

#[test]
fn junos_set_example() {
    let a = run("junos-set/before.set", "junos-set/after.set");
    assert!(has(&a, "NL-RT-002", "Default route"));
    assert_eq!(a.findings[0].severity, Severity::Critical);
    assert!(has(&a, "NL-IF-006", "PRINTERS"));
    assert!(has(&a, "NL-IF-003", "ge-0/0/11"));
    assert!(has(&a, "NL-MGMT-003", "NTP"));
    assert!(a
        .rollback
        .text()
        .contains("set routing-options static route 0.0.0.0/0 next-hop 10.20.0.1"));
}

#[test]
fn eos_example() {
    let a = run("eos/before.cfg", "eos/after.cfg");
    assert_eq!(a.vendor, Vendor::AristaEos);
    assert!(has(&a, "NL-ACL-001", "ACL-MGMT"));
    assert!(has(&a, "NL-BGP-002", "10.1.0.2"));
    assert!(has(&a, "NL-REF-001", "RM-CONN-LOOPBACKS"));
    assert!(has(&a, "NL-IF-006", "130"));
    let rb = a.rollback.text();
    // Sequenced EOS ACL is fixed surgically, 3-space indentation.
    assert!(rb.contains("ip access-list ACL-MGMT\n   20 permit udp 10.10.10.0/24 any eq snmp"));
    assert!(!rb.contains("no ip access-list"));
}

#[test]
fn diff_example() {
    let d = ex("change.diff");
    let a = analyze(&Input::Diff(&d), None).unwrap();
    assert!(a.partial);
    assert_eq!(a.vendor, Vendor::CiscoIos);
    assert!(has(&a, "NL-BGP-002", "198.51.100.1"));
    assert!(has(&a, "NL-ACL-001", "ACL-EDGE-IN"));
    assert!(has(&a, "NL-IF-006", "30"));
    assert!(!a.notes.is_empty());
    let rb = a.rollback.text();
    assert!(
        !rb.contains("no ip access-list"),
        "partial ACL must not be replaced:\n{rb}"
    );
    assert_eq!(rb.matches("router bgp 65010").count(), 1, "{rb}");
}

#[test]
fn identical_configs_produce_nothing() {
    let t = ex("ios-xe/before.cfg");
    let a = analyze(
        &Input::Files {
            before: &t,
            after: &t,
        },
        None,
    )
    .unwrap();
    assert!(a.findings.is_empty());
    assert!(a.diff.is_empty());
    assert!(a.rollback.is_empty());
}

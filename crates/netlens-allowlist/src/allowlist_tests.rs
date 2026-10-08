use super::*;
use Exp::*;
use Vendor::{Eos, Ios, Junos};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exp {
    Allow,
    Empty,
    TooLong,
    Control,
    NonAscii,
    Inject,
    Denied,
    Pipe,
    NotAllowed,
}

fn classify(r: &Result<(), Rejection>) -> Exp {
    match r {
        Ok(()) => Allow,
        Err(e) => match e.kind {
            RejectionKind::Empty => Empty,
            RejectionKind::TooLong { .. } => TooLong,
            RejectionKind::ControlChar { .. } => Control,
            RejectionKind::NonAscii { .. } => NonAscii,
            RejectionKind::Injection { .. } => Inject,
            RejectionKind::Denied { .. } => Denied,
            RejectionKind::InvalidPipe { .. } => Pipe,
            RejectionKind::NotAllowed => NotAllowed,
        },
    }
}

fn run_table(cfg: &AllowlistConfig, cases: &[(Vendor, &str, Exp)]) -> usize {
    let mut failures = Vec::new();
    for (vendor, cmd, exp) in cases {
        let got = check(*vendor, cmd, cfg);
        if classify(&got) != *exp {
            failures.push(format!("{vendor} {cmd:?}: expected {exp:?}, got {got:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    cases.len()
}

// ---------------------------------------------------------------------------
// Allowed
// ---------------------------------------------------------------------------

const IOS_ALLOWED: &[(Vendor, &str, Exp)] = &[
    (Ios, "show version", Allow),
    (Ios, "sh ver", Allow),
    (Ios, "show inventory", Allow),
    (Ios, "show clock", Allow),
    (Ios, "show running-config", Allow),
    (Ios, "sh run", Allow),
    (Ios, "sho run", Allow),
    (Ios, "show run", Allow),
    (
        Ios,
        "show running-config interface GigabitEthernet0/0/1",
        Allow,
    ),
    (Ios, "sh run int Gi0/0/1", Allow),
    (Ios, "show running-config | section router bgp", Allow),
    (Ios, "sh run | s router ospf", Allow),
    (Ios, "show startup-config", Allow),
    (Ios, "show interfaces", Allow),
    (Ios, "show interfaces GigabitEthernet0/0/1", Allow),
    (Ios, "show interface GigabitEthernet 0/0/1", Allow),
    (Ios, "sh int gi0/0/1", Allow),
    (Ios, "show interfaces status", Allow),
    (Ios, "show interfaces status err-disabled", Allow),
    (Ios, "show interfaces counters errors", Allow),
    (Ios, "show interfaces description", Allow),
    (Ios, "sh int desc", Allow),
    (Ios, "show interfaces transceiver detail", Allow),
    (Ios, "show interfaces Te1/1/1 transceiver", Allow),
    (Ios, "show ip interface brief", Allow),
    (Ios, "sho ip int br", Allow),
    (Ios, "sh ip int brief | exclude unassigned", Allow),
    (Ios, "show ipv6 interface brief", Allow),
    (Ios, "show ip route", Allow),
    (Ios, "sh ip ro", Allow),
    (Ios, "show ip route vrf CUST-A", Allow),
    (Ios, "show ip route 192.0.2.0", Allow),
    (Ios, "show ip route 192.0.2.0 255.255.255.0", Allow),
    (Ios, "show ip route 192.0.2.0/24 longer-prefixes", Allow),
    (Ios, "show ip route vrf MGMT 198.51.100.7", Allow),
    (Ios, "show ipv6 route 2001:db8::/32", Allow),
    (Ios, "show ip bgp summary", Allow),
    (Ios, "sh ip bgp summ", Allow),
    (Ios, "show bgp ipv4 unicast summary", Allow),
    (Ios, "show ip bgp vpnv4 vrf CUST-A summary", Allow),
    (
        Ios,
        "show bgp vpnv4 unicast vrf CUST-A neighbors 192.0.2.9",
        Allow,
    ),
    (Ios, "show ip bgp neighbors", Allow),
    (Ios, "show ip bgp neighbors 198.51.100.2", Allow),
    (Ios, "sh ip bgp nei 198.51.100.2 received-routes", Allow),
    (
        Ios,
        "show ip bgp neighbors 198.51.100.2 advertised-routes",
        Allow,
    ),
    (Ios, "show ip bgp 203.0.113.0/24", Allow),
    (Ios, "show ip ospf neighbor", Allow),
    (Ios, "sh ip ospf nei detail", Allow),
    (Ios, "show ip ospf interface GigabitEthernet0/0/2", Allow),
    (Ios, "show ip ospf interface brief", Allow),
    (Ios, "show ip ospf database", Allow),
    (Ios, "show ip ospf database router 203.0.113.21", Allow),
    (Ios, "show ip ospf 10 neighbor", Allow),
    (Ios, "show logging", Allow),
    (Ios, "sh log | i BGP", Allow),
    (Ios, "show logging | include %BGP-5-ADJCHANGE", Allow),
    (Ios, "show logging | include BGP|OSPF", Pipe),
    (Ios, "show environment all", Allow),
    (Ios, "show processes cpu sorted", Allow),
    (Ios, "show processes cpu history", Allow),
    (Ios, "sh proc cpu sort | ex 0.00", Allow),
    (Ios, "show cdp neighbors", Allow),
    (Ios, "show cdp neighbors detail", Allow),
    (Ios, "show lldp neighbors Gi1/0/12 detail", Allow),
    (Ios, "show ip arp", Allow),
    (Ios, "show ip arp vrf CUST-A 192.0.2.10", Allow),
    (Ios, "show mac address-table", Allow),
    (Ios, "show mac address-table interface Gi1/0/12", Allow),
    (Ios, "show mac address-table vlan 20", Allow),
    (Ios, "show ip access-lists", Allow),
    (Ios, "show ip access-lists EDGE-IN", Allow),
    (Ios, "show access-lists", Allow),
    (Ios, "show spanning-tree", Allow),
    (Ios, "show spanning-tree interface Gi1/0/12 detail", Allow),
    (Ios, "show spanning-tree vlan 20", Allow),
    (Ios, "show vlan brief", Allow),
    (Ios, "show ntp status", Allow),
    (Ios, "show ntp associations", Allow),
    (Ios, "show errdisable recovery", Allow),
    (Ios, "show etherchannel summary", Allow),
    (Ios, "show standby brief", Allow),
    (Ios, "show bfd neighbors details", Allow),
    (Ios, "show ip bgp summary | count Idle", Allow),
    (Ios, "show run | b router bgp", Allow),
    (
        Ios,
        "show running-config | include ^interface | exclude Loopback",
        Allow,
    ),
];

const EOS_ALLOWED: &[(Vendor, &str, Exp)] = &[
    (Eos, "show version", Allow),
    (Eos, "show interfaces status", Allow),
    (Eos, "show interfaces status errdisabled", Allow),
    (Eos, "show interfaces counters errors", Allow),
    (Eos, "show interfaces Ethernet47", Allow),
    (Eos, "show interfaces Ethernet47 transceiver", Allow),
    (Eos, "show interfaces Ethernet49/1 counters errors", Allow),
    (Eos, "sh int et47 | i CRC", Allow),
    (Eos, "show ip bgp summary", Allow),
    (Eos, "show ip bgp summary vrf PROD", Allow),
    (Eos, "show ip bgp neighbors 192.0.2.0", Allow),
    (Eos, "show bgp evpn summary", Allow),
    (Eos, "show ip bgp summary | json", Allow),
    (Eos, "show interfaces counters errors | json", Allow),
    (Eos, "show lldp neighbors", Allow),
    (Eos, "show lldp neighbors detail", Allow),
    (Eos, "show ip route", Allow),
    (Eos, "show ip route vrf PROD 203.0.113.0/24", Allow),
    (Eos, "show logging", Allow),
    (Eos, "show logging last 30 minutes", Allow),
    (Eos, "show logging | include BGP", Allow),
    (Eos, "show running-config", Allow),
    (Eos, "show running-config section router bgp", Allow),
    (Eos, "show running-config interfaces Ethernet47", Allow),
    (Eos, "show port-channel summary", Allow),
    (Eos, "show mlag", Allow),
    (Eos, "show mac address-table", Allow),
    (Eos, "show arp", Allow),
    (Eos, "show ip arp", Allow),
    (Eos, "show ip ospf neighbor", Allow),
    (Eos, "show processes top once", Allow),
    (Eos, "show interfaces | no-more", Allow),
];

const JUNOS_ALLOWED: &[(Vendor, &str, Exp)] = &[
    (Junos, "show version", Allow),
    (Junos, "show interfaces terse", Allow),
    (Junos, "show interfaces terse xe-0/1/2", Allow),
    (Junos, "show interfaces xe-0/1/2 extensive", Allow),
    (Junos, "show interfaces ge-0/0/0.0 terse", Allow),
    (Junos, "show interfaces descriptions", Allow),
    (
        Junos,
        "show interfaces diagnostics optics et-0/0/1:2",
        Allow,
    ),
    (Junos, "sh int ter", Allow),
    (Junos, "show route", Allow),
    (Junos, "show route table inet.0", Allow),
    (Junos, "show route protocol bgp", Allow),
    (Junos, "show route 203.0.113.0/24 exact", Allow),
    (Junos, "show route receive-protocol bgp 203.0.113.9", Allow),
    (
        Junos,
        "show route advertising-protocol bgp 203.0.113.9",
        Allow,
    ),
    (Junos, "show bgp summary", Allow),
    (Junos, "show bgp neighbor 203.0.113.9", Allow),
    (Junos, "show bgp neighbor", Allow),
    (Junos, "show ospf neighbor", Allow),
    (Junos, "show ospf database", Allow),
    (Junos, "show ospf interface ge-0/0/1.0 extensive", Allow),
    (Junos, "show log messages", Allow),
    (Junos, "show log messages | match BGP | last 50", Allow),
    (
        Junos,
        "show log messages | match \"tcp_auth|bgp_hold\"",
        Allow,
    ),
    (Junos, "show log messages | match tcp_auth | count", Allow),
    (Junos, "show log messages | except LLDP | last", Allow),
    (Junos, "show configuration", Allow),
    (Junos, "show configuration | display set", Allow),
    (
        Junos,
        "show configuration protocols bgp | display set",
        Allow,
    ),
    (
        Junos,
        "show configuration protocols bgp group CUST-EBGP",
        Allow,
    ),
    (Junos, "show configuration | display set | match bgp", Allow),
    (
        Junos,
        "show configuration interfaces | display inheritance no-comments",
        Allow,
    ),
    (Junos, "show bgp summary | display xml", Allow),
    (Junos, "show bgp summary | display json", Allow),
    (Junos, "show chassis hardware", Allow),
    (Junos, "show chassis environment", Allow),
    (Junos, "show chassis alarms", Allow),
    (Junos, "show lldp neighbors", Allow),
    (Junos, "show arp no-resolve", Allow),
    (Junos, "show ethernet-switching table", Allow),
    (Junos, "show firewall", Allow),
    (Junos, "show system processes extensive", Allow),
    (Junos, "show system uptime", Allow),
    (Junos, "show system commit", Allow),
    (Junos, "show ntp associations", Allow),
    (Junos, "show interfaces | find ge-0/0/3", Allow),
    (Junos, "show interfaces | no-more", Allow),
    (Junos, "show route | trim 5", Allow),
];

// ---------------------------------------------------------------------------
// Denylist: verbs, abbreviations, case, tokens
// ---------------------------------------------------------------------------

const DENIED: &[(Vendor, &str, Exp)] = &[
    // Every IOS/EOS denylist verb.
    (Ios, "configure terminal", Denied),
    (Ios, "conf t", Denied),
    (Ios, "config t", Denied),
    (Ios, "confi t", Denied),
    (Ios, "co t", Denied),
    (Ios, "c t", Denied),
    (Ios, "CoNf T", Denied),
    (Ios, "CONFIGURE TERMINAL", Denied),
    (Ios, "configure replace flash:base.cfg force", Denied),
    (Ios, "write memory", Denied),
    (Ios, "wr mem", Denied),
    (Ios, "wr", Denied),
    (Ios, "write erase", Denied),
    (Ios, "copy running-config startup-config", Denied),
    (Ios, "copy run start", Denied),
    (Ios, "cop run start", Denied),
    (Ios, "copy tftp://192.0.2.5/x running-config", Denied),
    (Ios, "reload", Denied),
    (Ios, "rel", Denied),
    (Ios, "reload in 5", Denied),
    (Ios, "delete flash:config.text", Denied),
    (Ios, "del /force flash:x", Denied),
    (Ios, "erase startup-config", Denied),
    (Ios, "format flash:", Denied),
    (Ios, "squeeze flash:", Denied),
    (Ios, "clear ip bgp *", Denied),
    (Ios, "clear ip bgp 198.51.100.2", Denied),
    (Ios, "cl counters", Denied),
    (Ios, "clear counters", Denied),
    (Ios, "debug ip bgp", Denied),
    (Ios, "deb all", Denied),
    (Ios, "undebug all", Denied),
    (Ios, "u all", Denied),
    (Ios, "no debug all", Denied),
    (Ios, "terminal length 0", Denied),
    (Ios, "term mon", Denied),
    (Ios, "telnet 192.0.2.1", Denied),
    (Ios, "ssh -l admin 192.0.2.1", Denied),
    (Ios, "tclsh", Denied),
    (Ios, "archive download-sw tftp://x", Denied),
    (Ios, "monitor capture CAP start", Denied),
    (Ios, "enable", Denied),
    (Ios, "en", Denied),
    (Ios, "ping 192.0.2.1", Denied),
    (Ios, "ping 192.0.2.1 repeat 100000 size 18000", Denied),
    (Ios, "traceroute 192.0.2.1", Denied),
    (Ios, "tr 192.0.2.1", Denied),
    (
        Ios,
        "install add file bootflash:x.bin activate commit",
        Denied,
    ),
    (Ios, "verify /md5 flash:x", Denied),
    (Ios, "send *", Denied),
    (Eos, "bash timeout 10 rm -rf /mnt/flash", Denied),
    (Eos, "ba", Denied),
    (Eos, "configure session", Denied),
    (Eos, "write", Denied),
    (Eos, "reload now", Denied),
    (Eos, "clear ip bgp neighbor 192.0.2.0", Denied),
    (Eos, "copy running-config startup-config", Denied),
    (Eos, "delete flash:startup-config", Denied),
    // Junos.
    (Junos, "request system reboot", Denied),
    (Junos, "request system zeroize", Denied),
    (Junos, "req sys reb", Denied),
    (Junos, "set cli screen-length 0", Denied),
    (
        Junos,
        "set protocols bgp group X neighbor 192.0.2.1",
        Denied,
    ),
    (Junos, "edit", Denied),
    (Junos, "ed", Denied),
    (Junos, "configure", Denied),
    (Junos, "configure exclusive", Denied),
    (Junos, "commit", Denied),
    (Junos, "commit confirmed 5", Denied),
    (Junos, "com", Denied),
    (Junos, "rollback 1", Denied),
    (Junos, "roll 1", Denied),
    (Junos, "start shell", Denied),
    (Junos, "start shell sh", Denied),
    (Junos, "file delete /var/log/messages", Denied),
    (Junos, "file copy /config/juniper.conf.gz /tmp/x", Denied),
    (Junos, "clear bgp neighbor 203.0.113.9", Denied),
    (Junos, "restart routing", Denied),
    (Junos, "test configuration", Denied),
    (Junos, "monitor traffic interface xe-0/1/2", Denied),
    (Junos, "monitor interface xe-0/1/2", Denied),
    (Junos, "op url http://203.0.113.50/x.slax", Denied),
    (Junos, "load override terminal", Denied),
    (Junos, "save /var/tmp/x", Denied),
    (Junos, "ping 203.0.113.9 rapid count 100000", Denied),
    (Junos, "traceroute 203.0.113.9", Denied),
    (Junos, "ssh 203.0.113.9", Denied),
    (Junos, "telnet 203.0.113.9", Denied),
    (Junos, "s", Denied),
    // Denied tokens inside a show command.
    (Ios, "show run start", Denied),
    (
        Junos,
        "show configuration | display set | save /var/tmp/x",
        Denied,
    ),
    (Ios, "show version copy", Denied),
    (Junos, "show bgp summary set", Denied),
    (Eos, "show ip route bash", Denied),
];

// ---------------------------------------------------------------------------
// Pipes
// ---------------------------------------------------------------------------

const PIPES: &[(Vendor, &str, Exp)] = &[
    (Ios, "show run | redirect flash:x", Denied),
    (Ios, "show run | red flash:x", Denied),
    (Ios, "show run | r flash:x", Denied),
    (Ios, "show run | tee flash:x", Denied),
    (Ios, "show run | t flash:x", Denied),
    (Ios, "show run | append flash:x", Denied),
    (Ios, "show run | a flash:x", Denied),
    (Ios, "show run | format flash:spec.xml", Denied),
    (Ios, "show run | f flash:spec.xml", Denied),
    (Ios, "show run | save flash:x", Denied),
    (Ios, "show run | exec reload", Denied),
    (Ios, "show log | i x | redirect flash:x", Denied),
    (Ios, "show log | i x | REDIRECT flash:x", Denied),
    (Ios, "show run|redirect flash:x", Denied),
    (Ios, "show run | utility egrep x", Pipe),
    (Ios, "show run | json", Pipe),
    (Ios, "show run |", Pipe),
    (Ios, "show run | | include x", Pipe),
    (Ios, "| include x", Pipe),
    (Ios, "show run | include", Pipe),
    (Ios, "show run | include \"x|redirect flash:x\"", Denied),
    (Eos, "show run | redirect flash:x", Denied),
    (Eos, "show run | tee flash:x", Denied),
    (Eos, "show run | append flash:x", Denied),
    (Eos, "show run | json extra", Pipe),
    (Eos, "show run | grep bgp", Pipe),
    (Eos, "show run | awk '{system(\"reboot\")}'", Pipe),
    (Junos, "show configuration | save /var/tmp/x", Denied),
    (Junos, "show configuration | s /var/tmp/x", Denied),
    (Junos, "show configuration | append /var/tmp/x", Denied),
    (Junos, "show configuration | tee /var/tmp/x", Denied),
    (Junos, "show configuration | request system reboot", Denied),
    (Junos, "show interfaces | refresh 1", Denied),
    (Junos, "show interfaces | hold", Denied),
    (Junos, "show configuration | compare rollback 1", Pipe),
    (Junos, "show configuration | display", Pipe),
    (Junos, "show configuration | display set foo", Pipe),
    (Junos, "show configuration | display commit-scripts", Pipe),
    (Junos, "show log messages | last 50 60", Pipe),
    (Junos, "show log messages | last x", Pipe),
    (Junos, "show log messages | count 5", Pipe),
    (Junos, "show log messages | match \"unbalanced", Inject),
    (Junos, "show log messages | match \"a\\\"b\"", Inject),
    (
        Junos,
        "show log messages | match \"x\" | save /var/tmp/x",
        Denied,
    ),
    (Junos, "show log messages | include x", Pipe),
    (Junos, "show log messages | match a|save", Denied),
];

// ---------------------------------------------------------------------------
// Injection, whitespace, characters, length
// ---------------------------------------------------------------------------

const CHARS: &[(Vendor, &str, Exp)] = &[
    // Newline / CR / tab / control.
    (Ios, "show ver\nconf t", Control),
    (Ios, "show ver\r\nreload", Control),
    (Ios, "show ver\rreload", Control),
    (Ios, "show\tversion", Control),
    (Ios, "show version\n", Control),
    (Ios, "show ver\u{0}", Control),
    (Ios, "show ver\u{1b}[2J", Control),
    (Ios, "show ver\u{7f}", Control),
    (Ios, "show ver\u{1a}", Control),
    (Ios, "show ver\u{85}conf t", Control),
    (Ios, "show ver\u{2028}reload", Control),
    (Ios, "show ver\u{2029}reload", Control),
    (Ios, "con\u{200b}f t", Control),
    (Ios, "sh\u{200d}ow run", Control),
    (Ios, "show run\u{202e}", Control),
    (Ios, "show run\u{2066}x\u{2069}", Control),
    (Ios, "\u{feff}show run", Control),
    (Ios, "show run\u{ad}", Control),
    // Unicode lookalikes.
    (Ios, "sh\u{043e}w run", NonAscii), // Cyrillic o
    (Ios, "\u{0441}onf t", NonAscii),   // Cyrillic es
    (Ios, "\u{ff53}\u{ff48}\u{ff4f}\u{ff57} run", NonAscii), // fullwidth "show"
    (Ios, "show\u{a0}run", NonAscii),   // NBSP
    (Ios, "show\u{3000}run", NonAscii), // ideographic space
    (Ios, "show run \u{ff5c} redirect flash:x", NonAscii), // fullwidth pipe
    (Junos, "show bgp summ\u{0430}ry", NonAscii),
    (Eos, "show ver\u{ff1b} reload", NonAscii), // fullwidth semicolon
    // Shell metacharacters.
    (Ios, "show ver; reload", Inject),
    (Ios, "show ver ;reload", Inject),
    (Ios, "show ver && reload", Inject),
    (Ios, "show ver & reload", Inject),
    (Ios, "show ver || reload", Inject),
    (Ios, "show run > flash:x", Inject),
    (Ios, "show run >> flash:x", Inject),
    (Ios, "show run < flash:x", Inject),
    (Ios, "show `reload`", Inject),
    (Ios, "show $(reload)", Inject),
    (Ios, "show ${IFS}run", Inject),
    (Ios, "show ?", Inject),
    (Eos, "show running-config > flash:x", Inject),
    (Junos, "show configuration > /var/tmp/x", Inject),
    (Junos, "show bgp summary; request system reboot", Inject),
    // Whitespace normalization.
    (Ios, "   show   ip   route   ", Allow),
    (Ios, "show  run", Allow),
    (Ios, " sh run ", Allow),
    (Ios, "show run  |  include  hostname", Allow),
    (Junos, "  show   bgp   summary  ", Allow),
    // Case.
    (Ios, "SHOW RUN", Allow),
    (Ios, "Show Ip Bgp Summary", Allow),
    (Ios, "SH IP INT BR | I up", Allow),
    (Junos, "SHOW BGP SUMMARY", Allow),
    (Junos, "SHOW CONFIGURATION | DISPLAY SET", Allow),
    (Junos, "REQUEST SYSTEM REBOOT", Denied),
    // Empty.
    (Ios, "", Empty),
    (Ios, "    ", Empty),
    (Junos, "", Empty),
    // Not allowed (safe but not on the list, or not a show command).
    (Ios, "show tech-support", NotAllowed),
    (Ios, "show", NotAllowed),
    (Ios, "dir flash:", NotAllowed),
    (Ios, "more flash:config.text", NotAllowed),
    (Ios, "exit", NotAllowed),
    (Ios, "showx run", NotAllowed),
    (Ios, "show run extra-garbage words", NotAllowed),
    (Junos, "show security policies", NotAllowed),
    (Junos, "help topic bgp", NotAllowed),
    (Eos, "show tech-support", NotAllowed),
];

#[test]
fn ios_allowed() {
    run_table(&AllowlistConfig::default(), IOS_ALLOWED);
}

#[test]
fn eos_allowed() {
    run_table(&AllowlistConfig::default(), EOS_ALLOWED);
}

#[test]
fn junos_allowed() {
    run_table(&AllowlistConfig::default(), JUNOS_ALLOWED);
}

#[test]
fn denylist() {
    run_table(&AllowlistConfig::default(), DENIED);
}

#[test]
fn pipes() {
    run_table(&AllowlistConfig::default(), PIPES);
}

#[test]
fn characters_injection_whitespace() {
    run_table(&AllowlistConfig::default(), CHARS);
}

#[test]
fn every_deny_verb_is_denied_on_every_vendor() {
    let cfg = AllowlistConfig::default();
    for v in Vendor::ALL {
        for verb in DENY_VERBS {
            for cmd in [
                verb.to_string(),
                format!("{verb} x"),
                verb.to_ascii_uppercase(),
            ] {
                let r = check(v, &cmd, &cfg);
                assert!(
                    matches!(
                        &r,
                        Err(Rejection {
                            kind: RejectionKind::Denied { .. },
                            ..
                        })
                    ),
                    "{v} {cmd:?} -> {r:?}"
                );
            }
        }
        for tok in DENY_TOKENS {
            let cmd = format!("show ip route {tok}");
            let r = check(v, &cmd, &cfg);
            assert!(
                matches!(
                    &r,
                    Err(Rejection {
                        kind: RejectionKind::Denied { .. },
                        ..
                    })
                ),
                "{v} {cmd:?} -> {r:?}"
            );
        }
        for p in DENY_PIPES {
            let cmd = format!("show version | {p} x");
            let r = check(v, &cmd, &cfg);
            assert!(
                matches!(
                    &r,
                    Err(Rejection {
                        kind: RejectionKind::Denied { .. },
                        ..
                    })
                ),
                "{v} {cmd:?} -> {r:?}"
            );
        }
    }
}

#[test]
fn every_prefix_of_dangerous_verbs_is_denied() {
    // Any abbreviation of a dangerous verb (that is not sh/sho) is denied.
    let cfg = AllowlistConfig::default();
    for verb in [
        "configure",
        "write",
        "copy",
        "reload",
        "delete",
        "clear",
        "debug",
        "request",
        "edit",
        "commit",
        "rollback",
        "erase",
        "format",
    ] {
        for n in 1..=verb.len() {
            let p = &verb[..n];
            for v in Vendor::ALL {
                let r = check(v, &format!("{p} x"), &cfg);
                assert!(
                    matches!(
                        &r,
                        Err(Rejection {
                            kind: RejectionKind::Denied { .. },
                            ..
                        })
                    ),
                    "{v} {p:?} -> {r:?}"
                );
            }
        }
    }
}

#[test]
fn safe_filter_aliases_never_spell_a_denied_filter() {
    for v in Vendor::ALL {
        for f in filters(v) {
            assert!(!DENY_PIPES.contains(&f.name), "{v} {}", f.name);
        }
    }
    for t in DENY_TOKENS {
        assert!(DENY_VERBS.contains(t), "{t} should also be a deny verb");
    }
}

#[test]
fn rejection_details() {
    let cfg = AllowlistConfig::default();
    let e = check(Ios, "conf t", &cfg).unwrap_err();
    assert_eq!(
        e.kind,
        RejectionKind::Denied {
            rule: "configure".into()
        }
    );
    assert_eq!(e.command, "conf t");
    assert!(e.to_string().contains("configure"), "{e}");

    let e = check(Ios, "show run | red flash:x", &cfg).unwrap_err();
    assert_eq!(
        e.kind,
        RejectionKind::Denied {
            rule: "| redirect".into()
        }
    );

    let e = check(Ios, "show ver\nconf t", &cfg).unwrap_err();
    assert_eq!(e.kind, RejectionKind::ControlChar { ch: '\n', pos: 8 });
    // Display escapes control characters.
    assert!(e.to_string().contains("\\n"), "{e}");
    assert!(!e.to_string().contains('\n'));

    let e = check(Ios, "sh\u{043e}w", &cfg).unwrap_err();
    assert_eq!(
        e.kind,
        RejectionKind::NonAscii {
            ch: '\u{043e}',
            pos: 2
        }
    );

    let e = check(Ios, "show ver; reload", &cfg).unwrap_err();
    assert_eq!(e.kind, RejectionKind::Injection { token: ";".into() });

    let e = check(Ios, &format!("show {}", "a".repeat(300)), &cfg).unwrap_err();
    assert_eq!(
        e.kind,
        RejectionKind::TooLong {
            len: 305,
            max: MAX_COMMAND_LEN
        }
    );
    let _: &dyn std::error::Error = &e;
}

#[test]
fn length_limits() {
    let cfg = AllowlistConfig::default();
    let pad = MAX_COMMAND_LEN - "show version".len();
    let at_limit = format!("show version{}", " ".repeat(pad));
    assert_eq!(at_limit.len(), MAX_COMMAND_LEN);
    assert!(check(Ios, &at_limit, &cfg).is_ok());
    let over = format!("{at_limit} ");
    assert!(matches!(
        check(Ios, &over, &cfg).unwrap_err().kind,
        RejectionKind::TooLong { .. }
    ));
    // Over-length beats every other check.
    let over_ctrl = format!("conf t\n{}", "x".repeat(300));
    assert!(matches!(
        check(Ios, &over_ctrl, &cfg).unwrap_err().kind,
        RejectionKind::TooLong { .. }
    ));
    // Multi-byte input is measured in bytes.
    let wide = "\u{ff53}".repeat(90);
    assert!(matches!(
        check(Ios, &wide, &cfg).unwrap_err().kind,
        RejectionKind::TooLong { .. }
    ));
}

#[test]
fn vet_returns_normalized_command_in_original_case() {
    let cfg = AllowlistConfig::default();
    let v = vet(Ios, "  sh   run  int   Gi0/0/1 ", &cfg).unwrap();
    assert_eq!(v.command, "sh run int Gi0/0/1");
    assert_eq!(v.canonical, "show running-config interface gi0/0/1");
    let v = vet(Junos, "show log messages | match \"Last error\"", &cfg).unwrap();
    assert_eq!(v.command, "show log messages | match \"Last error\"");
    assert_eq!(v.canonical, "show log messages");
}

// ---------------------------------------------------------------------------
// User config
// ---------------------------------------------------------------------------

#[test]
fn user_config_extends_allowlist() {
    let base = AllowlistConfig::default();
    assert!(check(
        Ios,
        "show platform hardware qfp active statistics drop",
        &base
    )
    .is_err());
    let cfg = AllowlistConfig::from_toml_str(
        r#"
        [ios]
        allow = ['show platform hardware qfp active statistics drop( clear)?', 'SHOW TECH-SUPPORT']
        [junos]
        allow = ['show security policies( hit-count)?']
        "#,
    )
    .unwrap();
    assert!(check(
        Ios,
        "show platform hardware qfp active statistics drop",
        &cfg
    )
    .is_ok());
    assert!(check(Ios, "show tech-support", &cfg).is_ok());
    assert!(check(Junos, "show security policies hit-count", &cfg).is_ok());
    // Not for other vendors.
    assert!(check(Eos, "show tech-support", &cfg).is_err());
    // Defaults still present.
    assert!(check(Ios, "show ip bgp summary", &cfg).is_ok());
    assert_eq!(cfg.patterns(Ios).len(), base.patterns(Ios).len() + 2);
    // The user's `( clear)?` matched as a show argument still hits DENY_TOKENS.
    assert!(matches!(
        check(
            Ios,
            "show platform hardware qfp active statistics drop clear",
            &cfg
        )
        .unwrap_err()
        .kind,
        RejectionKind::Denied { .. }
    ));
}

#[test]
fn user_patterns_are_anchored() {
    let cfg = AllowlistConfig::from_toml_str("[ios]\nallow = ['show foo']\n").unwrap();
    assert!(check(Ios, "show foo", &cfg).is_ok());
    assert!(check(Ios, "show foo bar", &cfg).is_err());
    assert!(check(Ios, "show xshow foo", &cfg).is_err());
    // Author-supplied anchors are harmless.
    let cfg = AllowlistConfig::from_toml_str("[ios]\nallow = ['^show bar$']\n").unwrap();
    assert!(check(Ios, "show bar", &cfg).is_ok());
    // Alternation cannot escape the anchors.
    let cfg = AllowlistConfig::from_toml_str("[ios]\nallow = ['show baz|x']\n").unwrap();
    assert!(check(Ios, "show baz", &cfg).is_ok());
    assert!(check(Ios, "show baz extra", &cfg).is_err());
}

#[test]
fn user_config_cannot_allow_denied_commands() {
    let cfg = AllowlistConfig::from_toml_str(
        r#"
        [ios]
        allow = ['^.*$', '^reload$', 'conf.*', 'copy .*', 'write( mem)?']
        [junos]
        allow = ['.*', 'request system reboot', 'start shell']
        [eos]
        allow = ['.*']
        "#,
    )
    .unwrap();
    let cases: &[(Vendor, &str, Exp)] = &[
        (Ios, "reload", Denied),
        (Ios, "conf t", Denied),
        (Ios, "configure terminal", Denied),
        (Ios, "copy run start", Denied),
        (Ios, "write mem", Denied),
        (Ios, "wr", Denied),
        (Ios, "clear ip bgp *", Denied),
        (Ios, "show run | redirect flash:x", Denied),
        (Ios, "show run | tee flash:x", Denied),
        (Ios, "show ver; reload", Inject),
        (Ios, "show ver\nreload", Control),
        (Ios, "ping 192.0.2.1", Denied),
        (Ios, "dir flash:", NotAllowed),   // show gate still applies
        (Ios, "show tech-support", Allow), // '.*' widens show commands only
        (Junos, "request system reboot", Denied),
        (Junos, "start shell", Denied),
        (Junos, "show configuration | save /tmp/x", Denied),
        (Junos, "show anything at all", Allow),
        (Eos, "bash rm -rf /", Denied),
        (Eos, "show ip route bash", Denied),
    ];
    run_table(&cfg, cases);
}

#[test]
fn user_config_deny_keys_are_rejected() {
    for doc in [
        "deny = ['show .*']",
        "denylist = []",
        "[deny]\nios = ['reload']",
        "[ios]\ndeny = []",
        "[ios]\ndenylist = ['configure']",
        "[ios]\nremove_deny = ['reload']",
        "[ios]\nallow_all = true",
        "[junos]\ndisable_denylist = true",
        "[eos]\noverride = true",
    ] {
        let e = AllowlistConfig::from_toml_str(doc).unwrap_err();
        assert!(
            matches!(e, ConfigError::DenylistNotConfigurable { .. }),
            "{doc:?} -> {e:?}"
        );
        assert!(e.to_string().contains("denylist"), "{e}");
    }
}

#[test]
fn user_config_errors() {
    let e = AllowlistConfig::from_toml_str("[ios]\nallow = ['show (unclosed']\n").unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::InvalidPattern {
                vendor: Vendor::Ios,
                ..
            }
        ),
        "{e:?}"
    );
    let e = AllowlistConfig::from_toml_str("[ios]\nallow = ['show {BOGUS}']\n").unwrap_err();
    assert!(matches!(e, ConfigError::InvalidPattern { .. }), "{e:?}");
    let e = AllowlistConfig::from_toml_str("[nxos]\nallow = []\n").unwrap_err();
    assert!(matches!(e, ConfigError::UnknownKey { .. }), "{e:?}");
    let e = AllowlistConfig::from_toml_str("[ios]\npatterns = []\n").unwrap_err();
    assert!(matches!(e, ConfigError::UnknownKey { .. }), "{e:?}");
    let e = AllowlistConfig::from_toml_str("[ios]\nallow = 'show x'\n").unwrap_err();
    assert!(matches!(e, ConfigError::InvalidType { .. }), "{e:?}");
    let e = AllowlistConfig::from_toml_str("[ios]\nallow = [1]\n").unwrap_err();
    assert!(matches!(e, ConfigError::InvalidType { .. }), "{e:?}");
    let e = AllowlistConfig::from_toml_str("ios = 1\n").unwrap_err();
    assert!(matches!(e, ConfigError::InvalidType { .. }), "{e:?}");
    let e = AllowlistConfig::from_toml_str("this is not toml").unwrap_err();
    assert!(matches!(e, ConfigError::Parse(_)), "{e:?}");
    // A failed extend leaves the config unchanged.
    let mut cfg = AllowlistConfig::default();
    let before = cfg.patterns(Ios).len();
    assert!(cfg
        .extend_from_toml_str("[ios]\nallow = ['ok', '(bad']\n")
        .is_err());
    assert_eq!(cfg.patterns(Ios).len(), before);
    // Empty user config is fine.
    assert!(AllowlistConfig::from_toml_str("").is_ok());
}

#[test]
fn defaults_compile_and_are_nonempty() {
    let cfg = AllowlistConfig::default();
    for v in Vendor::ALL {
        assert!(cfg.patterns(v).len() >= 15, "{v}");
    }
}

#[test]
fn default_patterns_never_allow_denylisted_words() {
    // Belt and braces: no default pattern literally contains a deny token as
    // a whole word, so the defaults never rely on the denylist to stay safe.
    for v in Vendor::ALL {
        for p in AllowlistConfig::default().patterns(v) {
            for w in p.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
                assert!(
                    !DENY_TOKENS.contains(&w),
                    "{v} pattern {p:?} contains {w:?}"
                );
            }
        }
    }
}

#[test]
fn vendor_parse_display_serde() {
    for (s, v) in [
        ("ios", Ios),
        ("IOS-XE", Ios),
        ("iosxe", Ios),
        ("cisco_ios", Ios),
        ("junos", Junos),
        ("Juniper", Junos),
        ("eos", Eos),
        ("arista_eos", Eos),
    ] {
        assert_eq!(s.parse::<Vendor>().unwrap(), v, "{s}");
    }
    assert!("nxos".parse::<Vendor>().is_err());
    for v in Vendor::ALL {
        assert_eq!(v.to_string().parse::<Vendor>().unwrap(), v);
    }
    #[derive(Deserialize, Serialize)]
    struct W {
        v: Vendor,
    }
    let w: W = toml::from_str("v = 'ios-xe'").unwrap();
    assert_eq!(w.v, Ios);
    let w: W = toml::from_str("v = 'junos'").unwrap();
    assert_eq!(w.v, Junos);
    assert_eq!(
        toml::to_string(&W { v: Eos }).unwrap().trim(),
        "v = \"eos\""
    );
}

#[test]
fn table_size() {
    // Keep the suite honest about its size.
    let n = IOS_ALLOWED.len()
        + EOS_ALLOWED.len()
        + JUNOS_ALLOWED.len()
        + DENIED.len()
        + PIPES.len()
        + CHARS.len();
    assert!(n >= 300, "only {n} table cases");
}

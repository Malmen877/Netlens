//! Deterministic rollback generation: invert the change per vendor.
//!
//! IOS/EOS: walk both indentation trees, negate added lines (`no ...`),
//! re-add removed lines/blocks, and treat "overwrite" commands (mtu,
//! description, remote-as, route-map per direction, ...) as a single
//! re-apply. ACLs are fixed surgically when entries carry sequence numbers,
//! otherwise replaced as a whole. Junos: `delete` what was added (collapsed
//! to the new object), `set` what was removed, `insert` to restore term order.

use crate::facts::extract;
use crate::model::{junos_display, Config, Node};
use crate::parse::junos_tokens;
use crate::section::{classify_ios, Section};
use crate::vendor::Vendor;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize)]
pub struct Rollback {
    pub vendor: Vendor,
    /// Config lines to paste (comments use the vendor's comment char).
    pub lines: Vec<String>,
    /// Caveats a human should read before applying.
    pub notes: Vec<String>,
}

impl Rollback {
    pub fn is_empty(&self) -> bool {
        !self.lines.iter().any(|l| !is_comment(l))
    }
    pub fn text(&self) -> String {
        let mut s = self.lines.join("\n");
        s.push('\n');
        s
    }
}

fn is_comment(l: &str) -> bool {
    let t = l.trim_start();
    t.starts_with('!') || t.starts_with('#')
}

pub fn generate(before: &Config, after: &Config) -> Rollback {
    match after.vendor {
        Vendor::Junos => junos(before, after),
        v => ios_like(before, after, v),
    }
}

// ------------------------------------------------------------- IOS/EOS ----

static RE_OVERWRITE: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let pats: &[(&str, &str)] = &[
        (r"^(description) ", "$1"),
        (
            r"^(mtu|ip mtu|ipv6 mtu|bandwidth|speed|duplex|load-interval|delay|hostname) ",
            "$1",
        ),
        (
            r"^(ip ospf cost|ip ospf hello-interval|ip ospf dead-interval|ip ospf network|ip ospf priority) ",
            "$1",
        ),
        (r"^(ip ospf)(?: \d+)? area ", "$1 area"),
        (
            r"^(switchport access vlan|switchport trunk native vlan|switchport mode|encapsulation dot1q|vrf forwarding|vrf) ",
            "$1",
        ),
        (r"^(switchport trunk allowed vlan) (?:\d|all|none)", "$1"),
        (r"^(ip address) \S+(?: \S+)?$", "$1"),
        (
            r"^((?:ip|ipv6) (?:access-group|traffic-filter)) \S+ (in|out)$",
            "$1 * $2",
        ),
        (r"^(access-class) \S+ (in|out)", "$1 * $2"),
        (
            r"^(transport input|transport output|exec-timeout|session-timeout) ",
            "$1",
        ),
        (r"^(router-id|bgp router-id|ospf router-id) ", "$1"),
        (
            r"^(neighbor \S+ (?:remote-as|description|password|update-source|ebgp-multihop|timers|local-as|maximum-prefix|maximum-routes|peer-group|peer group|send-community|next-hop-self|weight|allowas-in)) ?",
            "$1",
        ),
        (
            r"^(neighbor \S+ (?:route-map|prefix-list|filter-list|distribute-list)) \S+ (in|out)$",
            "$1 * $2",
        ),
        (
            r"^(enable secret|enable password|snmp-server location|snmp-server contact|ip domain name|ip domain-name|clock timezone|logging buffered) ",
            "$1",
        ),
        (r"^(username \S+) ", "$1"),
    ];
    pats.iter()
        .map(|(p, k)| (Regex::new(p).expect("valid regex"), *k))
        .collect()
});

/// Key identifying commands that overwrite each other ("mtu 1500" vs "mtu 9000").
pub fn overwrite_key(text: &str) -> Option<String> {
    for (re, rep) in RE_OVERWRITE.iter() {
        if let Some(c) = re.captures(text) {
            let mut out = String::new();
            c.expand(rep, &mut out);
            return Some(out);
        }
    }
    None
}

pub fn negate(text: &str) -> String {
    if let Some(rest) = text.strip_prefix("no ") {
        return rest.to_string();
    }
    if let Some(rest) = text.strip_prefix("banner ") {
        if let Some(kind) = rest.split(' ').next() {
            return format!("no banner {kind}");
        }
    }
    format!("no {text}")
}

fn render_subtree(n: &Node, depth: usize, unit: &str, out: &mut Vec<String>) {
    out.push(format!("{}{}", unit.repeat(depth), n.text));
    for c in &n.children {
        render_subtree(c, depth + 1, unit, out);
    }
}

fn match_by_text<'a>(
    b: &'a [Node],
    a: &'a [Node],
) -> (Vec<(&'a Node, &'a Node)>, Vec<&'a Node>, Vec<&'a Node>) {
    let mut amap: HashMap<&str, Vec<&Node>> = HashMap::new();
    for n in a {
        amap.entry(n.text.as_str()).or_default().push(n);
    }
    for v in amap.values_mut() {
        v.reverse();
    }
    let mut common = Vec::new();
    let mut removed = Vec::new();
    for n in b {
        match amap.get_mut(n.text.as_str()).and_then(|v| v.pop()) {
            Some(m) => common.push((n, m)),
            None => removed.push(n),
        }
    }
    let matched: BTreeSet<*const Node> = common.iter().map(|(_, m)| *m as *const Node).collect();
    let added = a
        .iter()
        .filter(|n| !matched.contains(&(*n as *const Node)))
        .collect();
    (common, removed, added)
}

fn is_named_acl(header: &str) -> bool {
    header.starts_with("ip access-list ")
        || header.starts_with("ipv6 access-list ")
        || header.starts_with("mac access-list ")
}

fn starts_with_seq(t: &str) -> bool {
    t.split(' ')
        .next()
        .map(|w| w.parse::<u64>().is_ok())
        .unwrap_or(false)
}

struct Gen<'a> {
    unit: &'a str,
    notes: Vec<String>,
    partial: bool,
}

impl Gen<'_> {
    /// Lines that turn `a` children back into `b` children (depth = indent).
    fn children(&mut self, header: &str, b: &[Node], a: &[Node], depth: usize) -> Vec<String> {
        let (common, removed, added) = match_by_text(b, a);
        let mut out = Vec::new();
        // Overwrite pairs: re-applying the old line is enough.
        let mut paired: BTreeSet<*const Node> = BTreeSet::new();
        for ad in &added {
            if let Some(k) = overwrite_key(&ad.text) {
                if removed
                    .iter()
                    .any(|r| overwrite_key(&r.text).as_deref() == Some(k.as_str()))
                {
                    paired.insert(*ad as *const Node);
                }
            }
        }
        let _ = header;
        for ad in &added {
            if paired.contains(&(*ad as *const Node)) {
                continue;
            }
            out.push(format!("{}{}", self.unit.repeat(depth), negate(&ad.text)));
        }
        for (bn, an) in &common {
            let inner = self.children(&bn.text, &bn.children, &an.children, depth + 1);
            if !inner.is_empty() {
                out.push(format!("{}{}", self.unit.repeat(depth), bn.text));
                out.extend(inner);
            }
        }
        for r in &removed {
            render_subtree(r, depth, self.unit, &mut out);
        }
        out
    }

    fn named_acl(&mut self, bn: &Node, an: &Node, pre: &mut Vec<String>, main: &mut Vec<String>) {
        let entries = |n: &Node| -> Vec<String> {
            n.children
                .iter()
                .map(|c| c.text.clone())
                .filter(|t| {
                    !t.starts_with("remark")
                        && !t.starts_with("statistics")
                        && !t.starts_with("counters")
                })
                .collect()
        };
        let (be, ae) = (entries(bn), entries(an));
        if be == ae && bn.children == an.children {
            return;
        }
        let all_seq = be.iter().chain(ae.iter()).all(|t| starts_with_seq(t));
        if all_seq {
            let inner = self.children(&bn.text, &bn.children, &an.children, 1);
            // For sequenced entries negate by sequence number only.
            let inner: Vec<String> = inner
                .into_iter()
                .map(|l| {
                    let t = l.trim_start();
                    if let Some(rest) = t.strip_prefix("no ") {
                        if let Some(seq) =
                            rest.split(' ').next().filter(|w| w.parse::<u64>().is_ok())
                        {
                            return format!("{}no {seq}", self.unit);
                        }
                    }
                    l
                })
                .collect();
            if !inner.is_empty() {
                main.push(bn.text.clone());
                main.extend(inner);
            }
        } else if self.partial {
            // A diff fragment does not contain the whole ACL: never replace it.
            let (_, removed, added) = match_by_text(&bn.children, &an.children);
            main.push(bn.text.clone());
            for ad in &added {
                main.push(format!("{}{}", self.unit, negate(&ad.text)));
            }
            if !removed.is_empty() {
                main.push(format!(
                    "{}! removed entries cannot be re-inserted at the right position without sequence numbers; restore manually:",
                    self.unit
                ));
                for r in &removed {
                    main.push(format!("{}!   {}", self.unit, r.text));
                }
            }
            self.notes.push(format!(
                "'{}' has no sequence numbers and the input is a diff, so removed entries are listed as comments instead of being re-added; use full before/after files for a pasteable ACL rollback",
                bn.text
            ));
        } else {
            self.notes.push(format!(
                "'{}' has no sequence numbers, so the rollback replaces it as a whole; while it is being re-entered the interface briefly filters with an empty ACL (permit-all on IOS). Apply in a maintenance window or add sequence numbers.",
                bn.text
            ));
            pre.push(negate(&bn.text));
            render_subtree(bn, 0, self.unit, pre);
        }
    }
}

fn is_policy_object(text: &str) -> bool {
    matches!(classify_ios(text), Section::Acl | Section::RoutePolicy)
}

fn ios_like(before: &Config, after: &Config, vendor: Vendor) -> Rollback {
    let unit = if vendor == Vendor::AristaEos {
        "   "
    } else {
        " "
    };
    let partial = before.partial || after.partial;
    let mut g = Gen {
        unit,
        notes: Vec::new(),
        partial,
    };
    let mut pre: Vec<String> = Vec::new();
    let mut main: Vec<String> = Vec::new();
    let mut post: Vec<String> = Vec::new();

    // Numbered ACLs are sets of top-level lines; compare per number.
    let numbered = |nodes: &[Node]| -> BTreeMap<String, Vec<String>> {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for n in nodes {
            if let Some(rest) = n.text.strip_prefix("access-list ") {
                if let Some(num) = rest.split(' ').next() {
                    m.entry(num.to_string()).or_default().push(n.text.clone());
                }
            }
        }
        m
    };
    let (bnum, anum) = (numbered(&before.tree), numbered(&after.tree));
    for (num, blines) in &bnum {
        if anum.get(num) != Some(blines) && partial {
            pre.push(format!("! access-list {num} changed; 'no access-list {num} ...' would delete the whole list, so restore it manually from the full config:"));
            for l in blines {
                pre.push(format!("!   {l}"));
            }
            g.notes.push(format!(
                "numbered access-list {num} cannot be rolled back safely from a diff"
            ));
            continue;
        }
        if anum.get(num) != Some(blines) {
            pre.push(format!("no access-list {num}"));
            pre.extend(blines.iter().cloned());
            g.notes.push(format!(
                "numbered access-list {num} is replaced as a whole; apply where a brief permit-all window is acceptable"
            ));
        }
    }
    for num in anum.keys() {
        if !bnum.contains_key(num) && !partial {
            post.push(format!("no access-list {num}"));
        }
    }
    let not_numbered = |n: &&Node| !n.text.starts_with("access-list ");
    let b_top: Vec<Node> = before.tree.iter().filter(not_numbered).cloned().collect();
    let a_top: Vec<Node> = after.tree.iter().filter(not_numbered).cloned().collect();
    let (common, removed, added) = match_by_text(&b_top, &a_top);

    // Overwrite pairs at top level (hostname, enable secret, username X ...).
    let mut paired: BTreeSet<*const Node> = BTreeSet::new();
    for ad in &added {
        if let Some(k) = overwrite_key(&ad.text) {
            if removed
                .iter()
                .any(|r| overwrite_key(&r.text).as_deref() == Some(k.as_str()))
            {
                paired.insert(*ad as *const Node);
            }
        }
    }
    for (bn, an) in &common {
        if is_named_acl(&bn.text) {
            g.named_acl(bn, an, &mut pre, &mut main);
            continue;
        }
        let inner = g.children(&bn.text, &bn.children, &an.children, 1);
        if !inner.is_empty() {
            main.push(bn.text.clone());
            main.extend(inner);
        }
    }
    for r in &removed {
        let target = if is_policy_object(&r.text) {
            &mut pre
        } else {
            &mut main
        };
        render_subtree(r, 0, unit, target);
    }
    for ad in &added {
        if paired.contains(&(*ad as *const Node)) {
            continue;
        }
        let neg = negate(&ad.text);
        if is_policy_object(&ad.text) {
            post.push(neg);
        } else {
            if ad.text.starts_with("interface ")
                && !ad.text.contains('.')
                && !ad.text.to_ascii_lowercase().contains("loopback")
                && !ad.text.to_ascii_lowercase().contains("vlan")
                && !ad.text.to_ascii_lowercase().contains("tunnel")
                && !ad.text.to_ascii_lowercase().contains("port-channel")
            {
                g.notes.push(format!(
                    "'{}' was added; physical interfaces cannot be deleted, so use 'default {}' instead of 'no {}' if needed",
                    ad.text, ad.text, ad.text
                ));
            }
            main.push(neg);
        }
    }

    let mut lines = Vec::new();
    if pre.is_empty() && main.is_empty() && post.is_empty() {
        return Rollback {
            vendor,
            lines,
            notes: vec!["no configuration changes to roll back".into()],
        };
    }
    lines.push(format!(
        "! netlens rollback ({}) - generated deterministically; review before applying",
        vendor.as_str()
    ));
    match vendor {
        Vendor::AristaEos => lines.push("! tip: paste inside 'configure session' + 'commit timer 00:05:00', or use 'configure replace flash:<before>'".into()),
        _ => lines.push("! tip: 'configure replace flash:<before.cfg> list' restores the exact prior config on IOS-XE".into()),
    }
    lines.extend(pre);
    lines.extend(main);
    lines.extend(post);
    lines.push("end".into());
    Rollback {
        vendor,
        lines,
        notes: g.notes,
    }
}

// --------------------------------------------------------------- Junos ----

const BOUNDARY: &[&str] = &[
    "term",
    "policy-statement",
    "prefix-list",
    "neighbor",
    "group",
    "unit",
    "filter",
    "route",
    "community",
    "as-path",
    "vlans",
    "interface",
];

const SINGLE_VALUED: &[&str] = &[
    "description",
    "mtu",
    "peer-as",
    "local-as",
    "autonomous-system",
    "metric",
    "preference",
    "router-id",
    "vlan-id",
    "host-name",
    "authentication-key",
    "hold-time",
    "local-address",
    "type",
    "interface-mode",
    "encrypted-password",
    "encapsulation",
    "speed",
    "native-vlan-id",
    "cost",
    "domain-name",
    "time-zone",
];

fn toks(s: &str) -> Vec<String> {
    junos_tokens(s)
}

fn single_value_key(t: &[String]) -> Option<String> {
    if t.len() >= 2 && SINGLE_VALUED.contains(&t[t.len() - 2].as_str()) {
        Some(t[..t.len() - 1].join(" "))
    } else {
        None
    }
}

fn junos(before: &Config, after: &Config) -> Rollback {
    let (removed, added) = crate::diff::raw_diff(before, after);
    let mut notes = Vec::new();
    if removed.is_empty() && added.is_empty() {
        return Rollback {
            vendor: Vendor::Junos,
            lines: Vec::new(),
            notes: vec!["no configuration changes to roll back".into()],
        };
    }
    let before_toks: Vec<Vec<String>> = before.stmts.iter().map(|s| toks(s.text())).collect();
    let removed_keys: BTreeSet<String> = removed
        .iter()
        .filter_map(|s| single_value_key(&toks(s.text())))
        .collect();

    let mut deletes: Vec<String> = Vec::new();
    let mut activates: Vec<String> = Vec::new();
    for s in &added {
        let text = s.text();
        if let Some(rest) = text.strip_prefix("deactivate ") {
            activates.push(format!("activate {rest}"));
            continue;
        }
        let t = toks(text);
        if let Some(k) = single_value_key(&t) {
            if removed_keys.contains(&k) {
                continue; // overwritten by the `set` below
            }
            deletes.push(format!("delete {k}"));
            continue;
        }
        // Collapse to the shortest new object prefix.
        let mut target = t.join(" ");
        for i in 0..t.len() {
            if BOUNDARY.contains(&t[i].as_str()) && i + 1 < t.len() {
                let prefix = &t[..=i + 1];
                let exists = before_toks
                    .iter()
                    .any(|bt| bt.len() >= prefix.len() && bt[..prefix.len()] == *prefix);
                if !exists {
                    target = prefix.join(" ");
                    break;
                }
            }
        }
        deletes.push(format!("delete {target}"));
    }
    // Dedupe and drop deletes covered by a shorter delete.
    deletes.sort();
    deletes.dedup();
    let covered: Vec<String> = deletes.clone();
    deletes.retain(|d| {
        !covered
            .iter()
            .any(|c| c != d && d.starts_with(&format!("{c} ")))
    });

    let mut sets: Vec<String> = Vec::new();
    let mut deactivates: Vec<String> = Vec::new();
    for s in &removed {
        let text = s.text();
        if text.starts_with("deactivate ") {
            deactivates.push(text.to_string());
        } else {
            sets.push(junos_display(text));
        }
    }

    // Restore filter term order.
    let (bf, af) = (extract(before), extract(after));
    let mut inserts = Vec::new();
    for (fname, bacl) in &bf.acls {
        let Some(aacl) = af.acls.get(fname) else {
            continue;
        };
        let border: Vec<&str> = bacl.entries.iter().map(|e| e.key.as_str()).collect();
        let aorder: Vec<&str> = aacl.entries.iter().map(|e| e.key.as_str()).collect();
        let aset: BTreeSet<&str> = aorder.iter().copied().collect();
        let prefix = before.stmts.iter().find_map(|s| {
            let t = s.text();
            let needle = format!(" filter {fname} term ");
            t.find(&needle)
                .map(|p| t[..p + needle.len() - " term ".len()].to_string())
        });
        let Some(prefix) = prefix else { continue };
        let common_b: Vec<&str> = border
            .iter()
            .copied()
            .filter(|t| aset.contains(t))
            .collect();
        let bset: BTreeSet<&str> = border.iter().copied().collect();
        let common_a: Vec<&str> = aorder
            .iter()
            .copied()
            .filter(|t| bset.contains(t))
            .collect();
        if common_b != common_a {
            for w in border.windows(2).rev() {
                inserts.push(format!(
                    "insert {prefix} term {} before term {}",
                    w[0], w[1]
                ));
            }
            continue;
        }
        for (i, t) in border.iter().enumerate() {
            if aset.contains(t) {
                continue;
            }
            if let Some(next) = border[i + 1..].iter().find(|n| aset.contains(*n)) {
                inserts.push(format!("insert {prefix} term {t} before term {next}"));
            }
        }
    }

    let mut lines = vec![
        "# netlens rollback (junos) - generated deterministically; review before applying"
            .to_string(),
        "# load with 'load set terminal', check 'show | compare', then 'commit confirmed 5'"
            .to_string(),
    ];
    lines.extend(deletes);
    lines.extend(activates);
    lines.extend(sets);
    lines.extend(deactivates);
    lines.extend(inserts);
    if after.partial {
        notes.push(
            "built from diff hunks: Junos paths are only as complete as the diff context".into(),
        );
    }
    Rollback {
        vendor: Vendor::Junos,
        lines,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn rb(b: &str, a: &str, v: Vendor) -> Rollback {
        generate(&parse(b, v), &parse(a, v))
    }

    fn body(r: &Rollback) -> Vec<String> {
        r.lines.iter().filter(|l| !is_comment(l)).cloned().collect()
    }

    #[test]
    fn negation() {
        assert_eq!(negate("shutdown"), "no shutdown");
        assert_eq!(negate("no ip redirects"), "ip redirects");
        assert_eq!(negate("banner motd ^C"), "no banner motd");
    }

    #[test]
    fn overwrite_keys() {
        assert_eq!(overwrite_key("mtu 9000").as_deref(), Some("mtu"));
        assert_eq!(
            overwrite_key("neighbor 10.0.0.2 route-map A out").as_deref(),
            Some("neighbor 10.0.0.2 route-map * out")
        );
        assert_eq!(
            overwrite_key("neighbor 10.0.0.2 remote-as 65002").as_deref(),
            Some("neighbor 10.0.0.2 remote-as")
        );
        assert_eq!(
            overwrite_key("switchport trunk allowed vlan 10,20").as_deref(),
            Some("switchport trunk allowed vlan")
        );
        assert_eq!(overwrite_key("switchport trunk allowed vlan add 30"), None);
        assert_eq!(
            overwrite_key("ip address 10.0.0.1 255.255.255.0").as_deref(),
            Some("ip address")
        );
        assert_eq!(
            overwrite_key("ip address 10.0.0.1 255.255.255.0 secondary"),
            None
        );
        assert_eq!(overwrite_key("neighbor 10.0.0.2 shutdown"), None);
    }

    #[test]
    fn ios_interface_and_bgp() {
        let b = "interface Gi1\n mtu 1500\n description wan\nrouter bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 route-map RM-OUT out\n";
        let a = "interface Gi1\n mtu 9000\n description wan\n shutdown\nrouter bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 route-map RM-NEW out\n neighbor 10.0.0.2 shutdown\n";
        let r = rb(b, a, Vendor::CiscoIos);
        assert_eq!(
            body(&r),
            vec![
                "interface Gi1",
                " no shutdown",
                " mtu 1500",
                "router bgp 65001",
                " no neighbor 10.0.0.2 shutdown",
                " neighbor 10.0.0.2 route-map RM-OUT out",
                "end",
            ]
        );
    }

    #[test]
    fn ios_removed_block_and_added_policy_object() {
        let b = "route-map RM permit 10\n match ip address prefix-list PL\ninterface Gi2\n ip address 10.1.1.1 255.255.255.0\n";
        let a = "interface Gi2\n ip address 10.1.1.1 255.255.255.0\nip prefix-list NEW seq 5 permit 10.0.0.0/8\n";
        let r = rb(b, a, Vendor::CiscoIos);
        let lines = body(&r);
        assert_eq!(lines[0], "route-map RM permit 10");
        assert_eq!(lines[1], " match ip address prefix-list PL");
        assert_eq!(lines[2], "no ip prefix-list NEW seq 5 permit 10.0.0.0/8");
    }

    #[test]
    fn ios_named_acl_without_seq_is_replaced() {
        let b = "ip access-list extended EDGE\n permit tcp any any eq 22\n permit tcp any any eq 443\n deny ip any any\n";
        let a = "ip access-list extended EDGE\n permit tcp any any eq 22\n deny ip any any\n";
        let r = rb(b, a, Vendor::CiscoIos);
        let lines = body(&r);
        assert_eq!(lines[0], "no ip access-list extended EDGE");
        assert_eq!(lines[1], "ip access-list extended EDGE");
        assert_eq!(lines.len(), 6);
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn eos_acl_with_seq_is_surgical() {
        let b = "ip access-list EDGE\n   10 permit tcp any any eq ssh\n   20 permit tcp any any eq https\n   30 deny ip any any\n";
        let a = "ip access-list EDGE\n   10 permit tcp any any eq ssh\n   25 permit udp any any eq ntp\n   30 deny ip any any\n";
        let r = rb(b, a, Vendor::AristaEos);
        assert_eq!(
            body(&r),
            vec![
                "ip access-list EDGE",
                "   no 25",
                "   20 permit tcp any any eq https",
                "end"
            ]
        );
        assert!(r.notes.is_empty());
    }

    #[test]
    fn partial_acl_is_never_replaced() {
        let d = "--- a/r1.cfg\n+++ b/r1.cfg\n@@ -20,3 +20,2 @@ ip access-list extended EDGE\n  permit tcp any any eq 22\n- permit tcp any any eq 443\n  permit tcp any any eq 80\n";
        let ud = crate::unidiff::parse_unified(d).unwrap();
        let (b, a) = crate::unidiff::to_configs(&ud, Vendor::CiscoIos);
        let r = generate(&b, &a);
        assert!(
            !r.lines.iter().any(|l| l.starts_with("no ip access-list")),
            "{:?}",
            r.lines
        );
        assert!(
            r.lines
                .iter()
                .any(|l| l.contains("!   permit tcp any any eq 443")),
            "{:?}",
            r.lines
        );
    }

    #[test]
    fn numbered_acl() {
        let b = "access-list 10 permit 10.0.0.0 0.0.0.255\naccess-list 10 deny any\n";
        let a = "access-list 10 deny any\n";
        let lines = body(&rb(b, a, Vendor::CiscoIos));
        assert_eq!(lines[0], "no access-list 10");
        assert_eq!(lines[1], "access-list 10 permit 10.0.0.0 0.0.0.255");
    }

    #[test]
    fn no_changes() {
        let r = rb("hostname r1\n", "hostname r1\n", Vendor::CiscoIos);
        assert!(r.is_empty());
    }

    #[test]
    fn junos_inverts_and_collapses() {
        let b = "set interfaces ge-0/0/0 mtu 1500\nset firewall family inet filter F term A from protocol tcp\nset firewall family inet filter F term A then accept\nset firewall family inet filter F term B then accept\nset firewall family inet filter F term Z then discard\nset protocols bgp group G neighbor 10.0.0.2\n";
        let a = "set interfaces ge-0/0/0 mtu 9000\nset firewall family inet filter F term B then accept\nset firewall family inet filter F term N from port 22\nset firewall family inet filter F term N then accept\nset firewall family inet filter F term Z then discard\nset protocols bgp group G neighbor 10.0.0.2\ndeactivate protocols bgp group G neighbor 10.0.0.2\nset interfaces ge-0/0/1 disable\n";
        let r = rb(b, a, Vendor::Junos);
        let lines = body(&r);
        assert!(
            lines.contains(&"delete firewall family inet filter F term N".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"delete interfaces ge-0/0/1 disable".to_string()),
            "{lines:?}"
        );
        assert!(lines.contains(&"activate protocols bgp group G neighbor 10.0.0.2".to_string()));
        assert!(lines.contains(&"set interfaces ge-0/0/0 mtu 1500".to_string()));
        assert!(!lines
            .iter()
            .any(|l| l.starts_with("delete interfaces ge-0/0/0 mtu")));
        assert!(lines
            .contains(&"set firewall family inet filter F term A from protocol tcp".to_string()));
        assert!(
            lines
                .contains(&"insert firewall family inet filter F term A before term B".to_string()),
            "{lines:?}"
        );
    }
}

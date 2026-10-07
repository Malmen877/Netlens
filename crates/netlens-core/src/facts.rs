//! Vendor-neutral facts extracted from a parsed config: interfaces, ACLs,
//! BGP peers, OSPF membership, static routes, VLANs and the reference graph
//! (who uses which route-map/prefix-list/ACL). Rules compare before/after facts.

use crate::model::{junos_display, Config, Node};
use crate::parse::junos_tokens;
use crate::vendor::Vendor;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

/// A quoted source line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Loc {
    pub line: usize,
    pub text: String,
}

impl Loc {
    pub fn new(line: usize, text: impl Into<String>) -> Self {
        Loc {
            line,
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefKind {
    Acl,
    RoutePolicy,
    PrefixList,
    CommunityList,
    AsPath,
    ClassMap,
    PolicyMap,
}

impl RefKind {
    pub fn name(&self, vendor: Vendor) -> &'static str {
        let junos = vendor == Vendor::Junos;
        match self {
            RefKind::Acl if junos => "firewall filter",
            RefKind::Acl => "access-list",
            RefKind::RoutePolicy if junos => "policy-statement",
            RefKind::RoutePolicy => "route-map",
            RefKind::PrefixList => "prefix-list",
            RefKind::CommunityList if junos => "community",
            RefKind::CommunityList => "community-list",
            RefKind::AsPath if junos => "as-path",
            RefKind::AsPath => "as-path access-list",
            RefKind::ClassMap => "class-map",
            RefKind::PolicyMap => "policy-map",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ref {
    pub kind: RefKind,
    pub name: String,
    pub loc: Loc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VlanSet {
    All,
    Some(BTreeSet<String>),
}

#[derive(Debug, Clone, Serialize)]
pub struct AclBinding {
    pub name: String,
    pub dir: String,
    pub loc: Loc,
}

#[derive(Debug, Clone, Serialize)]
pub struct Interface {
    pub name: String,
    pub loc: Loc,
    pub shutdown: Option<Loc>,
    pub mtu: BTreeMap<String, (String, Loc)>,
    pub addresses: Vec<(String, Loc)>,
    pub acls: Vec<AclBinding>,
    pub trunk_allowed: Option<(VlanSet, Vec<Loc>)>,
    pub is_trunk: bool,
}

impl Interface {
    fn new(name: &str, loc: Loc) -> Self {
        Interface {
            name: name.to_string(),
            loc,
            shutdown: None,
            mtu: BTreeMap::new(),
            addresses: Vec::new(),
            acls: Vec::new(),
            trunk_allowed: None,
            is_trunk: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Permit,
    Deny,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct AclEntry {
    /// Identity used for matching across before/after: entry text without
    /// sequence number (IOS/EOS) or the term name (Junos).
    pub key: String,
    /// Full content (equals key for IOS/EOS; all term lines for Junos).
    pub content: String,
    pub action: Action,
    pub catch_all: bool,
    pub seq: Option<u64>,
    pub loc: Loc,
}

#[derive(Debug, Clone, Serialize)]
pub struct Acl {
    pub name: String,
    pub loc: Loc,
    pub entries: Vec<AclEntry>,
    /// Header line (IOS named ACL) used by rollback.
    pub header: String,
    pub numbered: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyRef {
    pub kind: RefKind,
    pub name: String,
    pub dir: String,
    pub loc: Loc,
}

#[derive(Debug, Clone, Serialize)]
pub struct BgpPeer {
    /// Address, IOS peer-group name, or "group NAME" (Junos).
    pub key: String,
    pub is_group: bool,
    pub loc: Loc,
    pub remote_as: Option<(String, Loc)>,
    pub shutdown: Option<Loc>,
    pub policies: Vec<PolicyRef>,
    pub password: Option<(String, Loc)>,
    pub group: Option<String>,
}

impl BgpPeer {
    fn new(key: &str, loc: Loc) -> Self {
        BgpPeer {
            key: key.to_string(),
            is_group: false,
            loc,
            remote_as: None,
            shutdown: None,
            policies: Vec::new(),
            password: None,
            group: None,
        }
    }

    /// "shut down" (IOS/EOS) or "deactivated" (Junos `deactivate`).
    pub fn shut_verb(&self) -> &'static str {
        if self
            .shutdown
            .as_ref()
            .map(|l| l.text.starts_with("deactivate "))
            .unwrap_or(false)
        {
            "deactivated"
        } else {
            "shut down"
        }
    }

    pub fn label(&self) -> String {
        if self.key.starts_with("group ") {
            format!("BGP {}", self.key)
        } else if self.is_group {
            format!("BGP peer-group {}", self.key)
        } else {
            format!("BGP neighbor {}", self.key)
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Bgp {
    pub asn: Option<(String, Loc)>,
    pub peers: BTreeMap<String, BgpPeer>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Ospf {
    /// IOS/EOS `network` statements keyed "<pid>: network ... area N".
    pub networks: BTreeMap<String, Loc>,
    /// Interface -> area (IOS `ip ospf N area A`, Junos `area A interface IF`).
    pub iface_area: BTreeMap<String, (String, Loc)>,
    pub passive: BTreeMap<String, Loc>,
    pub no_passive: BTreeMap<String, Loc>,
    pub passive_default: Option<Loc>,
    pub cost: BTreeMap<String, (String, Loc)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StaticRoute {
    pub vrf: String,
    pub prefix: String,
    pub next_hop: String,
    pub default: bool,
    pub loc: Loc,
}

impl StaticRoute {
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.vrf, self.prefix, self.next_hop)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Facts {
    pub vendor: Vendor,
    pub interfaces: BTreeMap<String, Interface>,
    pub acls: BTreeMap<String, Acl>,
    pub bgp: Bgp,
    pub ospf: Ospf,
    pub statics: Vec<StaticRoute>,
    pub vlans: BTreeMap<String, Loc>,
    pub defs: BTreeMap<(RefKind, String), Loc>,
    pub refs: Vec<Ref>,
}

impl Facts {
    fn new(vendor: Vendor) -> Self {
        Facts {
            vendor,
            interfaces: BTreeMap::new(),
            acls: BTreeMap::new(),
            bgp: Bgp::default(),
            ospf: Ospf::default(),
            statics: Vec::new(),
            vlans: BTreeMap::new(),
            defs: BTreeMap::new(),
            refs: Vec::new(),
        }
    }

    fn def(&mut self, kind: RefKind, name: &str, loc: Loc) {
        self.defs.entry((kind, name.to_string())).or_insert(loc);
    }

    fn reference(&mut self, kind: RefKind, name: &str, loc: Loc) {
        let name = name.trim_matches('"');
        if name.is_empty() {
            return;
        }
        self.refs.push(Ref {
            kind,
            name: name.to_string(),
            loc,
        });
    }

    pub fn is_defined(&self, kind: RefKind, name: &str) -> bool {
        self.defs.contains_key(&(kind, name.to_string()))
    }

    pub fn refs_to(&self, kind: RefKind, name: &str) -> Vec<&Ref> {
        self.refs
            .iter()
            .filter(|r| r.kind == kind && r.name == name)
            .collect()
    }
}

pub fn extract(cfg: &Config) -> Facts {
    match cfg.vendor {
        Vendor::Junos => extract_junos(cfg),
        _ => extract_ios(cfg),
    }
}

// ------------------------------------------------------------ helpers ----

/// Dotted mask -> prefix length (None if not a contiguous mask).
pub fn mask_len(mask: &str) -> Option<u32> {
    let ip: std::net::Ipv4Addr = mask.parse().ok()?;
    let v = u32::from(ip);
    let len = v.leading_ones();
    if v.checked_shl(len).unwrap_or(0) == 0 {
        Some(len)
    } else {
        None
    }
}

/// Expand "10,20,30-32" into a set of VLAN ids (as strings).
pub fn parse_vlan_list(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                if a <= b && b - a <= 4094 {
                    for v in a..=b {
                        out.insert(v.to_string());
                    }
                    continue;
                }
            }
        }
        out.insert(part.to_string());
    }
    out
}

/// Compress a VLAN set for display: "10,20,30-32".
pub fn format_vlans(set: &BTreeSet<String>) -> String {
    let mut nums: Vec<u32> = set.iter().filter_map(|s| s.parse().ok()).collect();
    nums.sort_unstable();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < nums.len() {
        let start = nums[i];
        let mut end = start;
        while i + 1 < nums.len() && nums[i + 1] == end + 1 {
            i += 1;
            end = nums[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    for s in set {
        if s.parse::<u32>().is_err() {
            parts.push(s.clone());
        }
    }
    parts.join(",")
}

fn all_vlans() -> BTreeSet<String> {
    (1..=4094u32).map(|v| v.to_string()).collect()
}

fn ios_catch_all(content: &str) -> bool {
    let c = content
        .trim_end_matches(" log-input")
        .trim_end_matches(" log");
    matches!(
        c,
        "permit ip any any"
            | "deny ip any any"
            | "permit ipv6 any any"
            | "deny ipv6 any any"
            | "permit any"
            | "deny any"
            | "permit any any"
            | "deny any any"
            | "permit ip 0.0.0.0/0 0.0.0.0/0"
            | "deny ip 0.0.0.0/0 0.0.0.0/0"
    )
}

fn action_of(content: &str) -> Action {
    if content.starts_with("permit") {
        Action::Permit
    } else if content.starts_with("deny") {
        Action::Deny
    } else {
        Action::Other
    }
}

/// Split "10 permit ip any any" into (Some(10), "permit ip any any").
fn split_seq(t: &str) -> (Option<u64>, String) {
    if let Some((first, rest)) = t.split_once(' ') {
        if let Ok(n) = first.parse::<u64>() {
            return (Some(n), rest.to_string());
        }
    }
    (None, t.to_string())
}

// ------------------------------------------------------------ IOS/EOS ----

static RE_ROUTE_MAP_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)route-map (\S+)").unwrap());
static RE_MATCH_PL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^match ipv?6? ?address prefix-list (.+)$").unwrap());
static RE_MATCH_ACL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^match ipv?6? ?address (?:access-list )?(.+)$").unwrap());
static RE_NEIGH_PL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)prefix-list (\S+) (?:in|out)$").unwrap());
static RE_DIST_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"distribute-list prefix(?:-list)? (\S+)").unwrap());
static RE_DIST_ACL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"distribute-list (\S+) (?:in|out)").unwrap());
static RE_ACCESS_GROUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:ip|ipv6) (?:access-group|traffic-filter) (\S+)(?: (in|out))?").unwrap()
});
static RE_ACCESS_CLASS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:ipv6 )?access-class (\S+)").unwrap());
static RE_SERVICE_POLICY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^service-policy(?: type \S+)?(?: input| output)? (\S+)$").unwrap()
});
static RE_FILTER_LIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)filter-list (\S+)").unwrap());

fn extract_ios(cfg: &Config) -> Facts {
    let mut f = Facts::new(cfg.vendor);
    for node in &cfg.tree {
        let t = node.text.as_str();
        let toks: Vec<&str> = t.split(' ').collect();
        let loc = Loc::new(node.line, t);
        let lower = t.to_ascii_lowercase();
        if toks[0] == "interface" && toks.len() >= 2 {
            ios_interface(&mut f, node, &toks[1..].join(" "));
        } else if (lower.starts_with("ip access-list ")
            || lower.starts_with("ipv6 access-list ")
            || lower.starts_with("mac access-list "))
            && toks.len() >= 3
            && !matches!(
                toks[2],
                "resequence" | "logging" | "log-update" | "role-based"
            )
        {
            let name = toks[toks.len() - 1];
            f.def(RefKind::Acl, name, loc.clone());
            let mut entries = Vec::new();
            for c in &node.children {
                let ct = c.text.as_str();
                if ct.starts_with("remark")
                    || ct.starts_with("statistics")
                    || ct.starts_with("counters")
                    || ct.contains(" remark ")
                {
                    continue;
                }
                let (seq, content) = split_seq(ct);
                entries.push(AclEntry {
                    key: content.clone(),
                    action: action_of(&content),
                    catch_all: ios_catch_all(&content),
                    content,
                    seq,
                    loc: Loc::new(c.line, ct),
                });
            }
            f.acls.insert(
                name.to_string(),
                Acl {
                    name: name.to_string(),
                    loc,
                    entries,
                    header: t.to_string(),
                    numbered: false,
                },
            );
        } else if toks[0] == "access-list" && toks.len() >= 3 {
            let name = toks[1];
            if toks[2] == "remark" {
                continue;
            }
            let content = toks[2..].join(" ");
            f.def(RefKind::Acl, name, loc.clone());
            let acl = f.acls.entry(name.to_string()).or_insert_with(|| Acl {
                name: name.to_string(),
                loc: loc.clone(),
                entries: Vec::new(),
                header: format!("access-list {name}"),
                numbered: true,
            });
            acl.entries.push(AclEntry {
                key: content.clone(),
                action: action_of(&content),
                catch_all: ios_catch_all(&content),
                content,
                seq: None,
                loc,
            });
        } else if toks[0] == "route-map" && toks.len() >= 2 {
            f.def(RefKind::RoutePolicy, toks[1], loc);
        } else if (lower.starts_with("ip prefix-list ") || lower.starts_with("ipv6 prefix-list "))
            && toks.len() >= 3
            && toks[2] != "sequence-number"
        {
            f.def(RefKind::PrefixList, toks[2], loc);
        } else if lower.starts_with("ip community-list ") && toks.len() >= 3 {
            let name = if matches!(toks[2], "standard" | "expanded") && toks.len() >= 4 {
                toks[3]
            } else {
                toks[2]
            };
            f.def(RefKind::CommunityList, name, loc);
        } else if lower.starts_with("ip as-path access-list ") && toks.len() >= 4 {
            f.def(RefKind::AsPath, toks[3], loc);
        } else if toks[0] == "class-map" && toks.len() >= 2 {
            f.def(RefKind::ClassMap, toks[toks.len() - 1], loc);
        } else if toks[0] == "policy-map" && toks.len() >= 2 {
            f.def(RefKind::PolicyMap, toks[toks.len() - 1], loc);
            for c in &node.children {
                let ct = c.text.as_str();
                if let Some(rest) = ct.strip_prefix("class ") {
                    let name = rest.split(' ').next_back().unwrap_or("");
                    if name != "class-default" {
                        f.reference(RefKind::ClassMap, name, Loc::new(c.line, ct));
                    }
                }
            }
        } else if toks[0] == "router" && toks.get(1) == Some(&"bgp") && toks.len() >= 3 {
            f.bgp.asn = Some((toks[2].to_string(), loc));
            let mut nodes = Vec::new();
            collect_desc(&node.children, &mut nodes);
            for n in nodes {
                ios_bgp_line(&mut f, n);
            }
        } else if toks[0] == "router" && toks.get(1) == Some(&"ospf") && toks.len() >= 3 {
            let pid = toks[2];
            for c in &node.children {
                let ct = c.text.as_str();
                let cl = Loc::new(c.line, ct);
                if ct.starts_with("network ") {
                    f.ospf.networks.insert(format!("ospf {pid}: {ct}"), cl);
                } else if ct == "passive-interface default" {
                    f.ospf.passive_default = Some(cl);
                } else if let Some(i) = ct.strip_prefix("passive-interface ") {
                    f.ospf.passive.insert(i.to_string(), cl);
                } else if let Some(i) = ct.strip_prefix("no passive-interface ") {
                    f.ospf.no_passive.insert(i.to_string(), cl);
                }
            }
        } else if (toks[0] == "ip" || toks[0] == "ipv6") && toks.get(1) == Some(&"route") {
            if let Some(r) = ios_static(&toks, loc) {
                f.statics.push(r);
            }
        } else if toks[0] == "vlan"
            && toks.len() == 2
            && toks[1]
                .chars()
                .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
        {
            for v in parse_vlan_list(toks[1]) {
                f.vlans.insert(v, loc.clone());
            }
        } else if toks[0] == "snmp-server" && toks.get(1) == Some(&"community") && toks.len() >= 4 {
            let last = toks[toks.len() - 1];
            let prev = toks[toks.len() - 2];
            if !matches!(last.to_ascii_lowercase().as_str(), "ro" | "rw") && prev != "view" {
                f.reference(RefKind::Acl, last, loc);
            }
        } else if lower.starts_with("ip nat ") {
            if let Some(i) = toks.iter().position(|x| *x == "list") {
                if let Some(n) = toks.get(i + 1) {
                    f.reference(RefKind::Acl, n, loc.clone());
                }
            }
        } else if lower.starts_with("ntp access-group ") && toks.len() >= 4 {
            f.reference(RefKind::Acl, toks[3], loc);
        }
    }
    // Generic reference scan over every statement.
    for s in &cfg.stmts {
        let t = s.text();
        let loc = Loc::new(s.line, t);
        let top = s.path[0].as_str();
        if !t.starts_with("route-map ") {
            for c in RE_ROUTE_MAP_REF.captures_iter(t) {
                f.reference(RefKind::RoutePolicy, &c[1], loc.clone());
            }
        }
        if let Some(c) = RE_MATCH_PL.captures(t) {
            for n in c[1].split(' ') {
                f.reference(RefKind::PrefixList, n, loc.clone());
            }
        } else if let Some(c) = RE_MATCH_ACL.captures(t) {
            for n in c[1].split(' ') {
                f.reference(RefKind::Acl, n, loc.clone());
            }
        }
        if !top.starts_with("ip prefix-list") && !top.starts_with("ipv6 prefix-list") {
            if let Some(c) = RE_NEIGH_PL.captures(t) {
                f.reference(RefKind::PrefixList, &c[1], loc.clone());
            }
        }
        if let Some(c) = RE_DIST_PREFIX.captures(t) {
            f.reference(RefKind::PrefixList, &c[1], loc.clone());
        } else if let Some(c) = RE_DIST_ACL.captures(t) {
            if !matches!(&c[1], "prefix" | "route-map" | "gateway") {
                f.reference(RefKind::Acl, &c[1], loc.clone());
            }
        }
        if let Some(c) = RE_ACCESS_GROUP.captures(t) {
            f.reference(RefKind::Acl, &c[1], loc.clone());
        }
        if let Some(c) = RE_ACCESS_CLASS.captures(t) {
            f.reference(RefKind::Acl, &c[1], loc.clone());
        }
        if let Some(c) = RE_SERVICE_POLICY.captures(t) {
            f.reference(RefKind::PolicyMap, &c[1], loc.clone());
        }
        if let Some(rest) = t.strip_prefix("match community ") {
            for n in rest.split(' ').filter(|n| *n != "exact-match") {
                f.reference(RefKind::CommunityList, n, loc.clone());
            }
        }
        if let Some(rest) = t.strip_prefix("match as-path ") {
            for n in rest.split(' ') {
                f.reference(RefKind::AsPath, n, loc.clone());
            }
        }
        if let Some(c) = RE_FILTER_LIST.captures(t) {
            f.reference(RefKind::AsPath, &c[1], loc.clone());
        }
    }
    // Interface-level OSPF area membership and cost.
    let ifs: Vec<(String, Vec<Node>)> = cfg
        .tree
        .iter()
        .filter(|n| n.text.starts_with("interface "))
        .map(|n| (n.text["interface ".len()..].to_string(), n.children.clone()))
        .collect();
    for (name, children) in ifs {
        for c in children {
            let toks: Vec<&str> = c.text.split(' ').collect();
            let cl = Loc::new(c.line, c.text.clone());
            if toks.len() >= 4 && toks[0] == "ip" && toks[1] == "ospf" {
                // IOS: ip ospf <pid> area <a>; EOS: ip ospf area <a>
                if toks[2] == "area" {
                    f.ospf
                        .iface_area
                        .insert(name.clone(), (toks[3].to_string(), cl));
                } else if toks.len() >= 5 && toks[3] == "area" {
                    f.ospf
                        .iface_area
                        .insert(name.clone(), (toks[4].to_string(), cl));
                } else if toks[2] == "cost" {
                    f.ospf.cost.insert(name.clone(), (toks[3].to_string(), cl));
                }
            } else if toks.len() == 4 && toks[0] == "ip" && toks[1] == "ospf" && toks[2] == "cost" {
                f.ospf.cost.insert(name.clone(), (toks[3].to_string(), cl));
            }
        }
    }
    f
}

fn collect_desc<'a>(nodes: &'a [Node], out: &mut Vec<&'a Node>) {
    for n in nodes {
        out.push(n);
        collect_desc(&n.children, out);
    }
}

fn ios_interface(f: &mut Facts, node: &Node, name: &str) {
    let mut iface = Interface::new(name, Loc::new(node.line, node.text.clone()));
    for c in &node.children {
        let t = c.text.as_str();
        let toks: Vec<&str> = t.split(' ').collect();
        let loc = Loc::new(c.line, t);
        match toks.as_slice() {
            ["shutdown"] => iface.shutdown = Some(loc),
            ["mtu", v] => {
                iface.mtu.insert("mtu".into(), (v.to_string(), loc));
            }
            ["ip", "mtu", v] | ["ipv6", "mtu", v] => {
                iface
                    .mtu
                    .insert(format!("{} mtu", toks[0]), (v.to_string(), loc));
            }
            ["ip", "address", rest @ ..] | ["ipv6", "address", rest @ ..] if !rest.is_empty() => {
                iface
                    .addresses
                    .push((format!("{} {}", toks[0], rest.join(" ")), loc));
            }
            ["ip" | "ipv6", "access-group" | "traffic-filter", name, dir] => {
                iface.acls.push(AclBinding {
                    name: name.to_string(),
                    dir: dir.to_string(),
                    loc,
                });
            }
            ["switchport", "mode", "trunk"] => iface.is_trunk = true,
            ["switchport", "trunk", "allowed", "vlan", rest @ ..] if !rest.is_empty() => {
                let (cur, mut locs) = iface
                    .trunk_allowed
                    .take()
                    .unwrap_or((VlanSet::All, Vec::new()));
                let next = match rest {
                    ["all"] => VlanSet::All,
                    ["none"] => VlanSet::Some(BTreeSet::new()),
                    ["add", list] => {
                        let mut s = match cur {
                            VlanSet::All => all_vlans(),
                            VlanSet::Some(s) => s,
                        };
                        s.extend(parse_vlan_list(list));
                        VlanSet::Some(s)
                    }
                    ["remove", list] => {
                        let mut s = match cur {
                            VlanSet::All => all_vlans(),
                            VlanSet::Some(s) => s,
                        };
                        for v in parse_vlan_list(list) {
                            s.remove(&v);
                        }
                        VlanSet::Some(s)
                    }
                    ["except", list] => {
                        let mut s = all_vlans();
                        for v in parse_vlan_list(list) {
                            s.remove(&v);
                        }
                        VlanSet::Some(s)
                    }
                    [list] => VlanSet::Some(parse_vlan_list(list)),
                    _ => cur,
                };
                locs.push(loc);
                iface.trunk_allowed = Some((next, locs));
            }
            _ => {}
        }
    }
    f.interfaces.insert(name.to_string(), iface);
}

fn ios_bgp_line(f: &mut Facts, n: &Node) {
    let t = n.text.as_str();
    let toks: Vec<&str> = t.split(' ').collect();
    if toks.len() < 3 || toks[0] != "neighbor" {
        return;
    }
    let key = toks[1];
    let loc = Loc::new(n.line, t);
    let peer = f
        .bgp
        .peers
        .entry(key.to_string())
        .or_insert_with(|| BgpPeer::new(key, loc.clone()));
    match &toks[2..] {
        ["remote-as", asn, ..] => peer.remote_as = Some((asn.to_string(), loc)),
        ["shutdown", ..] => peer.shutdown = Some(loc),
        ["route-map", name, dir] => peer.policies.push(PolicyRef {
            kind: RefKind::RoutePolicy,
            name: name.to_string(),
            dir: dir.to_string(),
            loc,
        }),
        ["prefix-list", name, dir] => peer.policies.push(PolicyRef {
            kind: RefKind::PrefixList,
            name: name.to_string(),
            dir: dir.to_string(),
            loc,
        }),
        ["filter-list", name, dir] => peer.policies.push(PolicyRef {
            kind: RefKind::AsPath,
            name: name.to_string(),
            dir: dir.to_string(),
            loc,
        }),
        ["distribute-list", name, dir] => peer.policies.push(PolicyRef {
            kind: RefKind::Acl,
            name: name.to_string(),
            dir: dir.to_string(),
            loc,
        }),
        ["password", rest @ ..] => peer.password = Some((rest.join(" "), loc)),
        ["peer-group"] | ["peer", "group"] => peer.is_group = true,
        ["peer-group", g] | ["peer", "group", g] => peer.group = Some(g.to_string()),
        _ => {}
    }
}

fn ios_static(toks: &[&str], loc: Loc) -> Option<StaticRoute> {
    let mut i = 2;
    let mut vrf = String::new();
    if toks.get(i) == Some(&"vrf") {
        vrf = toks.get(i + 1)?.to_string();
        i += 2;
    }
    let dest = *toks.get(i)?;
    let (prefix, nh_start) = if dest.contains('/') {
        (dest.to_string(), i + 1)
    } else {
        let mask = toks.get(i + 1)?;
        let len = mask_len(mask)?;
        (format!("{dest}/{len}"), i + 2)
    };
    let next_hop = toks
        .get(nh_start..)
        .map(|r| r.join(" "))
        .unwrap_or_default();
    let default = prefix == "0.0.0.0/0" || prefix == "::/0";
    Some(StaticRoute {
        vrf,
        prefix,
        next_hop,
        default,
        loc,
    })
}

// -------------------------------------------------------------- Junos ----

static RE_J_IMPORT_EXPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s(?:import|export|vrf-import|vrf-export|from policy|instance-import|instance-export) (\S+)$").unwrap()
});
static RE_J_PREFIX_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\s(?:prefix-list|prefix-list-filter|source-prefix-list|destination-prefix-list) (\S+)",
    )
    .unwrap()
});
static RE_J_COMMUNITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s(?:from community|then community (?:add|set|delete)) (\S+)").unwrap()
});
static RE_J_ASPATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\sfrom as-path (\S+)").unwrap());

fn extract_junos(cfg: &Config) -> Facts {
    let mut f = Facts::new(Vendor::Junos);
    // Filter term ordering: filter -> Vec<(term, content lines, first loc)>
    let mut terms: BTreeMap<String, Vec<(String, Vec<String>, Loc)>> = BTreeMap::new();
    let mut filter_locs: BTreeMap<String, Loc> = BTreeMap::new();

    for s in &cfg.stmts {
        let text = s.text();
        let disp = junos_display(text);
        let loc = Loc::new(s.line, disp.clone());
        let toks_owned = junos_tokens(text);
        let toks: Vec<&str> = toks_owned.iter().map(String::as_str).collect();
        if toks.is_empty() {
            continue;
        }
        if toks[0] == "deactivate" {
            junos_deactivate(&mut f, &toks[1..], loc);
            continue;
        }
        // Strip routing-instance prefix for protocol/static facts.
        let (vrf, body): (String, &[&str]) = if toks[0] == "routing-instances" && toks.len() > 2 {
            (toks[1].to_string(), &toks[2..])
        } else {
            (String::new(), &toks[..])
        };
        match body {
            ["interfaces", ifname, rest @ ..] => {
                junos_interface(&mut f, ifname, rest, loc.clone());
            }
            ["firewall", rest @ ..] => {
                let (fname, after) = match rest {
                    ["family", _fam, "filter", name, after @ ..] => (*name, after),
                    ["filter", name, after @ ..] => (*name, after),
                    _ => ("", &[][..]),
                };
                if !fname.is_empty() {
                    let fname = fname.trim_matches('"');
                    f.def(RefKind::Acl, fname, loc.clone());
                    filter_locs.entry(fname.to_string()).or_insert(loc.clone());
                    if let ["term", tname, content @ ..] = after {
                        let list = terms.entry(fname.to_string()).or_default();
                        let line = content.join(" ");
                        match list.iter_mut().find(|(n, _, _)| n == tname) {
                            Some((_, lines, _)) => lines.push(line),
                            None => list.push((tname.to_string(), vec![line], loc.clone())),
                        }
                    }
                }
            }
            ["protocols", "bgp", "group", g, rest @ ..] => {
                let gkey = if vrf.is_empty() {
                    format!("group {g}")
                } else {
                    format!("group {g} (instance {vrf})")
                };
                let group = f
                    .bgp
                    .peers
                    .entry(gkey.clone())
                    .or_insert_with(|| BgpPeer::new(&gkey, loc.clone()));
                group.is_group = true;
                match rest {
                    ["neighbor", n, attrs @ ..] => {
                        let peer = f
                            .bgp
                            .peers
                            .entry(n.to_string())
                            .or_insert_with(|| BgpPeer::new(n, loc.clone()));
                        peer.group = Some(g.to_string());
                        junos_bgp_attr(peer, attrs, loc.clone());
                    }
                    attrs => junos_bgp_attr(group, attrs, loc.clone()),
                }
            }
            ["routing-options", "autonomous-system", asn, ..] if vrf.is_empty() => {
                f.bgp.asn = Some((asn.to_string(), loc.clone()));
            }
            ["protocols", "ospf" | "ospf3", "area", area, "interface", ifname, rest @ ..] => {
                f.ospf
                    .iface_area
                    .entry(ifname.to_string())
                    .or_insert((area.to_string(), loc.clone()));
                match rest {
                    ["passive", ..] => {
                        f.ospf.passive.insert(ifname.to_string(), loc.clone());
                    }
                    ["metric", m] => {
                        f.ospf
                            .cost
                            .insert(ifname.to_string(), (m.to_string(), loc.clone()));
                    }
                    _ => {}
                }
            }
            ["routing-options", "static", "route", prefix, kind, rest @ ..]
            | ["routing-options", "rib", _, "static", "route", prefix, kind, rest @ ..] => {
                if matches!(
                    *kind,
                    "next-hop"
                        | "qualified-next-hop"
                        | "discard"
                        | "reject"
                        | "receive"
                        | "next-table"
                ) {
                    let nh = if rest.is_empty() {
                        kind.to_string()
                    } else {
                        format!("{kind} {}", rest[0])
                    };
                    f.statics.push(StaticRoute {
                        vrf: vrf.clone(),
                        prefix: prefix.to_string(),
                        next_hop: nh,
                        default: *prefix == "0.0.0.0/0" || *prefix == "::/0",
                        loc: loc.clone(),
                    });
                }
            }
            ["vlans", name, ..] => {
                f.vlans.entry(name.to_string()).or_insert(loc.clone());
            }
            ["policy-options", "policy-statement", name, ..] => {
                f.def(RefKind::RoutePolicy, name, loc.clone())
            }
            ["policy-options", "prefix-list", name, ..] => {
                f.def(RefKind::PrefixList, name, loc.clone())
            }
            ["policy-options", "community", name, ..] => {
                f.def(RefKind::CommunityList, name, loc.clone())
            }
            ["policy-options", "as-path", name, ..] => f.def(RefKind::AsPath, name, loc.clone()),
            _ => {}
        }
        // References (any statement).
        let not_def_pl = !text.starts_with("policy-options prefix-list");
        if !text.starts_with("policy-options policy-statement") || text.contains(" from policy ") {
            if let Some(c) = RE_J_IMPORT_EXPORT.captures(text) {
                f.reference(RefKind::RoutePolicy, &c[1], loc.clone());
            }
        }
        if not_def_pl {
            if let Some(c) = RE_J_PREFIX_LIST.captures(text) {
                f.reference(RefKind::PrefixList, &c[1], loc.clone());
            }
        }
        if let Some(c) = RE_J_COMMUNITY.captures(text) {
            f.reference(RefKind::CommunityList, &c[1], loc.clone());
        }
        if let Some(c) = RE_J_ASPATH.captures(text) {
            f.reference(RefKind::AsPath, &c[1], loc.clone());
        }
    }
    // Interface filter bindings are references too.
    let bindings: Vec<AclBinding> = f
        .interfaces
        .values()
        .flat_map(|i| i.acls.iter().cloned())
        .collect();
    for b in bindings {
        f.reference(RefKind::Acl, &b.name, b.loc);
    }
    // Materialize filters with ordered terms.
    for (fname, floc) in filter_locs {
        let entries = terms
            .remove(&fname)
            .unwrap_or_default()
            .into_iter()
            .map(|(tname, lines, loc)| {
                let has_from = lines.iter().any(|l| l.starts_with("from "));
                let action = if lines.iter().any(|l| l == "then accept") {
                    Action::Permit
                } else if lines
                    .iter()
                    .any(|l| l == "then discard" || l.starts_with("then reject"))
                {
                    Action::Deny
                } else {
                    Action::Other
                };
                AclEntry {
                    key: tname.clone(),
                    content: lines.join("; "),
                    action,
                    catch_all: !has_from && action != Action::Other,
                    seq: None,
                    loc,
                }
            })
            .collect();
        f.acls.insert(
            fname.clone(),
            Acl {
                name: fname.clone(),
                loc: floc,
                entries,
                header: String::new(),
                numbered: false,
            },
        );
    }
    f
}

fn junos_interface(f: &mut Facts, ifname: &str, rest: &[&str], loc: Loc) {
    let phys = f
        .interfaces
        .entry(ifname.to_string())
        .or_insert_with(|| Interface::new(ifname, loc.clone()));
    match rest {
        ["disable"] => phys.shutdown = Some(loc),
        ["mtu", v] => {
            phys.mtu.insert("mtu".into(), (v.to_string(), loc));
        }
        ["unit", unit, urest @ ..] => {
            let uname = format!("{ifname}.{unit}");
            let u = f
                .interfaces
                .entry(uname.clone())
                .or_insert_with(|| Interface::new(&uname, loc.clone()));
            match urest {
                ["disable"] => u.shutdown = Some(loc),
                ["family", fam @ ("inet" | "inet6"), "address", addr, ..] => {
                    let a = format!("{fam} {addr}");
                    if !u.addresses.iter().any(|(x, _)| *x == a) {
                        u.addresses.push((a, loc));
                    }
                }
                ["family", fam, "mtu", v] => {
                    u.mtu.insert(format!("{fam} mtu"), (v.to_string(), loc));
                }
                ["family", _, "filter", dir @ ("input" | "output" | "input-list" | "output-list"), name] =>
                {
                    u.acls.push(AclBinding {
                        name: name.trim_matches('"').to_string(),
                        dir: dir.trim_end_matches("-list").to_string(),
                        loc,
                    });
                }
                ["family", "ethernet-switching", "interface-mode" | "port-mode", "trunk"] => {
                    u.is_trunk = true
                }
                ["family", "ethernet-switching", "vlan", "members", v] => {
                    let (cur, mut locs) = u
                        .trunk_allowed
                        .take()
                        .unwrap_or((VlanSet::Some(BTreeSet::new()), Vec::new()));
                    let next = match (cur, *v) {
                        (_, "all") => VlanSet::All,
                        (VlanSet::All, _) => VlanSet::All,
                        (VlanSet::Some(mut s), v) => {
                            s.extend(parse_vlan_list(v));
                            VlanSet::Some(s)
                        }
                    };
                    locs.push(loc);
                    u.trunk_allowed = Some((next, locs));
                }
                _ => {}
            }
        }
        _ => {}
    }
}

fn junos_bgp_attr(peer: &mut BgpPeer, attrs: &[&str], loc: Loc) {
    match attrs {
        ["peer-as", asn] => peer.remote_as = Some((asn.to_string(), loc)),
        [dir @ ("import" | "export"), name] => peer.policies.push(PolicyRef {
            kind: RefKind::RoutePolicy,
            name: name.to_string(),
            dir: dir.to_string(),
            loc,
        }),
        ["authentication-key", k] => peer.password = Some((k.to_string(), loc)),
        ["shutdown", ..] => peer.shutdown = Some(loc),
        _ => {}
    }
}

fn junos_deactivate(f: &mut Facts, toks: &[&str], loc: Loc) {
    let body: &[&str] = if toks.first() == Some(&"routing-instances") && toks.len() > 2 {
        &toks[2..]
    } else {
        toks
    };
    match body {
        ["protocols", "bgp", "group", g] => {
            let key = format!("group {g}");
            let p = f
                .bgp
                .peers
                .entry(key.clone())
                .or_insert_with(|| BgpPeer::new(&key, loc.clone()));
            p.is_group = true;
            p.shutdown = Some(loc);
        }
        ["protocols", "bgp", "group", g, "neighbor", n] => {
            let p = f
                .bgp
                .peers
                .entry(n.to_string())
                .or_insert_with(|| BgpPeer::new(n, loc.clone()));
            p.group = Some(g.to_string());
            p.shutdown = Some(loc);
        }
        ["interfaces", ifname] => {
            let i = f
                .interfaces
                .entry(ifname.to_string())
                .or_insert_with(|| Interface::new(ifname, loc.clone()));
            i.shutdown = Some(loc);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    #[test]
    fn mask_lengths() {
        assert_eq!(mask_len("255.255.255.0"), Some(24));
        assert_eq!(mask_len("0.0.0.0"), Some(0));
        assert_eq!(mask_len("255.255.255.255"), Some(32));
        assert_eq!(mask_len("255.0.255.0"), None);
    }

    #[test]
    fn vlan_lists() {
        let s = parse_vlan_list("10,20,30-32");
        assert_eq!(s.len(), 5);
        assert_eq!(format_vlans(&s), "10,20,30-32");
    }

    #[test]
    fn ios_facts() {
        let cfg = "interface Gi1\n ip address 10.0.0.1 255.255.255.0\n ip access-group EDGE in\n shutdown\n mtu 9000\ninterface Gi2\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n switchport trunk allowed vlan add 30\n ip ospf 1 area 0\n ip ospf cost 10\nip access-list extended EDGE\n remark test\n permit tcp any any eq 22\n deny ip any any log\naccess-list 10 permit 10.0.0.0 0.0.0.255\nroute-map RM permit 10\n match ip address prefix-list PL1 PL2\nip prefix-list PL1 seq 5 permit 10.0.0.0/8\nrouter bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 password 7 0822455D0A16\n address-family ipv4\n  neighbor 10.0.0.2 route-map RM out\n  neighbor 10.0.0.2 shutdown\nrouter ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n passive-interface default\n no passive-interface Gi2\nip route 0.0.0.0 0.0.0.0 192.0.2.1\nip route vrf MGMT 10.9.0.0 255.255.0.0 10.0.0.254 name x\nvlan 10,20\nline vty 0 4\n access-class VTY in\n";
        let f = extract(&parse(cfg, Vendor::CiscoIos));
        let gi1 = &f.interfaces["Gi1"];
        assert!(gi1.shutdown.is_some());
        assert_eq!(gi1.mtu["mtu"].0, "9000");
        assert_eq!(gi1.acls[0].name, "EDGE");
        let gi2 = &f.interfaces["Gi2"];
        match &gi2.trunk_allowed {
            Some((VlanSet::Some(s), _)) => assert_eq!(format_vlans(s), "10,20,30"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(f.ospf.iface_area["Gi2"].0, "0");
        assert_eq!(f.ospf.cost["Gi2"].0, "10");
        assert_eq!(f.acls["EDGE"].entries.len(), 2);
        assert!(f.acls["EDGE"].entries[1].catch_all);
        assert!(f.acls["10"].numbered);
        let p = &f.bgp.peers["10.0.0.2"];
        assert_eq!(p.remote_as.as_ref().unwrap().0, "65002");
        assert!(p.shutdown.is_some());
        assert_eq!(p.policies[0].name, "RM");
        assert!(p.password.is_some());
        assert_eq!(f.bgp.asn.as_ref().unwrap().0, "65001");
        assert!(f.ospf.passive_default.is_some());
        assert!(f.ospf.no_passive.contains_key("Gi2"));
        assert_eq!(f.statics.len(), 2);
        assert!(f.statics[0].default);
        assert_eq!(f.statics[1].prefix, "10.9.0.0/16");
        assert_eq!(f.statics[1].vrf, "MGMT");
        assert!(f.vlans.contains_key("20"));
        assert!(f.is_defined(RefKind::PrefixList, "PL1"));
        assert_eq!(f.refs_to(RefKind::PrefixList, "PL2").len(), 1);
        assert_eq!(f.refs_to(RefKind::RoutePolicy, "RM").len(), 1);
        assert_eq!(f.refs_to(RefKind::Acl, "VTY").len(), 1);
        assert_eq!(f.refs_to(RefKind::Acl, "EDGE").len(), 1);
    }

    #[test]
    fn eos_facts() {
        let cfg = "interface Ethernet1\n   ip address 10.0.0.1/31\n   ip ospf area 0.0.0.0\nip access-list EDGE\n   10 permit tcp any any eq bgp\n   20 deny ip any any\nrouter bgp 65001\n   neighbor SPINE peer group\n   neighbor 10.0.0.0 peer group SPINE\n   neighbor SPINE route-map RM-IN in\nip route 0.0.0.0/0 10.0.0.0\n";
        let f = extract(&parse(cfg, Vendor::AristaEos));
        assert_eq!(f.acls["EDGE"].entries[0].seq, Some(10));
        assert_eq!(f.acls["EDGE"].entries[0].key, "permit tcp any any eq bgp");
        assert!(f.bgp.peers["SPINE"].is_group);
        assert_eq!(f.bgp.peers["10.0.0.0"].group.as_deref(), Some("SPINE"));
        assert_eq!(f.ospf.iface_area["Ethernet1"].0, "0.0.0.0");
        assert!(f.statics[0].default);
    }

    #[test]
    fn junos_facts() {
        let cfg = "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30\nset interfaces ge-0/0/0 unit 0 family inet filter input PROTECT\nset interfaces ge-0/0/1 disable\nset interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members [ 10 20 ]\nset firewall family inet filter PROTECT term BGP from protocol tcp\nset firewall family inet filter PROTECT term BGP then accept\nset firewall family inet filter PROTECT term DENY then discard\nset protocols bgp group EBGP peer-as 65002\nset protocols bgp group EBGP export EXPORT-OUT\nset protocols bgp group EBGP neighbor 198.51.100.1\ndeactivate protocols bgp group EBGP neighbor 198.51.100.1\nset routing-options autonomous-system 65001\nset routing-options static route 0.0.0.0/0 next-hop 198.51.100.1\nset protocols ospf area 0.0.0.0 interface ge-0/0/0.0 passive\nset policy-options policy-statement EXPORT-OUT term 1 from prefix-list OURS\n";
        let f = extract(&parse(cfg, Vendor::Junos));
        assert_eq!(f.interfaces["ge-0/0/0.0"].addresses.len(), 1);
        assert_eq!(f.interfaces["ge-0/0/0.0"].acls[0].name, "PROTECT");
        assert!(f.interfaces["ge-0/0/1"].shutdown.is_some());
        let acl = &f.acls["PROTECT"];
        assert_eq!(acl.entries.len(), 2);
        assert_eq!(acl.entries[0].action, Action::Permit);
        assert!(acl.entries[1].catch_all);
        assert_eq!(f.bgp.peers["group EBGP"].policies[0].name, "EXPORT-OUT");
        assert!(f.bgp.peers["198.51.100.1"].shutdown.is_some());
        assert_eq!(f.bgp.asn.as_ref().unwrap().0, "65001");
        assert!(f.statics[0].default);
        assert!(f.ospf.passive.contains_key("ge-0/0/0.0"));
        assert!(f.is_defined(RefKind::RoutePolicy, "EXPORT-OUT"));
        assert_eq!(f.refs_to(RefKind::PrefixList, "OURS").len(), 1);
        assert_eq!(f.refs_to(RefKind::Acl, "PROTECT").len(), 1);
        match &f.interfaces["ge-0/0/2.0"].trunk_allowed {
            Some((VlanSet::Some(s), _)) => assert_eq!(s.len(), 2),
            o => panic!("{o:?}"),
        }
    }
}

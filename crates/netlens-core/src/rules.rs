//! Deterministic lint and risk rules. They need neither Batfish nor a model.
//!
//! Every rule compares before/after [`Facts`] (or the raw [`Diff`]) and emits
//! [`Finding`]s with quoted evidence. Ids (F1, F2, ...) are assigned later.

use crate::diff::{ChangeKind, Diff};
use crate::facts::{format_vlans, Acl, Action, Facts, Loc, RefKind, VlanSet};
use crate::finding::{Evidence, Finding, Severity};
use crate::model::Config;
use crate::section::{mgmt_category_ios, mgmt_category_junos, Section};
use crate::vendor::Vendor;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

/// Static description of a rule, for docs and `--list-rules`.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
}

pub const RULES: &[RuleInfo] = &[
    RuleInfo { id: "NL-IF-001", severity: Severity::High, summary: "Interface administratively shut down / disabled" },
    RuleInfo { id: "NL-IF-002", severity: Severity::High, summary: "Interface removed from the configuration" },
    RuleInfo { id: "NL-IF-003", severity: Severity::Medium, summary: "Interface brought up (shutdown removed)" },
    RuleInfo { id: "NL-IF-004", severity: Severity::Medium, summary: "MTU changed" },
    RuleInfo { id: "NL-IF-005", severity: Severity::High, summary: "Interface IP address removed or changed" },
    RuleInfo { id: "NL-IF-006", severity: Severity::High, summary: "VLAN removed from a trunk" },
    RuleInfo { id: "NL-IF-007", severity: Severity::Medium, summary: "VLAN definition removed" },
    RuleInfo { id: "NL-ACL-001", severity: Severity::High, summary: "ACL entry / filter term removed" },
    RuleInfo { id: "NL-ACL-002", severity: Severity::High, summary: "ACL entries / filter terms reordered" },
    RuleInfo { id: "NL-ACL-003", severity: Severity::Critical, summary: "Explicit catch-all permit removed: traffic now hits the implicit deny" },
    RuleInfo { id: "NL-ACL-004", severity: Severity::High, summary: "Catch-all permit added" },
    RuleInfo { id: "NL-ACL-005", severity: Severity::Critical, summary: "ACL/filter applied to an interface is undefined or has no entries" },
    RuleInfo { id: "NL-ACL-006", severity: Severity::High, summary: "Filter term content changed (Junos)" },
    RuleInfo { id: "NL-ACL-007", severity: Severity::Medium, summary: "Entries after a catch-all are unreachable" },
    RuleInfo { id: "NL-ACL-008", severity: Severity::Low, summary: "Explicit catch-all deny removed (logging/counters lost)" },
    RuleInfo { id: "NL-BGP-001", severity: Severity::High, summary: "BGP neighbor removed" },
    RuleInfo { id: "NL-BGP-002", severity: Severity::High, summary: "BGP neighbor shut down / deactivated" },
    RuleInfo { id: "NL-BGP-003", severity: Severity::High, summary: "BGP neighbor policy (route-map/prefix-list/import/export) changed" },
    RuleInfo { id: "NL-BGP-004", severity: Severity::High, summary: "BGP neighbor remote AS changed" },
    RuleInfo { id: "NL-BGP-005", severity: Severity::High, summary: "BGP session password changed" },
    RuleInfo { id: "NL-BGP-006", severity: Severity::Critical, summary: "Local BGP AS number changed" },
    RuleInfo { id: "NL-BGP-007", severity: Severity::Medium, summary: "New BGP neighbor without any route policy" },
    RuleInfo { id: "NL-BGP-008", severity: Severity::Medium, summary: "BGP neighbor re-enabled" },
    RuleInfo { id: "NL-OSPF-001", severity: Severity::High, summary: "OSPF network/interface membership changed" },
    RuleInfo { id: "NL-OSPF-002", severity: Severity::High, summary: "Interface moved to a different OSPF area" },
    RuleInfo { id: "NL-OSPF-003", severity: Severity::High, summary: "OSPF passive-interface changed" },
    RuleInfo { id: "NL-OSPF-004", severity: Severity::Medium, summary: "OSPF cost/metric changed" },
    RuleInfo { id: "NL-RT-001", severity: Severity::High, summary: "Static route removed" },
    RuleInfo { id: "NL-RT-002", severity: Severity::Critical, summary: "Default route removed" },
    RuleInfo { id: "NL-RT-003", severity: Severity::Medium, summary: "Static route next-hop changed" },
    RuleInfo { id: "NL-MGMT-001", severity: Severity::High, summary: "Management-plane change with lock-out risk (AAA, VTY, SSH, users, TACACS/RADIUS, services)" },
    RuleInfo { id: "NL-MGMT-002", severity: Severity::Medium, summary: "SNMP configuration changed" },
    RuleInfo { id: "NL-MGMT-003", severity: Severity::Low, summary: "NTP or logging configuration changed" },
    RuleInfo { id: "NL-REF-001", severity: Severity::High, summary: "Reference to an undefined route-map/prefix-list/ACL/policy (dangling)" },
    RuleInfo { id: "NL-REF-002", severity: Severity::Low, summary: "Definition no longer referenced (unused)" },
    RuleInfo { id: "NL-SEC-001", severity: Severity::Medium, summary: "Plaintext (type 0) credential introduced" },
    RuleInfo { id: "NL-SEC-002", severity: Severity::Medium, summary: "Well-known SNMP community (public/private)" },
];

pub struct Ctx<'a> {
    pub vendor: Vendor,
    pub before_cfg: &'a Config,
    pub after_cfg: &'a Config,
    pub before: &'a Facts,
    pub after: &'a Facts,
    pub diff: &'a Diff,
    /// Built from diff hunks: rules needing the full config are skipped.
    pub partial: bool,
}

fn ev_b(l: &Loc) -> Evidence {
    Evidence::before(l.line, l.text.clone())
}
fn ev_a(l: &Loc) -> Evidence {
    Evidence::after(l.line, l.text.clone())
}

/// Run every applicable rule. Returns findings (without ids) and notes
/// about skipped checks.
pub fn run(ctx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    interfaces(ctx, &mut out);
    acls(ctx, &mut out, &mut notes);
    bgp(ctx, &mut out);
    ospf(ctx, &mut out);
    statics(ctx, &mut out);
    mgmt(ctx, &mut out);
    secrets(ctx, &mut out);
    references(ctx, &mut out, &mut notes);
    (out, notes)
}

/// Lint a single configuration (no before/after): dangling references,
/// unreachable ACL entries, plaintext credentials.
pub fn lint_single(cfg: &Config, facts: &Facts) -> Vec<Finding> {
    let vendor = cfg.vendor;
    let mut out = Vec::new();
    for r in &facts.refs {
        if !facts.is_defined(r.kind, &r.name) {
            out.push(
                Finding::new(
                    "NL-REF-001",
                    Severity::High,
                    section_of_ref(r.kind),
                    format!(
                        "{} {} is referenced but not defined",
                        r.kind.name(vendor),
                        r.name
                    ),
                    dangling_explanation(r.kind, vendor),
                )
                .with(ev_a(&r.loc)),
            );
        }
    }
    for acl in facts.acls.values() {
        if let Some(f) = unreachable_after_catch_all(acl, vendor) {
            out.push(f);
        }
    }
    for s in &cfg.stmts {
        let t = s.display(vendor);
        if let Some(f) = secret_finding(&t, s.line, true) {
            out.push(f);
        }
    }
    dedupe(out)
}

fn dedupe(mut v: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    v.retain(|f| seen.insert((f.rule.clone(), f.title.clone(), f.first_line())));
    v
}

// ----------------------------------------------------------- interfaces ----

fn interfaces(ctx: &Ctx, out: &mut Vec<Finding>) {
    let v = ctx.vendor;
    for (name, b) in &ctx.before.interfaces {
        match ctx.after.interfaces.get(name) {
            None => {
                // Junos: skip units whose physical interface was removed too.
                if let Some((phys, _)) = name.split_once('.') {
                    if v == Vendor::Junos
                        && ctx.before.interfaces.contains_key(phys)
                        && !ctx.after.interfaces.contains_key(phys)
                    {
                        continue;
                    }
                }
                if ctx.partial && b.loc.line == 0 {
                    continue;
                }
                let mut f = Finding::new(
                    "NL-IF-002",
                    Severity::High,
                    Section::Interfaces,
                    format!("Interface {name} removed"),
                    "The interface's configuration is deleted. Its IP addressing, ACL bindings, routing-protocol participation and any services on it go away; physical ports fall back to defaults.",
                )
                .with(ev_b(&b.loc));
                for (a, l) in &b.addresses {
                    let _ = a;
                    f = f.with(ev_b(l));
                }
                out.push(f);
            }
            Some(a) => {
                match (&b.shutdown, &a.shutdown) {
                    (None, Some(l)) => out.push(
                        Finding::new(
                            "NL-IF-001",
                            Severity::High,
                            Section::Interfaces,
                            format!("Interface {name} shut down"),
                            "The interface goes administratively down: connected routes are withdrawn, adjacencies and BGP sessions over it drop, and traffic must reroute or is lost.",
                        )
                        .with(ev_a(l)),
                    ),
                    (Some(l), None) => out.push(
                        Finding::new(
                            "NL-IF-003",
                            Severity::Medium,
                            Section::Interfaces,
                            format!("Interface {name} brought up"),
                            "A previously shut interface becomes active. It can form new adjacencies, attract traffic or create a loop if the far end is not ready.",
                        )
                        .with(ev_b(l))
                        .with(ev_a(&a.loc)),
                    ),
                    _ => {}
                }
                for (k, (bv, bl)) in &b.mtu {
                    if let Some((av, al)) = a.mtu.get(k) {
                        if av != bv {
                            out.push(
                                Finding::new(
                                    "NL-IF-004",
                                    Severity::Medium,
                                    Section::Interfaces,
                                    format!("Interface {name} {k} changed {bv} -> {av}"),
                                    "MTU must match on both ends of a link. A mismatch leaves OSPF/IS-IS adjacencies stuck (e.g. OSPF in EXSTART/EXCHANGE) and silently drops large packets.",
                                )
                                .with(ev_b(bl))
                                .with(ev_a(al)),
                            );
                        }
                    } else {
                        out.push(
                            Finding::new(
                                "NL-IF-004",
                                Severity::Medium,
                                Section::Interfaces,
                                format!("Interface {name} {k} {bv} removed (back to default)"),
                                "The MTU reverts to the platform default, which may not match the far end.",
                            )
                            .with(ev_b(bl)),
                        );
                    }
                }
                for (k, (av, al)) in &a.mtu {
                    if !b.mtu.contains_key(k) {
                        out.push(
                            Finding::new(
                                "NL-IF-004",
                                Severity::Medium,
                                Section::Interfaces,
                                format!("Interface {name} {k} set to {av}"),
                                "MTU must match on both ends of a link. A mismatch leaves OSPF adjacencies stuck and drops large packets.",
                            )
                            .with(ev_a(al)),
                        );
                    }
                }
                let a_addrs: BTreeSet<&str> = a.addresses.iter().map(|(x, _)| x.as_str()).collect();
                let removed: Vec<&(String, Loc)> = b
                    .addresses
                    .iter()
                    .filter(|(x, _)| !a_addrs.contains(x.as_str()))
                    .collect();
                if !removed.is_empty() {
                    let b_addrs: BTreeSet<&str> =
                        b.addresses.iter().map(|(x, _)| x.as_str()).collect();
                    let added: Vec<&(String, Loc)> = a
                        .addresses
                        .iter()
                        .filter(|(x, _)| !b_addrs.contains(x.as_str()))
                        .collect();
                    let verb = if added.is_empty() {
                        "removed"
                    } else {
                        "changed"
                    };
                    let mut f = Finding::new(
                        "NL-IF-005",
                        Severity::High,
                        Section::Interfaces,
                        format!("Interface {name} IP address {verb}"),
                        "Connected routes change, and anything sourced from or peering with the old address (BGP/OSPF neighbors, tunnels, management access) breaks until the far end is updated.",
                    );
                    for (_, l) in removed {
                        f = f.with(ev_b(l));
                    }
                    for (_, l) in added {
                        f = f.with(ev_a(l));
                    }
                    out.push(f);
                }
                if let (Some((bs, bl)), Some((as_, al))) = (&b.trunk_allowed, &a.trunk_allowed) {
                    let lost: Option<String> = match (bs, as_) {
                        (VlanSet::All, VlanSet::Some(s)) => Some(format!(
                            "all VLANs except {}",
                            if s.is_empty() {
                                "none".into()
                            } else {
                                format_vlans(s)
                            }
                        )),
                        (VlanSet::Some(bset), VlanSet::Some(aset)) => {
                            let gone: BTreeSet<String> = bset.difference(aset).cloned().collect();
                            if gone.is_empty() {
                                None
                            } else {
                                Some(format_vlans(&gone))
                            }
                        }
                        _ => None,
                    };
                    if let Some(lost) = lost {
                        let mut f = Finding::new(
                            "NL-IF-006",
                            Severity::High,
                            Section::Interfaces,
                            format!("VLAN(s) {lost} removed from trunk {name}"),
                            "Hosts in the removed VLANs lose connectivity across this trunk; STP may also reconverge for those VLANs.",
                        );
                        for l in bl {
                            f = f.with(ev_b(l));
                        }
                        for l in al {
                            f = f.with(ev_a(l));
                        }
                        out.push(f);
                    }
                }
            }
        }
    }
    for (vlan, l) in &ctx.before.vlans {
        if !ctx.after.vlans.contains_key(vlan) && !(ctx.partial && l.line == 0) {
            out.push(
                Finding::new(
                    "NL-IF-007",
                    Severity::Medium,
                    Section::Vlans,
                    format!("VLAN {vlan} removed"),
                    "Removing the VLAN definition suspends it on every access and trunk port that carries it.",
                )
                .with(ev_b(l)),
            );
        }
    }
}

// ----------------------------------------------------------------- ACLs ----

fn acl_label(v: Vendor) -> &'static str {
    if v == Vendor::Junos {
        "firewall filter"
    } else {
        "ACL"
    }
}

fn entry_label(v: Vendor) -> &'static str {
    if v == Vendor::Junos {
        "term"
    } else {
        "entry"
    }
}

fn acls(ctx: &Ctx, out: &mut Vec<Finding>, notes: &mut Vec<String>) {
    let v = ctx.vendor;
    let kind = acl_label(v);
    let el = entry_label(v);
    for (name, b) in &ctx.before.acls {
        let Some(a) = ctx.after.acls.get(name) else {
            continue; // whole ACL removed: covered by NL-REF-001 when still referenced
        };
        let akeys: BTreeMap<&str, usize> = a
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.key.as_str(), i))
            .collect();
        for e in &b.entries {
            if !akeys.contains_key(e.key.as_str()) {
                let consequence = match e.action {
                    Action::Permit => "Traffic it permitted now falls through to later entries and, if nothing else matches, to the implicit deny at the end.",
                    Action::Deny => "Traffic it denied is now evaluated by later entries and may be permitted.",
                    Action::Other => "Packets it matched are now evaluated by later entries.",
                };
                // A removed catch-all permit is reported by NL-ACL-003 instead.
                if e.catch_all && e.action == Action::Permit {
                    continue;
                }
                out.push(
                    Finding::new(
                        "NL-ACL-001",
                        Severity::High,
                        Section::Acl,
                        format!("{kind} {name}: {el} removed"),
                        consequence,
                    )
                    .with(ev_b(&e.loc)),
                );
            }
        }
        if v == Vendor::Junos {
            for e in &b.entries {
                if let Some(&i) = akeys.get(e.key.as_str()) {
                    let ae = &a.entries[i];
                    if ae.content != e.content {
                        out.push(
                            Finding::new(
                                "NL-ACL-006",
                                Severity::High,
                                Section::Acl,
                                format!("{kind} {name}: term {} changed", e.key),
                                "The term's match conditions or action changed, so a different set of packets is accepted or discarded.",
                            )
                            .with(ev_b(&e.loc))
                            .with(ev_a(&ae.loc)),
                        );
                    }
                }
            }
        }
        // Reorder: relative order of entries present in both.
        let bkeys: BTreeSet<&str> = b.entries.iter().map(|e| e.key.as_str()).collect();
        let b_common: Vec<&str> = b
            .entries
            .iter()
            .map(|e| e.key.as_str())
            .filter(|k| akeys.contains_key(k))
            .collect();
        let a_common: Vec<&str> = a
            .entries
            .iter()
            .map(|e| e.key.as_str())
            .filter(|k| bkeys.contains(k))
            .collect();
        if b_common != a_common {
            let first = b_common
                .iter()
                .zip(a_common.iter())
                .position(|(x, y)| x != y)
                .unwrap_or(0);
            let bl = b.entries.iter().find(|e| e.key == b_common[first]).unwrap();
            let al = a.entries.iter().find(|e| e.key == a_common[first]).unwrap();
            out.push(
                Finding::new(
                    "NL-ACL-002",
                    Severity::High,
                    Section::Acl,
                    format!("{kind} {name}: {el}s reordered"),
                    "ACLs are first-match. Changing the order changes which entry a packet hits, even though no entry was added or removed.",
                )
                .with(ev_b(&bl.loc))
                .with(ev_a(&al.loc)),
            );
        }
        if ctx.partial {
            continue;
        }
        let b_last = b.entries.last();
        let a_last = a.entries.last();
        let b_cp = b_last.filter(|e| e.catch_all && e.action == Action::Permit);
        let a_cp = a_last.filter(|e| e.catch_all && e.action == Action::Permit);
        if let (Some(be), None) = (b_cp, a_cp) {
            let mut f = Finding::new(
                "NL-ACL-003",
                Severity::Critical,
                Section::Acl,
                format!("{kind} {name}: final catch-all permit removed"),
                "The explicit permit-everything at the end is gone, so all traffic not matched by an earlier entry now hits the implicit deny. This typically blocks far more than intended.",
            )
            .with(ev_b(&be.loc));
            if let Some(al) = a_last {
                f = f.with(ev_a(&al.loc));
            }
            out.push(f);
        }
        if let (None, Some(ae)) = (b_cp, a_cp) {
            out.push(
                Finding::new(
                    "NL-ACL-004",
                    Severity::High,
                    Section::Acl,
                    format!("{kind} {name}: catch-all permit added"),
                    "Everything not explicitly denied earlier is now permitted, which effectively disables filtering for unmatched traffic.",
                )
                .with(ev_a(&ae.loc)),
            );
        }
        let b_cd = b_last.filter(|e| e.catch_all && e.action == Action::Deny);
        let a_cd = a_last.filter(|e| e.catch_all && e.action == Action::Deny);
        if let (Some(be), None, None) = (b_cd, a_cd, a_cp) {
            out.push(
                Finding::new(
                    "NL-ACL-008",
                    Severity::Low,
                    Section::Acl,
                    format!("{kind} {name}: explicit final deny removed"),
                    "The implicit deny still applies, but logging and hit counters from the explicit deny are lost.",
                )
                .with(ev_b(&be.loc)),
            );
        }
        if !has_unreachable(b) {
            if let Some(f) = unreachable_after_catch_all(a, v) {
                out.push(f);
            }
        }
    }
    if ctx.partial {
        notes.push(
            "diff input: implicit-deny and applied-ACL checks need full configs and were skipped"
                .into(),
        );
        return;
    }
    // ACL applied to an interface but undefined/empty after the change.
    for (ifname, a) in &ctx.after.interfaces {
        for bind in &a.acls {
            let state = match ctx.after.acls.get(&bind.name) {
                None => Some("is not defined"),
                Some(acl) if acl.entries.is_empty() => Some("has no entries"),
                _ => None,
            };
            let Some(state) = state else { continue };
            // Only flag if this is new.
            let was_ok = ctx
                .before
                .acls
                .get(&bind.name)
                .map(|x| !x.entries.is_empty())
                .unwrap_or(false);
            let was_bound = ctx
                .before
                .interfaces
                .get(ifname)
                .map(|i| i.acls.iter().any(|x| x.name == bind.name))
                .unwrap_or(false);
            if was_bound && !was_ok {
                continue;
            }
            let expl = if v == Vendor::Junos {
                "A filter that is referenced but not defined fails commit; an empty filter discards everything (implicit discard)."
            } else {
                "On IOS/EOS an applied ACL that is undefined or empty behaves as permit-all, silently removing the filtering on this interface."
            };
            out.push(
                Finding::new(
                    "NL-ACL-005",
                    Severity::Critical,
                    Section::Acl,
                    format!(
                        "{kind} {} applied {} on {ifname} {state}",
                        bind.name, bind.dir
                    ),
                    expl,
                )
                .with(ev_a(&bind.loc)),
            );
        }
    }
}

fn has_unreachable(acl: &Acl) -> bool {
    acl.entries
        .iter()
        .position(|e| e.catch_all)
        .map(|p| p + 1 < acl.entries.len())
        .unwrap_or(false)
}

fn unreachable_after_catch_all(acl: &Acl, v: Vendor) -> Option<Finding> {
    let pos = acl.entries.iter().position(|e| e.catch_all)?;
    if pos + 1 >= acl.entries.len() {
        return None;
    }
    let mut f = Finding::new(
        "NL-ACL-007",
        Severity::Medium,
        Section::Acl,
        format!(
            "{} {}: {} {} after a catch-all can never match",
            acl_label(v),
            acl.name,
            acl.entries.len() - pos - 1,
            if acl.entries.len() - pos - 1 == 1 {
                entry_label(v).to_string()
            } else {
                format!("{}s", entry_label(v))
            }
        ),
        "ACLs are first-match; anything placed after a match-all entry is dead code.",
    )
    .with(ev_a(&acl.entries[pos].loc));
    for e in &acl.entries[pos + 1..] {
        f = f.with(ev_a(&e.loc));
    }
    Some(f)
}

// ------------------------------------------------------------------ BGP ----

fn bgp(ctx: &Ctx, out: &mut Vec<Finding>) {
    if let (Some((ba, bl)), Some((aa, al))) = (&ctx.before.bgp.asn, &ctx.after.bgp.asn) {
        if ba != aa {
            out.push(
                Finding::new(
                    "NL-BGP-006",
                    Severity::Critical,
                    Section::Bgp,
                    format!("Local BGP AS changed {ba} -> {aa}"),
                    "Every BGP session resets and peers reject the new AS until their remote-as is updated.",
                )
                .with(ev_b(bl))
                .with(ev_a(al)),
            );
        }
    }
    for (key, b) in &ctx.before.bgp.peers {
        let label = b.label();
        let Some(a) = ctx.after.bgp.peers.get(key) else {
            if ctx.partial && b.loc.line == 0 {
                continue;
            }
            out.push(
                Finding::new(
                    "NL-BGP-001",
                    Severity::High,
                    Section::Bgp,
                    format!("{label} removed"),
                    "The session is torn down and every prefix learned from or advertised to this peer is withdrawn.",
                )
                .with(ev_b(&b.loc)),
            );
            continue;
        };
        match (&b.shutdown, &a.shutdown) {
            (None, Some(l)) => out.push(
                Finding::new(
                    "NL-BGP-002",
                    Severity::High,
                    Section::Bgp,
                    format!("{label} {}", a.shut_verb()),
                    "The session goes down immediately; prefixes learned from this peer are withdrawn and traffic shifts to other paths, or is dropped if there is none.",
                )
                .with(ev_a(l)),
            ),
            (Some(l), None) => out.push(
                Finding::new(
                    "NL-BGP-008",
                    Severity::Medium,
                    Section::Bgp,
                    format!("{label} re-enabled"),
                    "The session comes back up and starts exchanging routes under the current policy.",
                )
                .with(ev_b(l)),
            ),
            _ => {}
        }
        if let (Some((bas, bl)), Some((aas, al))) = (&b.remote_as, &a.remote_as) {
            if bas != aas {
                out.push(
                    Finding::new(
                        "NL-BGP-004",
                        Severity::High,
                        Section::Bgp,
                        format!("{label} remote AS changed {bas} -> {aas}"),
                        "The session resets and will only come back if the peer really uses the new AS.",
                    )
                    .with(ev_b(bl))
                    .with(ev_a(al)),
                );
            }
        }
        match (&b.password, &a.password) {
            (Some((bp, bl)), Some((ap, al))) if bp != ap => out.push(
                Finding::new(
                    "NL-BGP-005",
                    Severity::High,
                    Section::Bgp,
                    format!("{label} session password changed"),
                    "TCP-MD5/AO authentication must match on both sides; the session drops (hold-timer expiry) until the peer uses the same key.",
                )
                .with(ev_b(bl))
                .with(ev_a(al)),
            ),
            (Some((_, bl)), None) => out.push(
                Finding::new(
                    "NL-BGP-005",
                    Severity::High,
                    Section::Bgp,
                    format!("{label} session password removed"),
                    "If the peer still expects authentication, the session will not re-establish.",
                )
                .with(ev_b(bl)),
            ),
            (None, Some((_, al))) => out.push(
                Finding::new(
                    "NL-BGP-005",
                    Severity::High,
                    Section::Bgp,
                    format!("{label} session password added"),
                    "The session drops until the peer configures the same key.",
                )
                .with(ev_a(al)),
            ),
            _ => {}
        }
        // Policy changes, grouped per direction/kind.
        let fmt = |p: &crate::facts::PolicyRef| {
            format!("{}|{}|{}", p.dir, p.kind.name(ctx.vendor), p.name)
        };
        let bset: BTreeSet<String> = b.policies.iter().map(fmt).collect();
        let aset: BTreeSet<String> = a.policies.iter().map(fmt).collect();
        if bset != aset {
            let mut f = Finding::new(
                "NL-BGP-003",
                Severity::High,
                Section::Bgp,
                format!("{label} routing policy changed"),
                "A different route-map/prefix-list/policy now filters or modifies routes to/from this peer; prefixes may be leaked or withdrawn. Soft or hard session resets may be required to apply it.",
            );
            for p in b.policies.iter().filter(|p| !aset.contains(&fmt(p))) {
                f = f.with(ev_b(&p.loc));
            }
            for p in a.policies.iter().filter(|p| !bset.contains(&fmt(p))) {
                f = f.with(ev_a(&p.loc));
            }
            out.push(f);
        }
    }
    for (key, a) in &ctx.after.bgp.peers {
        if ctx.before.bgp.peers.contains_key(key) || a.is_group {
            continue;
        }
        let inherits = a
            .group
            .as_ref()
            .map(|g| {
                ctx.after
                    .bgp
                    .peers
                    .get(g)
                    .or_else(|| ctx.after.bgp.peers.get(&format!("group {g}")))
                    .map(|p| !p.policies.is_empty())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if a.policies.is_empty() && !inherits && !ctx.partial {
            out.push(
                Finding::new(
                    "NL-BGP-007",
                    Severity::Medium,
                    Section::Bgp,
                    format!("New {} has no route policy", a.label()),
                    "Without inbound/outbound policy the session may accept or advertise everything (vendor defaults differ); eBGP peers should always have explicit policy.",
                )
                .with(ev_a(&a.loc)),
            );
        }
    }
}

// ----------------------------------------------------------------- OSPF ----

fn ospf(ctx: &Ctx, out: &mut Vec<Finding>) {
    let (b, a) = (&ctx.before.ospf, &ctx.after.ospf);
    for (k, l) in &b.networks {
        if !a.networks.contains_key(k) {
            out.push(
                Finding::new(
                    "NL-OSPF-001",
                    Severity::High,
                    Section::Ospf,
                    format!("OSPF network statement removed ({})", k.split(": ").nth(1).unwrap_or(k)),
                    "Interfaces matching this network stop running OSPF: adjacencies drop and their subnets are no longer advertised.",
                )
                .with(ev_b(l)),
            );
        }
    }
    for (k, l) in &a.networks {
        if !b.networks.contains_key(k) {
            out.push(
                Finding::new(
                    "NL-OSPF-001",
                    Severity::High,
                    Section::Ospf,
                    format!("OSPF network statement added ({})", k.split(": ").nth(1).unwrap_or(k)),
                    "More interfaces may start running OSPF, forming new adjacencies and advertising new subnets.",
                )
                .with(ev_a(l)),
            );
        }
    }
    for (ifn, (barea, bl)) in &b.iface_area {
        match a.iface_area.get(ifn) {
            None => out.push(
                Finding::new(
                    "NL-OSPF-001",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} removed from OSPF area {barea}"),
                    "OSPF adjacencies on this interface drop and its subnet is no longer advertised.",
                )
                .with(ev_b(bl)),
            ),
            Some((aarea, al)) if aarea != barea => out.push(
                Finding::new(
                    "NL-OSPF-002",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} moved from OSPF area {barea} to {aarea}"),
                    "Area IDs must match on both ends; the adjacency drops until the neighbor is moved as well, and inter-area routing changes.",
                )
                .with(ev_b(bl))
                .with(ev_a(al)),
            ),
            _ => {}
        }
    }
    for (ifn, (aarea, al)) in &a.iface_area {
        if !b.iface_area.contains_key(ifn) {
            out.push(
                Finding::new(
                    "NL-OSPF-001",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} added to OSPF area {aarea}"),
                    "The interface starts sending hellos and its subnet is advertised into OSPF.",
                )
                .with(ev_a(al)),
            );
        }
    }
    let passive_msg_on = "The interface stops sending hellos: existing adjacencies over it drop (the subnet is still advertised).";
    let passive_msg_off = "The interface starts sending hellos and may form unexpected adjacencies (a security and stability concern on edge links).";
    match (&b.passive_default, &a.passive_default) {
        (None, Some(l)) => out.push(
            Finding::new("NL-OSPF-003", Severity::High, Section::Ospf, "OSPF passive-interface default enabled", "All interfaces become passive unless explicitly excluded; every adjacency not covered by 'no passive-interface' drops.")
                .with(ev_a(l)),
        ),
        (Some(l), None) => out.push(
            Finding::new("NL-OSPF-003", Severity::High, Section::Ospf, "OSPF passive-interface default removed", "All OSPF interfaces start sending hellos, including edge-facing ones.")
                .with(ev_b(l)),
        ),
        _ => {}
    }
    for (ifn, l) in &a.passive {
        if !b.passive.contains_key(ifn) {
            out.push(
                Finding::new(
                    "NL-OSPF-003",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} made OSPF-passive"),
                    passive_msg_on,
                )
                .with(ev_a(l)),
            );
        }
    }
    for (ifn, l) in &b.passive {
        if !a.passive.contains_key(ifn)
            && (a.iface_area.contains_key(ifn) || ctx.vendor.is_ios_like())
        {
            out.push(
                Finding::new(
                    "NL-OSPF-003",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} no longer OSPF-passive"),
                    passive_msg_off,
                )
                .with(ev_b(l)),
            );
        }
    }
    for (ifn, l) in &b.no_passive {
        if !a.no_passive.contains_key(ifn) && a.passive_default.is_some() {
            out.push(
                Finding::new(
                    "NL-OSPF-003",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} becomes OSPF-passive (no passive-interface removed)"),
                    passive_msg_on,
                )
                .with(ev_b(l)),
            );
        }
    }
    for (ifn, l) in &a.no_passive {
        if !b.no_passive.contains_key(ifn) && b.passive_default.is_some() {
            out.push(
                Finding::new(
                    "NL-OSPF-003",
                    Severity::High,
                    Section::Ospf,
                    format!("Interface {ifn} no longer OSPF-passive"),
                    passive_msg_off,
                )
                .with(ev_a(l)),
            );
        }
    }
    for (ifn, (bc, bl)) in &b.cost {
        if let Some((ac, al)) = a.cost.get(ifn) {
            if ac != bc {
                out.push(
                    Finding::new(
                        "NL-OSPF-004",
                        Severity::Medium,
                        Section::Ospf,
                        format!("OSPF cost on {ifn} changed {bc} -> {ac}"),
                        "Path selection changes: traffic may shift onto or away from this link.",
                    )
                    .with(ev_b(bl))
                    .with(ev_a(al)),
                );
            }
        }
    }
}

// --------------------------------------------------------- static routes ----

fn statics(ctx: &Ctx, out: &mut Vec<Finding>) {
    let akeys: BTreeSet<String> = ctx.after.statics.iter().map(|r| r.key()).collect();
    for r in &ctx.before.statics {
        if akeys.contains(&r.key()) {
            continue;
        }
        let vrf = if r.vrf.is_empty() {
            String::new()
        } else {
            format!(" (vrf {})", r.vrf)
        };
        let replacement = ctx
            .after
            .statics
            .iter()
            .find(|x| x.vrf == r.vrf && x.prefix == r.prefix);
        if let Some(n) = replacement {
            out.push(
                Finding::new(
                    "NL-RT-003",
                    Severity::Medium,
                    Section::StaticRoutes,
                    format!("Static route {}{vrf} next-hop changed", r.prefix),
                    "Traffic to this prefix is forwarded to a different next-hop; verify it is reachable and the path is intended.",
                )
                .with(ev_b(&r.loc))
                .with(ev_a(&n.loc)),
            );
        } else if r.default {
            out.push(
                Finding::new(
                    "NL-RT-002",
                    Severity::Critical,
                    Section::StaticRoutes,
                    format!("Default route{vrf} removed"),
                    "Without a default route, traffic to any destination not in the routing table is dropped unless a dynamic default is learned.",
                )
                .with(ev_b(&r.loc)),
            );
        } else {
            out.push(
                Finding::new(
                    "NL-RT-001",
                    Severity::High,
                    Section::StaticRoutes,
                    format!("Static route {}{vrf} removed", r.prefix),
                    "Traffic to this prefix follows a less specific route or is dropped; redistribution of the static route stops.",
                )
                .with(ev_b(&r.loc)),
            );
        }
    }
}

// ---------------------------------------------------------------- mgmt ----

fn mgmt(ctx: &Ctx, out: &mut Vec<Finding>) {
    let mut cats: BTreeMap<&'static str, Vec<Evidence>> = BTreeMap::new();
    let lookup = |c: &crate::diff::Change| -> Option<&'static str> {
        let head = c.path.first().map(String::as_str).unwrap_or("");
        match ctx.vendor {
            Vendor::Junos => mgmt_category_junos(head),
            _ => mgmt_category_ios(&head.to_ascii_lowercase()),
        }
    };
    for c in &ctx.diff.changes {
        if c.section != Section::Mgmt {
            continue;
        }
        let Some(cat) = lookup(c) else { continue };
        let text = if ctx.vendor == Vendor::Junos {
            crate::model::junos_display(c.text())
        } else {
            c.text().to_string()
        };
        let ev = match c.kind {
            ChangeKind::Removed => Evidence::before(c.line, text),
            ChangeKind::Added => Evidence::after(c.line, text),
        };
        cats.entry(cat).or_default().push(ev);
    }
    for (cat, evs) in cats {
        let (rule, sev, expl) = match cat {
            "SNMP" => ("NL-MGMT-002", Severity::Medium, "Monitoring may stop (polling/traps), or SNMP access may be opened to more sources than intended."),
            "NTP" | "logging" => ("NL-MGMT-003", Severity::Low, "Time sync or log delivery changes; this affects troubleshooting and audit trails rather than forwarding."),
            _ => ("NL-MGMT-001", Severity::High, "Management-plane changes can lock you out of the device. Keep a console/out-of-band session open and use a timed rollback (commit confirmed / reload in / configure session timer)."),
        };
        let mut f = Finding::new(
            rule,
            sev,
            Section::Mgmt,
            format!("Management plane changed: {cat}"),
            expl,
        );
        f.evidence = evs;
        out.push(f);
    }
}

// -------------------------------------------------------------- secrets ----

static RE_PLAINTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|\s)(?:password|secret|key|key-string)\s+0\s+\S+|(?:^|\s)username\s+\S+(?:\s+privilege\s+\d+)?\s+password\s+(?:[^0-9\s]\S*)").unwrap()
});
static RE_WEAK_SNMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:snmp-server community|snmp community)\s+"?(public|private)"?(?:\s|$)"#)
        .unwrap()
});

fn secret_finding(text: &str, line: usize, after: bool) -> Option<Finding> {
    let ev = if after {
        Evidence::after(line, text)
    } else {
        Evidence::before(line, text)
    };
    if RE_WEAK_SNMP.is_match(text) {
        return Some(
            Finding::new(
                "NL-SEC-002",
                Severity::Medium,
                Section::Mgmt,
                "Well-known SNMP community configured",
                "'public'/'private' are the first communities scanners try; use SNMPv3 or a long random community restricted by an ACL.",
            )
            .with(ev),
        );
    }
    if RE_PLAINTEXT.is_match(text) {
        return Some(
            Finding::new(
                "NL-SEC-001",
                Severity::Medium,
                Section::Mgmt,
                "Plaintext credential in configuration",
                "The secret is stored unencrypted (type 0) and is readable by anyone with config access or a backup copy. Use a hashed type (secret 9/8, sha512) instead.",
            )
            .with(ev),
        );
    }
    None
}

fn secrets(ctx: &Ctx, out: &mut Vec<Finding>) {
    for c in &ctx.diff.changes {
        if c.kind != ChangeKind::Added {
            continue;
        }
        let text = if ctx.vendor == Vendor::Junos {
            crate::model::junos_display(c.text())
        } else {
            c.text().to_string()
        };
        if let Some(f) = secret_finding(&text, c.line, true) {
            out.push(f);
        }
    }
}

// ----------------------------------------------------------- references ----

fn section_of_ref(k: RefKind) -> Section {
    match k {
        RefKind::Acl => Section::Acl,
        RefKind::ClassMap | RefKind::PolicyMap => Section::Qos,
        _ => Section::RoutePolicy,
    }
}

fn dangling_explanation(k: RefKind, v: Vendor) -> String {
    let base = match (k, v) {
        (_, Vendor::Junos) => "Junos rejects the commit when a referenced policy, prefix-list or filter does not exist.",
        (RefKind::RoutePolicy, _) => "On IOS/EOS a BGP neighbor whose route-map does not exist typically advertises/accepts nothing (IOS-XE) or behaves platform-specifically; redistribution with a missing route-map redistributes nothing.",
        (RefKind::PrefixList, _) => "A missing prefix-list matches everything on some platforms and nothing on others; either way the intended filter is not applied.",
        (RefKind::Acl, _) => "An undefined ACL is treated as permit-all where it filters traffic, and as no-match where it is used for classification.",
        _ => "The referenced object does not exist, so the intended match or policy is not applied.",
    };
    base.to_string()
}

fn references(ctx: &Ctx, out: &mut Vec<Finding>, notes: &mut Vec<String>) {
    let v = ctx.vendor;
    if ctx.partial {
        // Only what the diff itself proves: a definition removed in the diff
        // while a reference to it is still visible in the after-context.
        for ((kind, name), bl) in &ctx.before.defs {
            if ctx.after.defs.contains_key(&(*kind, name.clone())) {
                continue;
            }
            let refs = ctx.after.refs_to(*kind, name);
            if refs.is_empty() {
                continue;
            }
            let mut f = Finding::new(
                "NL-REF-001",
                Severity::High,
                section_of_ref(*kind),
                format!(
                    "{} {} deleted but still referenced (diff context)",
                    kind.name(v),
                    name
                ),
                dangling_explanation(*kind, v),
            )
            .with(ev_b(bl));
            for r in refs {
                f = f.with(ev_a(&r.loc));
            }
            out.push(f);
        }
        notes.push("diff input: dangling/unused reference checks only see the diff context".into());
        return;
    }
    // Dangling references introduced by the change.
    let mut seen: BTreeSet<(RefKind, String)> = BTreeSet::new();
    for r in &ctx.after.refs {
        if ctx.after.is_defined(r.kind, &r.name) {
            continue;
        }
        if !seen.insert((r.kind, r.name.clone())) {
            continue;
        }
        let pre_existing = !ctx.before.is_defined(r.kind, &r.name)
            && !ctx.before.refs_to(r.kind, &r.name).is_empty();
        let all_refs = ctx.after.refs_to(r.kind, &r.name);
        let (title, sev) = if ctx.before.is_defined(r.kind, &r.name) {
            (
                format!("{} {} deleted but still referenced", r.kind.name(v), r.name),
                Severity::High,
            )
        } else if pre_existing {
            (
                format!(
                    "{} {} is referenced but not defined (pre-existing)",
                    r.kind.name(v),
                    r.name
                ),
                Severity::Info,
            )
        } else {
            (
                format!("{} {} referenced but not defined", r.kind.name(v), r.name),
                Severity::High,
            )
        };
        let mut f = Finding::new(
            "NL-REF-001",
            sev,
            section_of_ref(r.kind),
            title,
            dangling_explanation(r.kind, v),
        );
        if let Some(bl) = ctx.before.defs.get(&(r.kind, r.name.clone())) {
            f = f.with(ev_b(bl));
        }
        for x in all_refs {
            f = f.with(ev_a(&x.loc));
        }
        out.push(f);
    }
    // Reverse: definitions that became unused because of this change.
    for ((kind, name), al) in &ctx.after.defs {
        if !ctx.after.refs_to(*kind, name).is_empty() {
            continue;
        }
        let was_used = !ctx.before.refs_to(*kind, name).is_empty();
        let is_new = !ctx.before.defs.contains_key(&(*kind, name.clone()));
        if !(was_used || is_new) {
            continue;
        }
        let why = if was_used {
            "no longer referenced"
        } else {
            "added but never referenced"
        };
        let mut f = Finding::new(
            "NL-REF-002",
            Severity::Low,
            section_of_ref(*kind),
            format!("{} {} is {why}", kind.name(v), name),
            "Unused policy objects are harmless to forwarding but usually mean a reference was changed by mistake or cleanup is pending.",
        )
        .with(ev_a(al));
        for r in ctx.before.refs_to(*kind, name) {
            f = f.with(ev_b(&r.loc));
        }
        out.push(f);
    }
}

//! Syslog correlation helpers for troubleshooting: pick the log
//! lines that mention the peer/interface in question, with line numbers so
//! the explanation can quote them as evidence.

use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

static RE_MNEMONIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+)").unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct LogHit {
    pub line: usize,
    pub text: String,
    /// Cisco/Arista style facility-severity-mnemonic, e.g. BGP-5-ADJCHANGE.
    pub mnemonic: Option<String>,
    pub severity: Option<u8>,
}

/// Lines mentioning any of `terms` (case-insensitive), newest last, at most `max`.
pub fn correlate(text: &str, terms: &[&str], max: usize) -> Vec<LogHit> {
    let terms: Vec<String> = terms
        .iter()
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect();
    let mut hits: Vec<LogHit> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let low = l.to_ascii_lowercase();
            terms.iter().any(|t| low.contains(t.as_str()))
        })
        .map(|(i, l)| {
            let m = RE_MNEMONIC.captures(l);
            LogHit {
                line: i + 1,
                text: l.trim_end().to_string(),
                mnemonic: m.as_ref().map(|c| format!("{}-{}-{}", &c[1], &c[2], &c[3])),
                severity: m.as_ref().and_then(|c| c[2].parse().ok()),
            }
        })
        .collect();
    if hits.len() > max {
        hits.drain(..hits.len() - max);
    }
    hits
}

// ---------------------------------------------------------------------------
// Deterministic filtering for `netlens troubleshoot`.

static RE_IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static RE_IPV6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b").unwrap());
static RE_IF_CISCO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|GigabitEthernet|FastEthernet|Ethernet|Port-channel|Loopback|Tunnel|Vlan|Management|Te|Twe|Fo|Hu|Gi|Fa|Et|Po|Lo|Tu|Vl|Ma)(\d+(?:/\d+)*(?:\.\d+)?)\b").unwrap()
});
static RE_IF_JUNOS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b((?:ge|xe|et|mge)-\d+/\d+/\d+(?:\.\d+)?|(?:ae|lo|irb|em|fxp|me)\d+(?:\.\d+)?)\b")
        .unwrap()
});

const IF_NAMES: &[(&str, &str)] = &[
    ("tengigabitethernet", "Te"),
    ("twentyfivegige", "Twe"),
    ("fortygigabitethernet", "Fo"),
    ("hundredgige", "Hu"),
    ("gigabitethernet", "Gi"),
    ("fastethernet", "Fa"),
    ("ethernet", "Et"),
    ("port-channel", "Po"),
    ("loopback", "Lo"),
    ("tunnel", "Tu"),
    ("vlan", "Vl"),
    ("management", "Ma"),
];

/// Interface names in `text`, each with its long and short alias
/// (`Gi1/0/12` <-> `GigabitEthernet1/0/12`).
pub fn interface_terms(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for c in RE_IF_CISCO.captures_iter(text) {
        let pre = c[1].to_ascii_lowercase();
        let num = &c[2];
        for (long, short) in IF_NAMES {
            if pre == *long || pre == short.to_ascii_lowercase() {
                out.push(format!("{long}{num}"));
                out.push(format!("{}{num}", short.to_ascii_lowercase()));
            }
        }
    }
    for m in RE_IF_JUNOS.find_iter(text) {
        out.push(m.as_str().to_string());
        // xe-0/1/2.0 -> also match the physical port
        if let Some((phys, _)) = m.as_str().split_once('.') {
            out.push(phys.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// IP addresses in `text`.
pub fn ip_terms(text: &str) -> Vec<String> {
    let mut out: Vec<String> = RE_IPV4
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .filter(|ip| ip.split('.').all(|o| o.parse::<u8>().is_ok()))
        .collect();
    out.extend(
        RE_IPV6
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .filter(|s| s.parse::<std::net::Ipv6Addr>().is_ok()),
    );
    out.sort();
    out.dedup();
    out
}

/// Keyword groups: if the symptom mentions a trigger, these log terms are
/// relevant too.
const KEYWORD_GROUPS: &[(&[&str], &[&str])] = &[
    (&["bgp"], &["BGP"]),
    (&["ospf", "exstart", "adjacenc"], &["OSPF"]),
    (&["isis", "is-is"], &["ISIS", "CLNS"]),
    (
        &[
            "interface",
            "link",
            "port",
            "down",
            "flap",
            "no network",
            "led",
            "errdisable",
            "err-disable",
            "cable",
            "optic",
            "crc",
            "errors",
            "power",
        ],
        &[
            "UPDOWN",
            "LINK",
            "LINEPROTO",
            "ERR_DISABLE",
            "err-disable",
            "SNMP_TRAP_LINK",
            "ILPOWER",
            "TRANSCEIVER",
            "CRC",
        ],
    ),
];

/// Configuration changes are always relevant ("what changed?").
const ALWAYS_TERMS: &[&str] = &[
    "CONFIG_I",
    "UI_COMMIT",
    "UI_COMMIT_COMPLETED",
    "Configured from",
];

/// Terms derived from a free-text symptom: addresses, interfaces, protocol
/// keywords, plus configuration-change markers.
pub fn symptom_terms(symptom: &str) -> Vec<String> {
    let low = symptom.to_ascii_lowercase();
    let mut out = ip_terms(symptom);
    out.extend(interface_terms(symptom));
    for (triggers, terms) in KEYWORD_GROUPS {
        if triggers.iter().any(|t| low.contains(t)) {
            out.extend(terms.iter().map(|t| t.to_string()));
        }
    }
    out.extend(ALWAYS_TERMS.iter().map(|t| t.to_string()));
    out.sort();
    out.dedup();
    out
}

/// Addresses and interfaces named in an (approved) command.
pub fn command_terms(cmd: &str) -> Vec<String> {
    let mut out = ip_terms(cmd);
    out.extend(interface_terms(cmd));
    out
}

/// Whole-token, case-insensitive match: `192.0.2.1` does not match
/// `192.0.2.10`, `Gi1/0/1` does not match `Gi1/0/12`.
pub fn matches_term(line: &str, term: &str) -> bool {
    let l = line.to_ascii_lowercase();
    let t = term.to_ascii_lowercase();
    if t.is_empty() {
        return false;
    }
    let lb = l.as_bytes();
    let mut from = 0;
    while let Some(pos) = l[from..].find(&t) {
        let start = from + pos;
        let end = start + t.len();
        let before_ok = start == 0 || !lb[start - 1].is_ascii_alphanumeric();
        let after_ok = end >= lb.len()
            || (!lb[end].is_ascii_alphanumeric()
                && !(matches!(lb[end], b'.' | b'/')
                    && lb.get(end + 1).is_some_and(|c| c.is_ascii_digit())
                    && t.as_bytes().last().is_some_and(|c| c.is_ascii_digit())));
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Incremental, deterministic syslog filter. Lines are shown to the model
/// once, with stable ids `L<line number>`.
#[derive(Debug, Clone)]
pub struct SyslogFilter {
    lines: Vec<String>,
    terms: Vec<String>,
    shown: std::collections::BTreeSet<usize>,
    max_total: usize,
}

impl SyslogFilter {
    pub fn new(text: &str, max_total: usize) -> Self {
        SyslogFilter {
            lines: text.lines().map(|l| l.trim_end().to_string()).collect(),
            terms: Vec::new(),
            shown: Default::default(),
            max_total,
        }
    }

    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    pub fn total_lines(&self) -> usize {
        self.lines.len()
    }

    pub fn shown_count(&self) -> usize {
        self.shown.len()
    }

    /// Text of a shown line (1-based), if it was shown.
    pub fn shown_line(&self, line: usize) -> Option<&str> {
        if self.shown.contains(&line) {
            self.lines.get(line - 1).map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Add terms; return the newly matching lines (oldest first).
    ///
    /// When more lines match than the budget allows, lines matching a
    /// specific term (an address, an interface, a config-change marker) win
    /// over lines that only match a protocol keyword, and within each tier
    /// the oldest half (the onset) and the newest half are kept.
    pub fn add_terms(&mut self, terms: &[String]) -> Vec<LogHit> {
        for t in terms {
            if !t.trim().is_empty() && !self.terms.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                self.terms.push(t.clone());
            }
        }
        let specific = |t: &String| {
            t.chars().any(|c| c.is_ascii_digit())
                || ALWAYS_TERMS.iter().any(|a| a.eq_ignore_ascii_case(t))
        };
        let (mut tier1, mut tier2) = (Vec::new(), Vec::new());
        for n in 1..=self.lines.len() {
            if self.shown.contains(&n) {
                continue;
            }
            let l = &self.lines[n - 1];
            if self
                .terms
                .iter()
                .filter(|t| specific(t))
                .any(|t| matches_term(l, t))
            {
                tier1.push(n);
            } else if self.terms.iter().any(|t| matches_term(l, t)) {
                tier2.push(n);
            }
        }
        fn pick(v: Vec<usize>, budget: usize) -> Vec<usize> {
            if v.len() <= budget {
                return v;
            }
            let head = budget / 2;
            let tail = budget - head;
            let mut out: Vec<usize> = v[..head].to_vec();
            out.extend_from_slice(&v[v.len() - tail..]);
            out
        }
        let budget = self.max_total.saturating_sub(self.shown.len());
        let mut new = pick(tier1, budget);
        let left = budget.saturating_sub(new.len());
        new.extend(pick(tier2, left));
        new.sort_unstable();
        new.iter()
            .map(|&n| {
                self.shown.insert(n);
                let l = &self.lines[n - 1];
                let m = RE_MNEMONIC.captures(l);
                LogHit {
                    line: n,
                    text: l.clone(),
                    mnemonic: m.as_ref().map(|c| format!("{}-{}-{}", &c[1], &c[2], &c[3])),
                    severity: m.as_ref().and_then(|c| c[2].parse().ok()),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_relevant_lines() {
        let log = "Oct  7 10:00:01 r1 %LINK-3-UPDOWN: Interface Gi2, changed state to down\nOct  7 10:00:02 r1 %BGP-5-ADJCHANGE: neighbor 198.51.100.1 Down BGP Notification sent\nOct  7 10:00:03 r1 %SYS-5-CONFIG_I: Configured from console\n";
        let h = correlate(log, &["198.51.100.1"], 10);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].line, 2);
        assert_eq!(h[0].mnemonic.as_deref(), Some("BGP-5-ADJCHANGE"));
        assert_eq!(h[0].severity, Some(5));
        assert_eq!(correlate(log, &["gi2", "bgp"], 1).len(), 1);
    }

    #[test]
    fn whole_token_matching() {
        assert!(matches_term("neighbor 192.0.2.1 Down", "192.0.2.1"));
        assert!(!matches_term("neighbor 192.0.2.10 Down", "192.0.2.1"));
        assert!(matches_term("from 203.0.113.9:52114 wrong", "203.0.113.9"));
        assert!(!matches_term("on Gi1/0/12 now", "Gi1/0/1"));
        assert!(matches_term("%BGP-5-ADJCHANGE: x", "bgp"));
        assert!(matches_term("RPD_BGP_NEIGHBOR_STATE_CHANGED", "BGP"));
        assert!(!matches_term("BGPX", "bgp"));
    }

    #[test]
    fn terms_from_symptom_and_commands() {
        let t = symptom_terms("BGP to 192.0.2.0 flapping on Et47 since 07:08");
        assert!(t.contains(&"192.0.2.0".to_string()));
        assert!(t.contains(&"ethernet47".to_string()) && t.contains(&"et47".to_string()));
        assert!(t.contains(&"BGP".to_string()) && t.contains(&"UI_COMMIT".to_string()));
        assert!(!t.iter().any(|x| x == "07:08"));
        let c = command_terms("show interfaces GigabitEthernet0/0/1");
        assert!(c.contains(&"gi0/0/1".to_string()));
        assert!(
            interface_terms("show interfaces terse xe-0/1/2.0").contains(&"xe-0/1/2".to_string())
        );
    }

    #[test]
    fn filter_is_incremental_and_capped() {
        let log = "a r1 %LINK-3-UPDOWN: Interface Gi1/0/12, changed state to down\nb r1 %SYS-5-CONFIG_I: Configured from console\nc r1 %BGP-5-ADJCHANGE: neighbor 192.0.2.1 Down\nd r1 %BGP-5-ADJCHANGE: neighbor 192.0.2.1 Up\n";
        let mut f = SyslogFilter::new(log, 3);
        let first = f.add_terms(&symptom_terms("bgp 192.0.2.1 down"));
        // 4 matches, budget 3: newest kept
        assert_eq!(
            first.iter().map(|h| h.line).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        assert!(f
            .add_terms(&command_terms("show interfaces Gi1/0/12"))
            .is_empty());
        assert_eq!(
            f.shown_line(3).unwrap(),
            "c r1 %BGP-5-ADJCHANGE: neighbor 192.0.2.1 Down"
        );
        assert!(f.shown_line(1).is_none());
    }

    #[test]
    fn over_budget_keeps_onset_and_newest() {
        let mut log = String::new();
        for i in 0..20 {
            log.push_str(&format!("t{i} r1 BGP_IO_ERROR peer 192.0.2.1 x\n"));
        }
        log.push_str("t20 r1 %BGP-5-ADJCHANGE: neighbor 192.0.2.9 Up\n");
        let mut f = SyslogFilter::new(&log, 4);
        let hits = f.add_terms(&symptom_terms("bgp peer 192.0.2.1"));
        // 20 address lines beat the keyword-only line; onset + newest kept
        assert_eq!(
            hits.iter().map(|h| h.line).collect::<Vec<_>>(),
            vec![1, 2, 19, 20]
        );
    }
}

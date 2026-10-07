//! Syslog correlation helpers for troubleshooting (phase 2): pick the log
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
}

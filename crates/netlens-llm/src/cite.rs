//! Citation validation: every claim must cite evidence ids that exist.
//!
//! The model is asked for three sections of `- ` bullets, each bullet ending
//! with citations like `[F2]` or `[F1][B3]` (also `[F1, F2]`). A claim is one
//! bullet (or one paragraph line). Claims citing nothing valid are dropped;
//! unknown ids are stripped and reported.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::LazyLock;

pub const SECTIONS: [&str; 3] = ["SUMMARY", "BLAST RADIUS", "ROLLBACK"];

static RE_HEADING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:#{1,6}\s*)?(?:\*\*|__)?\s*(summary|risk summary|blast radius|rollback(?: notes)?|rollback snippet)\s*(?:\*\*|__)?\s*:?\s*(?:\*\*|__)?\s*(.*)$").unwrap()
});
static RE_BULLET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:[-*•]|\d+[.)])\s+(.*)$").unwrap());
static RE_CITE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[\s*([A-Za-z]\d+(?:\s*[,;]\s*[A-Za-z]\d+)*)\s*\]").unwrap());

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Claim {
    pub section: String,
    pub text: String,
    pub citations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Dropped {
    pub section: String,
    pub text: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Validated {
    pub claims: Vec<Claim>,
    pub dropped: Vec<Dropped>,
    /// Unknown ids that were stripped from otherwise-cited claims.
    pub unknown_ids: Vec<String>,
}

impl Validated {
    pub fn section(&self, name: &str) -> Vec<&Claim> {
        self.claims.iter().filter(|c| c.section == name).collect()
    }
    pub fn total(&self) -> usize {
        self.claims.len() + self.dropped.len()
    }
}

fn canonical_section(h: &str) -> &'static str {
    let h = h.to_ascii_lowercase();
    if h.starts_with("blast") {
        "BLAST RADIUS"
    } else if h.starts_with("rollback") {
        "ROLLBACK"
    } else {
        "SUMMARY"
    }
}

fn clean(s: &str) -> String {
    s.replace("**", "")
        .replace("__", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract ids cited in `text`.
pub fn citations_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for c in RE_CITE.captures_iter(text) {
        for id in c[1].split([',', ';']) {
            let id = id.trim().to_ascii_uppercase();
            if !id.is_empty() && !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

pub fn validate(text: &str, valid: &BTreeSet<String>) -> Validated {
    // 1. Split into (section, claim text) units.
    let mut units: Vec<(String, String)> = Vec::new();
    let mut section = "SUMMARY".to_string();
    let mut open = false; // can the next indented line continue the last unit?
    for line in text.lines() {
        if line.trim().is_empty() {
            open = false;
            continue;
        }
        if let Some(c) = RE_HEADING.captures(line) {
            // Only treat as heading when short (avoid "Summary of the risk is ...").
            let rest = c.get(2).map(|m| m.as_str()).unwrap_or("");
            let is_heading = rest.is_empty() || line.contains(':');
            if is_heading {
                section = canonical_section(&c[1]).to_string();
                if !rest.trim().is_empty() {
                    units.push((section.clone(), rest.to_string()));
                    open = true;
                } else {
                    open = false;
                }
                continue;
            }
        }
        if let Some(c) = RE_BULLET.captures(line) {
            units.push((section.clone(), c[1].to_string()));
            open = true;
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if open && indented {
            if let Some(last) = units.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
                continue;
            }
        }
        units.push((section.clone(), line.to_string()));
        open = true;
    }
    // 2. Validate each unit.
    let mut v = Validated::default();
    for (section, raw) in units {
        let text = clean(&raw);
        if text.is_empty() || text == "-" {
            continue;
        }
        let ids = citations_in(&text);
        let (good, bad): (Vec<String>, Vec<String>) =
            ids.into_iter().partition(|i| valid.contains(i));
        if good.is_empty() {
            let reason = if bad.is_empty() {
                "no citation".to_string()
            } else {
                format!(
                    "cites unknown evidence {}",
                    bad.iter()
                        .map(|b| format!("[{b}]"))
                        .collect::<Vec<_>>()
                        .join("")
                )
            };
            v.dropped.push(Dropped {
                section,
                text,
                reason,
            });
            continue;
        }
        let mut t = text.clone();
        for b in &bad {
            if !v.unknown_ids.contains(b) {
                v.unknown_ids.push(b.clone());
            }
            t = t.replace(&format!("[{b}]"), "");
        }
        v.claims.push(Claim {
            section,
            text: clean(&t),
            citations: good,
        });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn keeps_cited_drops_uncited_and_unknown() {
        let text = "SUMMARY:\n- BGP to ISP-A goes down [F2]\n- Everything is fine.\n- Upstream must change filters [F99]\n\nBLAST RADIUS:\n- Inbound HTTPS is blocked [F5][C3]\n* Mixed [F1, F42]\n\nROLLBACK:\n1. Apply the rollback [R1]\n";
        let v = validate(text, &ids(&["F1", "F2", "F5", "C3", "R1"]));
        assert_eq!(v.claims.len(), 4, "{v:#?}");
        assert_eq!(v.dropped.len(), 2);
        assert_eq!(v.dropped[0].reason, "no citation");
        assert!(v.dropped[1].reason.contains("[F99]"));
        assert_eq!(v.section("BLAST RADIUS").len(), 2);
        let mixed = v
            .claims
            .iter()
            .find(|c| c.text.starts_with("Mixed"))
            .unwrap();
        assert_eq!(mixed.citations, vec!["F1"]);
        assert_eq!(v.unknown_ids, vec!["F42"]);
        assert_eq!(v.section("ROLLBACK")[0].citations, vec!["R1"]);
    }

    #[test]
    fn markdown_headings_and_continuations() {
        let text = "## Summary\n- **High risk**: the session drops\n  because the neighbor is shut [F1]\n### Blast radius:\n- all ISP-A prefixes [F1]\n**Rollback:** re-enable the neighbor [R1]\n";
        let v = validate(text, &ids(&["F1", "R1"]));
        assert_eq!(v.claims.len(), 3, "{v:#?}");
        assert!(v.claims[0].text.contains("because the neighbor is shut"));
        assert!(!v.claims[0].text.contains("**"));
        assert_eq!(v.claims[2].section, "ROLLBACK");
        assert!(v.dropped.is_empty());
    }

    #[test]
    fn text_before_any_heading_is_summary_and_case_insensitive_ids() {
        let v = validate("The change is risky [f1].", &ids(&["F1"]));
        assert_eq!(v.claims[0].section, "SUMMARY");
        assert_eq!(v.claims[0].citations, vec!["F1"]);
    }

    #[test]
    fn empty_answer() {
        let v = validate("", &ids(&["F1"]));
        assert_eq!(v.total(), 0);
    }
}

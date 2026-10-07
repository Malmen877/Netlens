//! Semantic diff: multiset comparison of flattened statements, grouped by
//! section, with block folding (a removed block hides its removed children).

use crate::model::{Config, Stmt};
use crate::section::{classify, Section};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Removed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    /// Stable id within one report, e.g. "C3".
    pub id: String,
    pub kind: ChangeKind,
    pub section: Section,
    /// Header chain + line (IOS/EOS) or a single set-path (Junos).
    pub path: Vec<String>,
    /// Line in the before file (removed) or after file (added).
    pub line: usize,
    /// Number of descendant lines folded into this change (whole block).
    pub folded: usize,
}

impl Change {
    pub fn text(&self) -> &str {
        self.path.last().map(String::as_str).unwrap_or("")
    }
    pub fn parent(&self) -> &[String] {
        &self.path[..self.path.len().saturating_sub(1)]
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Diff {
    pub changes: Vec<Change>,
    pub added: usize,
    pub removed: usize,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn sections(&self) -> Vec<(Section, usize, usize)> {
        let mut m: Vec<(Section, usize, usize)> = Vec::new();
        for c in &self.changes {
            let n = 1 + c.folded;
            let idx = match m.iter().position(|(s, _, _)| *s == c.section) {
                Some(i) => i,
                None => {
                    m.push((c.section, 0, 0));
                    m.len() - 1
                }
            };
            match c.kind {
                ChangeKind::Added => m[idx].1 += n,
                ChangeKind::Removed => m[idx].2 += n,
            }
        }
        m.sort_by_key(|(s, _, _)| *s);
        m
    }
}

fn key(s: &Stmt) -> String {
    s.path.join("\u{1f}")
}

/// Raw statement-level differences (unfolded).
pub fn raw_diff<'a>(before: &'a Config, after: &'a Config) -> (Vec<&'a Stmt>, Vec<&'a Stmt>) {
    let mut bcount: HashMap<String, Vec<&Stmt>> = HashMap::new();
    for s in &before.stmts {
        bcount.entry(key(s)).or_default().push(s);
    }
    let mut acount: HashMap<String, Vec<&Stmt>> = HashMap::new();
    for s in &after.stmts {
        acount.entry(key(s)).or_default().push(s);
    }
    let mut removed = Vec::new();
    for (k, bs) in &bcount {
        let a = acount.get(k).map(|v| v.len()).unwrap_or(0);
        if bs.len() > a {
            removed.extend(bs[a..].iter().copied());
        }
    }
    let mut added = Vec::new();
    for (k, as_) in &acount {
        let b = bcount.get(k).map(|v| v.len()).unwrap_or(0);
        if as_.len() > b {
            added.extend(as_[b..].iter().copied());
        }
    }
    removed.sort_by_key(|s| (s.line, s.path.len()));
    added.sort_by_key(|s| (s.line, s.path.len()));
    (removed, added)
}

fn fold(stmts: &[&Stmt]) -> Vec<(Stmt, usize)> {
    let mut out: Vec<(Stmt, usize)> = Vec::new();
    for s in stmts {
        if let Some(last) = out
            .iter_mut()
            .rev()
            .find(|(p, _)| p.path.len() < s.path.len() && s.path.starts_with(&p.path))
        {
            last.1 += 1;
            continue;
        }
        out.push(((*s).clone(), 0));
    }
    out
}

/// Compute the semantic diff between two configs of the same vendor.
pub fn diff(before: &Config, after: &Config) -> Diff {
    let vendor = after.vendor;
    let (removed, added) = raw_diff(before, after);
    let mut changes: Vec<Change> = Vec::new();
    for (s, folded) in fold(&removed) {
        changes.push(Change {
            id: String::new(),
            kind: ChangeKind::Removed,
            section: classify(&s, vendor),
            path: s.path,
            line: s.line,
            folded,
        });
    }
    for (s, folded) in fold(&added) {
        changes.push(Change {
            id: String::new(),
            kind: ChangeKind::Added,
            section: classify(&s, vendor),
            path: s.path,
            line: s.line,
            folded,
        });
    }
    // Stable order: section, then parent context, removed before added, line.
    changes.sort_by(|a, b| {
        a.section
            .cmp(&b.section)
            .then_with(|| a.parent().cmp(b.parent()))
            .then_with(|| (a.kind == ChangeKind::Added).cmp(&(b.kind == ChangeKind::Added)))
            .then_with(|| a.line.cmp(&b.line))
    });
    for (i, c) in changes.iter_mut().enumerate() {
        c.id = format!("C{}", i + 1);
    }
    Diff {
        added: added.len(),
        removed: removed.len(),
        changes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;
    use crate::vendor::Vendor;

    #[test]
    fn detects_added_removed_and_folds_blocks() {
        let b = "interface Gi1\n ip address 10.0.0.1 255.255.255.0\ninterface Gi2\n description old\n mtu 1500\n";
        let a = "interface Gi1\n ip address 10.0.0.1 255.255.255.0\n shutdown\n";
        let d = diff(&parse(b, Vendor::CiscoIos), &parse(a, Vendor::CiscoIos));
        assert_eq!(d.removed, 3);
        assert_eq!(d.added, 1);
        assert_eq!(d.changes.len(), 2);
        let rem = d
            .changes
            .iter()
            .find(|c| c.kind == ChangeKind::Removed)
            .unwrap();
        assert_eq!(rem.text(), "interface Gi2");
        assert_eq!(rem.folded, 2);
        let add = d
            .changes
            .iter()
            .find(|c| c.kind == ChangeKind::Added)
            .unwrap();
        assert_eq!(add.path, vec!["interface Gi1", "shutdown"]);
        assert_eq!(add.line, 3);
        assert_eq!(d.changes[0].id, "C1");
    }

    #[test]
    fn identical_configs_have_empty_diff() {
        let t = "hostname r1\ninterface Gi1\n shutdown\n";
        let d = diff(&parse(t, Vendor::CiscoIos), &parse(t, Vendor::CiscoIos));
        assert!(d.is_empty());
    }

    #[test]
    fn whitespace_only_changes_ignored() {
        let d = diff(
            &parse("interface Gi1\n description  a   b\n", Vendor::CiscoIos),
            &parse("interface Gi1\n  description a b\n", Vendor::CiscoIos),
        );
        assert!(d.is_empty());
    }

    #[test]
    fn junos_diff() {
        let b = "set interfaces ge-0/0/0 mtu 1500\nset system host-name r1\n";
        let a = "set interfaces ge-0/0/0 mtu 9000\nset system host-name r1\n";
        let d = diff(&parse(b, Vendor::Junos), &parse(a, Vendor::Junos));
        assert_eq!(d.changes.len(), 2);
        assert!(d.changes.iter().all(|c| c.section == Section::Interfaces));
    }
}

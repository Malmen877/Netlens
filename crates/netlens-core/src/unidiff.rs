//! Unified-diff input (`netlens review --diff change.diff`).
//!
//! Each hunk is split into a before fragment (context + `-` lines) and an
//! after fragment (context + `+` lines) with real line numbers. For
//! IOS/EOS, git's hunk-header context (the enclosing top-level line, e.g.
//! `@@ ... @@ interface Gi1`) is re-attached so indented lines keep their
//! parent block.

use crate::model::{flatten, Config};
use crate::parse::parse_lines;
use crate::vendor::Vendor;

#[derive(Debug, Clone)]
pub struct Hunk {
    pub old_start: usize,
    pub new_start: usize,
    pub context: Option<String>,
    pub before: Vec<(usize, String)>,
    pub after: Vec<(usize, String)>,
}

#[derive(Debug, Clone)]
pub struct UniDiff {
    pub old_name: Option<String>,
    pub new_name: Option<String>,
    pub hunks: Vec<Hunk>,
}

impl UniDiff {
    /// All after-side text (for vendor detection).
    pub fn after_text(&self) -> String {
        let mut s = String::new();
        for h in &self.hunks {
            for (_, l) in &h.after {
                s.push_str(l);
                s.push('\n');
            }
        }
        s
    }
}

fn parse_range(s: &str) -> Option<usize> {
    let s = s.trim_start_matches(['-', '+']);
    s.split(',').next()?.parse().ok()
}

pub fn parse_unified(text: &str) -> Result<UniDiff, String> {
    let mut d = UniDiff {
        old_name: None,
        new_name: None,
        hunks: Vec::new(),
    };
    let mut files = 0;
    let mut cur: Option<Hunk> = None;
    let (mut bno, mut ano) = (0usize, 0usize);
    for raw in text.lines() {
        if let Some(rest) = raw.strip_prefix("+++ ") {
            files += 1;
            if files > 1 {
                return Err(
                    "the diff touches more than one file; review one device config per run".into(),
                );
            }
            d.new_name = Some(
                rest.split('\t')
                    .next()
                    .unwrap_or(rest)
                    .trim()
                    .trim_start_matches("b/")
                    .to_string(),
            );
            if let Some(h) = cur.take() {
                d.hunks.push(h);
            }
            continue;
        }
        if let Some(rest) = raw.strip_prefix("--- ") {
            if cur.is_none() || raw.starts_with("--- a/") || raw.starts_with("--- /") {
                if let Some(h) = cur.take() {
                    d.hunks.push(h);
                }
                d.old_name = Some(
                    rest.split('\t')
                        .next()
                        .unwrap_or(rest)
                        .trim()
                        .trim_start_matches("a/")
                        .to_string(),
                );
                continue;
            }
        }
        if raw.starts_with("diff ") || raw.starts_with("index ") {
            continue;
        }
        if let Some(rest) = raw.strip_prefix("@@") {
            if let Some(h) = cur.take() {
                d.hunks.push(h);
            }
            let end = rest
                .find("@@")
                .ok_or_else(|| format!("malformed hunk header: {raw}"))?;
            let ranges: Vec<&str> = rest[..end].split_whitespace().collect();
            if ranges.len() < 2 {
                return Err(format!("malformed hunk header: {raw}"));
            }
            let old_start =
                parse_range(ranges[0]).ok_or_else(|| format!("malformed hunk header: {raw}"))?;
            let new_start =
                parse_range(ranges[1]).ok_or_else(|| format!("malformed hunk header: {raw}"))?;
            let ctx = rest[end + 2..].trim_end();
            let ctx = ctx.strip_prefix(' ').unwrap_or(ctx);
            bno = old_start;
            ano = new_start;
            cur = Some(Hunk {
                old_start,
                new_start,
                context: if ctx.trim().is_empty() {
                    None
                } else {
                    Some(ctx.to_string())
                },
                before: Vec::new(),
                after: Vec::new(),
            });
            continue;
        }
        let Some(h) = cur.as_mut() else { continue };
        if raw.starts_with('\\') {
            continue; // "\ No newline at end of file"
        }
        let (tag, body) = raw.split_at(raw.len().min(1));
        match tag {
            "+" => {
                h.after.push((ano, body.to_string()));
                ano += 1;
            }
            "-" => {
                h.before.push((bno, body.to_string()));
                bno += 1;
            }
            " " | "" => {
                h.before.push((bno, body.to_string()));
                h.after.push((ano, body.to_string()));
                bno += 1;
                ano += 1;
            }
            _ => {}
        }
    }
    if let Some(h) = cur.take() {
        d.hunks.push(h);
    }
    if d.hunks.is_empty() {
        return Err("no unified-diff hunks found (expected lines starting with '@@'); use 'diff -u' or 'git diff'".into());
    }
    Ok(d)
}

/// Build partial before/after configs from the diff hunks.
pub fn to_configs(d: &UniDiff, vendor: Vendor) -> (Config, Config) {
    let mut before = Config::empty(vendor);
    let mut after = Config::empty(vendor);
    before.partial = true;
    after.partial = true;
    for h in &d.hunks {
        for (side, cfg) in [(&h.before, &mut before), (&h.after, &mut after)] {
            let mut lines: Vec<(usize, &str)> =
                side.iter().map(|(n, l)| (*n, l.as_str())).collect();
            if vendor.is_ios_like() {
                let first_indented = lines
                    .iter()
                    .find(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('!'))
                    .map(|(_, l)| l.starts_with(' ') || l.starts_with('\t'))
                    .unwrap_or(false);
                if let Some(ctx) = &h.context {
                    if first_indented && !ctx.starts_with(' ') {
                        lines.insert(0, (0, ctx.as_str()));
                    }
                }
            }
            let part = parse_lines(&lines, vendor);
            for root in part.tree {
                // Merge repeated synthetic parents (same block in two hunks).
                match cfg
                    .tree
                    .iter_mut()
                    .find(|r| r.text == root.text && (r.line == 0 || root.line == 0))
                {
                    Some(existing) => {
                        if existing.line == 0 {
                            existing.line = root.line;
                        }
                        existing.children.extend(root.children);
                    }
                    None => cfg.tree.push(root),
                }
            }
            cfg.stmts.extend(part.stmts);
        }
    }
    if vendor.is_ios_like() {
        before.stmts = flatten(&before.tree);
        after.stmts = flatten(&after.tree);
    }
    (before, after)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIFF: &str = "diff --git a/r1.cfg b/r1.cfg\nindex 111..222 100644\n--- a/r1.cfg\n+++ b/r1.cfg\n@@ -10,4 +10,5 @@ router bgp 65001\n  neighbor 10.0.0.2 remote-as 65002\n- neighbor 10.0.0.2 route-map OLD out\n+ neighbor 10.0.0.2 route-map NEW out\n+ neighbor 10.0.0.2 shutdown\n  neighbor 10.0.0.3 remote-as 65003\n";

    #[test]
    fn parses_hunks_with_line_numbers() {
        let d = parse_unified(DIFF).unwrap();
        assert_eq!(d.old_name.as_deref(), Some("r1.cfg"));
        assert_eq!(d.hunks.len(), 1);
        let h = &d.hunks[0];
        assert_eq!(h.context.as_deref(), Some("router bgp 65001"));
        assert_eq!(h.before.len(), 3);
        assert_eq!(h.after.len(), 4);
        assert_eq!(
            h.before[1],
            (11, " neighbor 10.0.0.2 route-map OLD out".to_string())
        );
        assert_eq!(h.after[2], (12, " neighbor 10.0.0.2 shutdown".to_string()));
    }

    #[test]
    fn reattaches_context_for_ios() {
        let d = parse_unified(DIFF).unwrap();
        let (b, a) = to_configs(&d, Vendor::CiscoIos);
        assert!(a.partial);
        assert_eq!(a.tree.len(), 1);
        assert_eq!(a.tree[0].text, "router bgp 65001");
        assert_eq!(a.tree[0].line, 0);
        assert_eq!(a.tree[0].children.len(), 4);
        assert_eq!(b.tree[0].children.len(), 3);
    }

    #[test]
    fn rejects_non_diff_and_multi_file() {
        assert!(parse_unified("hostname r1\n").is_err());
        let two = format!("{DIFF}--- a/r2.cfg\n+++ b/r2.cfg\n@@ -1 +1 @@\n-a\n+b\n");
        assert!(parse_unified(&two)
            .unwrap_err()
            .contains("more than one file"));
    }
}

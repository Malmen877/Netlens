//! Shared rendering helpers for findings.

use crate::style::{wrap, Style};
use netlens_core::redact::Redactor;
use netlens_core::Finding;

/// Copy of findings with secrets in titles/evidence replaced by placeholders.
pub fn redact_findings(fs: &[Finding], r: &mut Redactor) -> Vec<Finding> {
    fs.iter()
        .map(|f| {
            let mut f = f.clone();
            f.title = r.redact_line(&f.title);
            for e in f.evidence.iter_mut() {
                e.text = r.redact_line(&e.text);
            }
            f
        })
        .collect()
}

pub fn finding_text(f: &Finding, s: &Style) -> String {
    let mut out = format!(
        " {}  {} {}  {}\n",
        s.bold(&format!("{:<4}", f.id)),
        s.sev(f.severity),
        s.dim(&format!("{:<12}", f.rule)),
        s.bold(&f.title)
    );
    for e in &f.evidence {
        let loc = if e.line > 0 {
            format!("{}:{}", e.side.as_str(), e.line)
        } else {
            format!("{}:-", e.side.as_str())
        };
        out.push_str(&format!(
            "       {}  {}\n",
            s.cyan(&format!("{loc:<11}")),
            e.text.trim_end()
        ));
    }
    out.push_str(&s.dim(wrap(&f.explanation, 100, "       ").trim_end_matches('\n')));
    out.push('\n');
    out
}

pub fn counts_line(fs: &[Finding], s: &Style) -> String {
    let c = netlens_core::finding::SeverityCounts::of(fs);
    let mut parts = Vec::new();
    for (n, sev) in [
        (c.critical, netlens_core::Severity::Critical),
        (c.high, netlens_core::Severity::High),
        (c.medium, netlens_core::Severity::Medium),
        (c.low, netlens_core::Severity::Low),
        (c.info, netlens_core::Severity::Info),
    ] {
        if n > 0 {
            parts.push(format!("{n} {}", sev.as_str()));
        }
    }
    if parts.is_empty() {
        s.green("none")
    } else {
        parts.join(", ")
    }
}

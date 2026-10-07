//! The review prompt. Everything in it has already been redacted (and
//! optionally IP-masked) by the caller.

use crate::client::ChatMessage;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    /// Citation id: F# (rule finding), B# (Batfish), C# (diff change), R1 (rollback).
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewContext {
    pub vendor: String,
    pub source: String,
    pub items: Vec<EvidenceItem>,
    pub notes: Vec<String>,
}

impl ReviewContext {
    pub fn ids(&self) -> std::collections::BTreeSet<String> {
        self.items.iter().map(|i| i.id.clone()).collect()
    }
}

pub const SYSTEM_PROMPT: &str = "You are netlens, a careful senior network engineer reviewing a proposed configuration change before it is deployed. You are read-only: never propose configuration commands other than the provided rollback.

Rules:
1. Use ONLY the evidence items provided. Each item starts with an id in square brackets: [F1] rule findings, [B1] Batfish results, [C1] raw config changes, [R1] the deterministic rollback.
2. Every bullet MUST end with one or more citations of those ids, e.g. \"... drops the ISP session [F2][C6]\". Bullets without a valid citation are automatically discarded.
3. Do not invent devices, addresses, prefixes, customers or impacts that the cited evidence does not support. If impact is uncertain, say so.
4. Secrets appear as <redacted:...> and addresses may appear as IP4_n / IP6_n placeholders; copy them exactly, never guess real values.
5. One claim per bullet, at most 5 bullets per section, plain language for an on-call engineer.

Answer with exactly these three sections and '- ' bullets:
SUMMARY:
BLAST RADIUS:
ROLLBACK:";

pub fn build_messages(ctx: &ReviewContext) -> Vec<ChatMessage> {
    let mut u = String::new();
    u.push_str(&format!("Vendor: {}\nChange: {}\n", ctx.vendor, ctx.source));
    for n in &ctx.notes {
        u.push_str(&format!("Note: {n}\n"));
    }
    u.push_str("\nEVIDENCE:\n");
    for it in &ctx.items {
        u.push_str(&format!("[{}] {}\n", it.id, it.text));
    }
    u.push_str("\nWrite the review now. Remember: every bullet ends with citations like [F1].");
    vec![ChatMessage::system(SYSTEM_PROMPT), ChatMessage::user(u)]
}

/// The exact text sent (for hashing/size in the audit log).
pub fn prompt_text(messages: &[ChatMessage]) -> String {
    messages
        .iter()
        .map(|m| format!("<{}>\n{}", m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Limits that keep the prompt small enough for a 14B model's context.
pub const MAX_CHANGES: usize = 60;
pub const MAX_ROLLBACK_LINES: usize = 60;

/// Inputs for [`build_context`]. Everything is raw (unredacted); redaction
/// and optional IP masking happen here so nothing can skip them.
pub struct ContextInput<'a> {
    pub vendor: netlens_core::Vendor,
    pub source: &'a str,
    pub findings: &'a [netlens_core::Finding],
    pub changes: &'a [netlens_core::diff::Change],
    pub rollback: &'a [String],
    pub notes: &'a [String],
}

/// Build the evidence list sent to the model: redact first, then mask.
pub fn build_context(
    input: &ContextInput,
    redactor: &mut netlens_core::redact::Redactor,
    mut masker: Option<&mut netlens_core::ipmask::IpMasker>,
) -> ReviewContext {
    let mut clean = |s: &str, ctx: &str, r: &mut netlens_core::redact::Redactor| -> String {
        let red = if s.contains('\n') {
            r.redact_text(s)
        } else {
            r.redact_line_ctx(s, ctx)
        };
        match masker.as_deref_mut() {
            Some(m) => m.mask(&red),
            None => red,
        }
    };
    let mut items = Vec::new();
    for f in input.findings {
        let mut t = format!(
            "severity={} rule={} section={} | {}\n    why: {}",
            f.severity.as_str(),
            f.rule,
            serde_json::to_value(f.section)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            f.title,
            f.explanation
        );
        for e in &f.evidence {
            let loc = if e.line > 0 {
                format!("{}:{}", e.side.as_str(), e.line)
            } else {
                e.side.as_str().to_string()
            };
            t.push_str(&format!("\n    evidence {loc}: {}", e.text.trim()));
        }
        items.push(EvidenceItem {
            id: f.id.clone(),
            text: clean(&t, "", redactor),
        });
    }
    for c in input.changes.iter().take(MAX_CHANGES) {
        let kind = match c.kind {
            netlens_core::diff::ChangeKind::Added => "added",
            netlens_core::diff::ChangeKind::Removed => "removed",
        };
        let side = if kind == "added" { "after" } else { "before" };
        let parent = c.parent().join(" > ");
        let leaf = if input.vendor == netlens_core::Vendor::Junos {
            netlens_core::model::junos_display(c.text())
        } else {
            c.text().to_string()
        };
        let leaf = clean(&leaf, &parent, redactor);
        let parent_c = clean(&parent, "", redactor);
        let mut t = format!(
            "change={kind} section={} | {side}:{} {}{}",
            serde_json::to_value(c.section)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            c.line,
            if parent_c.is_empty() {
                String::new()
            } else {
                format!("{parent_c} > ")
            },
            leaf
        );
        if c.folded > 0 {
            t.push_str(&format!(" (whole block, {} more lines)", c.folded));
        }
        items.push(EvidenceItem {
            id: c.id.clone(),
            text: t,
        });
    }
    let mut notes: Vec<String> = input.notes.iter().map(|n| clean(n, "", redactor)).collect();
    if input.changes.len() > MAX_CHANGES {
        notes.push(format!(
            "{} more changes omitted for length",
            input.changes.len() - MAX_CHANGES
        ));
    }
    if !input.rollback.is_empty() {
        let mut t = format!(
            "deterministic rollback generated by netlens ({}):",
            input.vendor.display_name()
        );
        for l in input.rollback.iter().take(MAX_ROLLBACK_LINES) {
            t.push_str("\n    ");
            t.push_str(l);
        }
        if input.rollback.len() > MAX_ROLLBACK_LINES {
            t.push_str(&format!(
                "\n    ... {} more lines",
                input.rollback.len() - MAX_ROLLBACK_LINES
            ));
        }
        items.push(EvidenceItem {
            id: "R1".into(),
            text: clean(&t, "", redactor),
        });
    }
    ReviewContext {
        vendor: input.vendor.display_name().to_string(),
        source: clean(input.source, "", redactor),
        items,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlens_core::{analyze, Input};

    #[test]
    fn context_is_redacted_and_masked() {
        let before = "hostname r1\nsnmp-server community s3cr3tC0mm RO\nrouter bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n";
        let after = "hostname r1\nsnmp-server community n3wS3cret RO\nrouter bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n neighbor 192.0.2.1 shutdown\n";
        let a = analyze(&Input::Files { before, after }, None).unwrap();
        let mut r = netlens_core::redact::Redactor::new();
        let mut m = netlens_core::ipmask::IpMasker::new();
        let ctx = build_context(
            &ContextInput {
                vendor: a.vendor,
                source: "b -> a",
                findings: &a.findings,
                changes: &a.diff.changes,
                rollback: &a.rollback.lines,
                notes: &a.notes,
            },
            &mut r,
            Some(&mut m),
        );
        let all = build_messages(&ctx)
            .iter()
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !all.contains("s3cr3tC0mm") && !all.contains("n3wS3cret"),
            "{all}"
        );
        assert!(!all.contains("192.0.2.1"), "{all}");
        assert!(all.contains("IP4_1") && all.contains("<redacted:"));
        assert!(ctx.ids().contains("R1") && ctx.ids().contains("F1") && ctx.ids().contains("C1"));
    }
}

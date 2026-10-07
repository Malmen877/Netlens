//! A deterministic stand-in for a real model, used by tests, CI and the
//! README demo. It reads the evidence list from the prompt and answers with
//! properly cited bullets. It also emits a `<think>` block, one uncited
//! bullet and one bullet citing a non-existent id, so the stripping and the
//! citation validator are visibly exercised.

use crate::client::ChatMessage;

struct Item {
    id: String,
    severity: String,
    rule: String,
    title: String,
}

fn parse_items(prompt: &str) -> Vec<Item> {
    let mut out = Vec::new();
    for line in prompt.lines() {
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some((id, body)) = rest.split_once("] ") else {
            continue;
        };
        let field = |k: &str| -> String {
            body.split_whitespace()
                .find_map(|w| w.strip_prefix(&format!("{k}=")))
                .unwrap_or("")
                .to_string()
        };
        let title = body
            .split_once(" | ")
            .map(|(_, t)| t.trim().to_string())
            .unwrap_or_default();
        out.push(Item {
            id: id.to_string(),
            severity: field("severity"),
            rule: field("rule"),
            title,
        });
    }
    out
}

fn impact(rule: &str, id: &str) -> &'static str {
    if id.starts_with('B') {
        return "Batfish independently reports";
    }
    match rule.get(..6).unwrap_or("") {
        "NL-BGP" => "Routing: prefixes exchanged with this peer are affected by",
        "NL-ACL" => "Traffic matched by this filter changes behavior because of",
        "NL-IF-" => "Hosts and adjacencies behind this interface are affected by",
        "NL-RT-" => "Destinations using this route are affected by",
        "NL-OSP" => "OSPF adjacencies and routes are affected by",
        "NL-REF" => "The referencing policy will not behave as intended because of",
        "NL-MGM" => "Management access or monitoring is affected by",
        _ => "Also affected:",
    }
}

pub fn respond(messages: &[ChatMessage]) -> String {
    let prompt = messages
        .iter()
        .filter(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let items = parse_items(&prompt);
    let findings: Vec<&Item> = items
        .iter()
        .filter(|i| i.id.starts_with('F') || i.id.starts_with('B'))
        .collect();
    let has_rollback = items.iter().any(|i| i.id == "R1");
    let mut s = String::new();
    s.push_str(&format!(
        "<think>\nmock model: {} evidence items, {} findings. Drafting a cited review.\n</think>\n",
        items.len(),
        findings.len()
    ));
    s.push_str("SUMMARY:\n");
    if findings.is_empty() {
        let c = items
            .iter()
            .find(|i| i.id.starts_with('C'))
            .map(|i| i.id.clone());
        match c {
            Some(c) => s.push_str(&format!(
                "- No rule flagged this change; review the raw changes manually. [{c}]\n"
            )),
            None => s.push_str("- No configuration changes were found.\n"),
        }
    } else {
        let top = findings[0];
        let sev = if top.severity.is_empty() {
            "unknown".to_string()
        } else {
            top.severity.to_uppercase()
        };
        s.push_str(&format!(
            "- Overall risk is {sev}: {} findings, the most severe being \"{}\". [{}]\n",
            findings.len(),
            top.title,
            top.id
        ));
        for f in findings.iter().skip(1).take(3) {
            s.push_str(&format!("- {} ({}). [{}]\n", f.title, f.severity, f.id));
        }
    }
    s.push_str("- This change looks routine and is safe to apply during business hours.\n");
    s.push_str("\nBLAST RADIUS:\n");
    for f in findings.iter().take(4) {
        s.push_str(&format!(
            "- {} \"{}\". [{}]\n",
            impact(&f.rule, &f.id),
            f.title,
            f.id
        ));
    }
    s.push_str("- The upstream provider will also have to update its filters. [F99]\n");
    s.push_str("\nROLLBACK:\n");
    if has_rollback {
        s.push_str(
            "- Apply the generated rollback snippet to restore the previous configuration. [R1]\n",
        );
    }
    if let Some(f) = findings
        .iter()
        .find(|f| f.severity == "critical" || f.severity == "high")
    {
        s.push_str(&format!(
            "- Because of the high-severity items, apply the change with a timed rollback (commit confirmed / reload in) and keep console access. [{}]\n",
            f.id
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cite::validate;

    #[test]
    fn mock_answer_is_cited_except_the_planted_bad_claims() {
        let prompt = "Vendor: cisco-ios\nEVIDENCE:\n[F1] severity=high rule=NL-BGP-002 section=bgp | BGP neighbor 10.0.0.2 shut down\n[F2] severity=medium rule=NL-IF-004 section=interfaces | MTU changed\n[R1] rollback snippet\n";
        let out = respond(&[ChatMessage::user(prompt)]);
        assert!(out.starts_with("<think>"));
        let text = crate::think::strip_think(&out);
        let valid = ["F1", "F2", "R1"].iter().map(|s| s.to_string()).collect();
        let v = validate(&text, &valid);
        assert_eq!(v.dropped.len(), 2, "{v:#?}");
        assert!(v.claims.len() >= 5);
        assert!(v.claims.iter().all(|c| !c.citations.is_empty()));
    }
}

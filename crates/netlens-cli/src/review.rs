//! `netlens review`: deterministic analysis, optional Batfish, optional
//! cited LLM summary, deterministic rollback.

use crate::config::{self, ModelSettings};
use crate::output::{counts_line, finding_text, redact_findings};
use crate::style::{wrap, ColorChoice, Style};
use anyhow::{bail, Context, Result};
use clap::Args;
use netlens_core::audit::AuditLog;
use netlens_core::diff::ChangeKind;
use netlens_core::ipmask::IpMasker;
use netlens_core::redact::Redactor;
use netlens_core::{analyze, Finding, Input, Severity, Vendor};
use netlens_llm::prompt::{build_context, ContextInput};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Args, Debug)]
pub struct ReviewArgs {
    /// Running/before config
    #[arg(value_name = "BEFORE", required_unless_present = "diff")]
    pub before: Option<PathBuf>,
    /// Candidate/after config
    #[arg(value_name = "AFTER", required_unless_present = "diff")]
    pub after: Option<PathBuf>,
    /// Review a unified diff instead of two files ("-" reads stdin)
    #[arg(long, value_name = "FILE", conflicts_with_all = ["before", "after"])]
    pub diff: Option<PathBuf>,
    /// Force the vendor instead of autodetecting: ios | junos | eos
    #[arg(long, value_name = "VENDOR")]
    pub vendor: Option<String>,
    /// Deterministic review only; never contact a model
    #[arg(long)]
    pub no_llm: bool,
    /// OpenAI-compatible base URL [env NETLENS_MODEL_URL; default http://localhost:11434/v1; "mock://" = built-in mock]
    #[arg(long, value_name = "URL")]
    pub model_url: Option<String>,
    /// Model name [env NETLENS_MODEL; default qwen3:14b]
    #[arg(long, value_name = "NAME")]
    pub model: Option<String>,
    /// Model request timeout in seconds [default 300]
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,
    /// Allow Qwen3-style thinking (slower; <think> blocks are always stripped)
    #[arg(long)]
    pub think: bool,
    /// Replace IP addresses with IP4_n/IP6_n placeholders before the model sees them
    #[arg(long)]
    pub mask_ips: bool,
    /// Show model claims that failed citation validation (marked UNVERIFIED)
    #[arg(long)]
    pub keep_uncited: bool,
    /// Also run Batfish questions (e.g. http://localhost:9996); needs full configs
    #[arg(long, value_name = "URL")]
    pub batfish: Option<String>,
    /// Batfish timeout in seconds
    #[arg(long, value_name = "SECS", default_value_t = 180)]
    pub batfish_timeout: u64,
    /// Show secrets in the report and rollback (the model never sees them)
    #[arg(long)]
    pub reveal_secrets: bool,
    /// Machine-readable JSON report on stdout
    #[arg(long)]
    pub json: bool,
    /// Exit with code 2 if any finding is at or above this severity: info|low|medium|high|critical
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,
    /// Audit log path [env NETLENS_AUDIT; default ~/.local/state/netlens/audit.jsonl]
    #[arg(long, value_name = "PATH", conflicts_with = "no_audit")]
    pub audit: Option<PathBuf>,
    /// Do not write the audit log
    #[arg(long)]
    pub no_audit: bool,
    /// Store full (redacted) prompts in the audit log, not just their hash
    #[arg(long)]
    pub audit_prompts: bool,
    /// Maximum number of raw changes listed in the text report
    #[arg(long, value_name = "N", default_value_t = 40)]
    pub max_changes: usize,
}

pub fn read_input(p: &Path) -> Result<String> {
    if p.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("cannot read stdin")?;
        return Ok(s);
    }
    let bytes = std::fs::read(p).with_context(|| format!("cannot read '{}'", p.display()))?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => Ok(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

fn open_audit(
    file: &config::FileConfig,
    a: &ReviewArgs,
    warnings: &mut Vec<String>,
) -> Result<AuditLog> {
    if a.no_audit {
        return Ok(AuditLog::disabled());
    }
    match config::audit_path(file, a.audit.clone()) {
        None => {
            warnings.push("no audit log location (HOME unset); use --audit PATH".into());
            Ok(AuditLog::disabled())
        }
        Some((p, explicit)) => match AuditLog::open(&p) {
            Ok(l) => Ok(l),
            Err(e) if explicit => Err(anyhow::anyhow!(
                "cannot open audit log {}: {e} (use --no-audit to skip)",
                p.display()
            )),
            Err(e) => {
                warnings.push(format!(
                    "audit log disabled: cannot open {}: {e}",
                    p.display()
                ));
                Ok(AuditLog::disabled())
            }
        },
    }
}

fn audit(log: &AuditLog, event: &str, v: Value, warnings: &mut Vec<String>) {
    if let Err(e) = log.record(event, v) {
        warnings.push(format!("audit write failed: {e}"));
    }
}

fn section_name(s: netlens_core::section::Section) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

pub fn run(a: ReviewArgs, config_flag: Option<&Path>, color: ColorChoice) -> Result<u8> {
    let loaded = config::load(config_flag)?;
    let file = &loaded.file;
    let fail_on: Option<Severity> = a
        .fail_on
        .as_deref()
        .map(|s| s.parse())
        .transpose()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let vendor: Option<Vendor> = a
        .vendor
        .as_deref()
        .map(|s| s.parse())
        .transpose()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let mut warnings: Vec<String> = Vec::new();

    // ---- inputs
    let (before_text, after_text, diff_text, source, inputs) = if let Some(d) = &a.diff {
        let t = read_input(d)?;
        let name = if d.as_os_str() == "-" {
            "<stdin>".to_string()
        } else {
            d.display().to_string()
        };
        let inputs = json!([{"role": "diff", "name": name, "bytes": t.len(), "sha256": netlens_core::sha256_hex(t.as_bytes())}]);
        (
            String::new(),
            String::new(),
            Some(t),
            format!("diff {name}"),
            inputs,
        )
    } else {
        let (b, af) = (
            a.before.as_ref().expect("clap"),
            a.after.as_ref().expect("clap"),
        );
        if b.as_os_str() == "-" && af.as_os_str() == "-" {
            bail!("only one of BEFORE/AFTER can be read from stdin");
        }
        let bt = read_input(b)?;
        let at = read_input(af)?;
        let inputs = json!([
            {"role": "before", "name": b.display().to_string(), "bytes": bt.len(), "sha256": netlens_core::sha256_hex(bt.as_bytes())},
            {"role": "after", "name": af.display().to_string(), "bytes": at.len(), "sha256": netlens_core::sha256_hex(at.as_bytes())}
        ]);
        (
            bt,
            at,
            None,
            format!("{} -> {}", b.display(), af.display()),
            inputs,
        )
    };
    let input = match &diff_text {
        Some(t) => Input::Diff(t),
        None => Input::Files {
            before: &before_text,
            after: &after_text,
        },
    };
    let analysis = analyze(&input, vendor).map_err(|e| anyhow::anyhow!(e))?;
    if analysis.diff.is_empty() {
        warnings.push("no configuration differences found".into());
    }
    if let Some(d) = &analysis.detection {
        if !d.confident {
            warnings.push(format!(
                "vendor autodetect is a guess ({}): {}; use --vendor to override",
                analysis.vendor.key(),
                d.reason
            ));
        }
    }

    // ---- audit
    let log = open_audit(file, &a, &mut warnings)?;
    audit(
        &log,
        "review.start",
        json!({"mode": if diff_text.is_some() {"diff"} else {"files"}, "inputs": inputs, "vendor": analysis.vendor.as_str(), "llm": !a.no_llm, "batfish": a.batfish.is_some() || file.batfish_url.is_some(), "reveal_secrets": a.reveal_secrets}),
        &mut warnings,
    );

    // ---- batfish
    let batfish_url = a.batfish.clone().or_else(|| file.batfish_url.clone());
    let mut batfish_json = Value::Null;
    let mut bf_findings: Vec<Finding> = Vec::new();
    let mut bf_run = None;
    if let Some(url) = &batfish_url {
        if diff_text.is_some() {
            warnings.push("Batfish skipped: it needs full before/after configs, not a diff".into());
            batfish_json = json!({"url": url, "status": "skipped", "reason": "diff input"});
        } else {
            match netlens_batfish::run_review(
                url,
                &before_text,
                &after_text,
                analysis.vendor,
                Duration::from_secs(a.batfish_timeout),
            ) {
                Ok(run) => {
                    for q in run.questions.iter().filter(|q| q.status != "ok") {
                        warnings.push(format!(
                            "Batfish question {} failed: {}",
                            q.name,
                            q.error.clone().unwrap_or_default()
                        ));
                    }
                    audit(
                        &log,
                        "batfish.run",
                        json!({"url": run.url, "ok": true, "questions": run.questions, "findings": run.findings.len()}),
                        &mut warnings,
                    );
                    bf_findings = run.findings.clone();
                    bf_run = Some(run);
                }
                Err(e) => {
                    audit(
                        &log,
                        "batfish.run",
                        json!({"url": url, "ok": false, "error": e.to_string()}),
                        &mut warnings,
                    );
                    warnings.push(format!("Batfish unavailable, continuing without it: {e}"));
                    batfish_json = json!({"url": url, "status": "error", "error": e.to_string()});
                }
            }
        }
    }

    // ---- redaction for display (model input is always redacted, separately below)
    let mut redactor = Redactor::new();
    let all_findings: Vec<Finding> = analysis
        .findings
        .iter()
        .chain(bf_findings.iter())
        .cloned()
        .collect();
    let (shown_f, shown_b, rollback_lines) = if a.reveal_secrets {
        (
            analysis.findings.clone(),
            bf_findings.clone(),
            analysis.rollback.lines.clone(),
        )
    } else {
        let f = redact_findings(&analysis.findings, &mut redactor);
        let b = redact_findings(&bf_findings, &mut redactor);
        let rb: Vec<String> = analysis
            .rollback
            .lines
            .iter()
            .map(|l| redactor.redact_line(l))
            .collect();
        (f, b, rb)
    };
    let rollback_redacted = rollback_lines.iter().any(|l| l.contains("<redacted:"));
    let mut rollback_notes = analysis.rollback.notes.clone();
    if rollback_redacted {
        rollback_notes.push(
            "contains redacted secrets: re-run with --reveal-secrets to get a pasteable rollback"
                .into(),
        );
    }
    let changes_view: Vec<(String, &'static str, usize, String, String, usize)> = analysis
        .diff
        .changes
        .iter()
        .map(|c| {
            let parent = c.parent().join(" > ");
            let leaf = if analysis.vendor == Vendor::Junos {
                netlens_core::model::junos_display(c.text())
            } else {
                c.text().to_string()
            };
            let (parent, leaf) = if a.reveal_secrets {
                (parent, leaf)
            } else {
                (
                    redactor.redact_line(&parent),
                    redactor.redact_line_ctx(&leaf, &parent),
                )
            };
            let kind = if c.kind == ChangeKind::Added {
                "added"
            } else {
                "removed"
            };
            (
                c.id.clone(),
                kind,
                c.line,
                section_name(c.section),
                if parent.is_empty() {
                    leaf
                } else {
                    format!("{parent} > {leaf}")
                },
                c.folded,
            )
        })
        .collect();

    // ---- LLM
    let ms: ModelSettings = config::model_settings(
        file,
        a.model_url.clone(),
        a.model.clone(),
        a.timeout,
        a.think,
    );
    let mask_ips = a.mask_ips || file.mask_ips.unwrap_or(false);
    let store_prompts = a.audit_prompts || file.audit_prompts.unwrap_or(false);
    let mut llm_json = Value::Null;
    let mut llm_review = None;
    let mut llm_error = None;
    if !a.no_llm {
        let cfg = ms.to_model_config();
        let mut model_redactor = Redactor::new();
        let mut masker = IpMasker::new();
        let notes: Vec<String> = analysis
            .notes
            .iter()
            .chain(analysis.rollback.notes.iter())
            .cloned()
            .collect();
        let ctx = build_context(
            &ContextInput {
                vendor: analysis.vendor,
                source: &source,
                findings: &all_findings,
                changes: &analysis.diff.changes,
                rollback: &analysis.rollback.lines,
                notes: &notes,
            },
            &mut model_redactor,
            if mask_ips { Some(&mut masker) } else { None },
        );
        let backend = netlens_llm::backend_for(&cfg);
        match netlens_llm::run_review(
            backend.as_ref(),
            &cfg,
            &ctx,
            if mask_ips { Some(&masker) } else { None },
            &log,
            store_prompts,
        ) {
            Ok(r) => {
                llm_json = json!({"status": "ok", "model": r.model, "endpoint": r.endpoint, "latency_ms": r.latency_ms, "prompt_sha256": r.prompt_sha256, "prompt_bytes": r.prompt_bytes, "redactions": model_redactor.count, "masked_ips": masker.len(), "claims": r.claims, "dropped": r.dropped, "unknown_ids": r.unknown_ids});
                llm_review = Some((r, model_redactor.count, masker.len()));
            }
            Err(e) => {
                warnings.push(format!("AI summary skipped: {e}"));
                llm_json = json!({"status": "error", "endpoint": cfg.endpoint(), "model": cfg.model, "error": e.to_string()});
                llm_error = Some(e.to_string());
            }
        }
    }

    // ---- exit status
    let max = netlens_core::finding::SeverityCounts::of(&all_findings).max();
    let code = match (fail_on, max) {
        (Some(t), Some(m)) if m >= t => 2,
        _ => 0,
    };
    audit(
        &log,
        "review.end",
        json!({"findings": analysis.findings.len(), "batfish_findings": bf_findings.len(), "max_severity": max.map(|m| m.as_str()), "llm": if a.no_llm {"disabled"} else if llm_error.is_some() {"error"} else {"ok"}, "exit_code": code}),
        &mut warnings,
    );

    // ---- output
    let es = Style::stderr(color);
    for w in &warnings {
        eprintln!("{} {w}", es.yellow(&es.bold("warning:")));
    }
    if a.json {
        if let Some(run) = &bf_run {
            batfish_json = json!({"url": run.url, "status": "ok", "version": run.version, "questions": run.questions, "findings": shown_b});
        }
        let sections: Vec<Value> = analysis
            .diff
            .sections()
            .iter()
            .map(|(s, add, rem)| json!({"section": section_name(*s), "added": add, "removed": rem}))
            .collect();
        let changes: Vec<Value> = changes_view.iter().map(|(id, kind, line, sec, text, folded)| json!({"id": id, "kind": kind, "line": line, "section": sec, "text": text, "folded": folded})).collect();
        let report = json!({
            "netlens_version": env!("CARGO_PKG_VERSION"),
            "vendor": analysis.vendor.as_str(),
            "vendor_detection": analysis.detection.as_ref().map(|d| json!({"vendor": d.vendor.as_str(), "confident": d.confident, "reason": d.reason})),
            "mode": if diff_text.is_some() {"diff"} else {"files"},
            "partial": analysis.partial,
            "inputs": inputs,
            "summary": {"added": analysis.diff.added, "removed": analysis.diff.removed, "findings": all_findings.len(), "max_severity": max.map(|m| m.as_str()), "counts": netlens_core::finding::SeverityCounts::of(&all_findings)},
            "sections": sections,
            "changes": changes,
            "findings": shown_f,
            "batfish": batfish_json,
            "llm": llm_json,
            "rollback": {"vendor": analysis.vendor.as_str(), "lines": rollback_lines, "notes": rollback_notes, "contains_redactions": rollback_redacted},
            "notes": analysis.notes,
            "warnings": warnings,
            "audit": {"path": log.path().map(|p| p.display().to_string()), "session": log.session()},
            "exit_code": code,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(code);
    }

    let s = Style::new(color);
    let mut out = String::new();
    let det = match &analysis.detection {
        Some(d) => format!(
            "autodetected{}",
            if d.confident { "" } else { ", low confidence" }
        ),
        None => "--vendor".into(),
    };
    out.push_str(&format!(
        "{}  {}  {}\n",
        s.bold("netlens review"),
        s.cyan(&format!("{} ({det})", analysis.vendor.display_name())),
        s.dim(&source)
    ));
    if analysis.partial {
        out.push_str(
            &s.dim(
                "  diff mode: only hunk context is known; some checks are limited (see notes)\n",
            ),
        );
    }
    let secs: Vec<String> = analysis
        .diff
        .sections()
        .iter()
        .map(|(sec, add, rem)| {
            let mut p = Vec::new();
            if *add > 0 {
                p.push(format!("+{add}"));
            }
            if *rem > 0 {
                p.push(format!("-{rem}"));
            }
            format!("{} {}", section_name(*sec), p.join("/"))
        })
        .collect();
    out.push_str(&format!(
        "\n{} +{} -{} lines in {} sections: {}\n",
        s.heading("Changes"),
        analysis.diff.added,
        analysis.diff.removed,
        secs.len(),
        secs.join(", ")
    ));
    for (id, kind, line, sec, text, folded) in changes_view.iter().take(a.max_changes) {
        let (sign, side) = if *kind == "added" {
            (s.green("+"), "after")
        } else {
            (s.red("-"), "before")
        };
        let fold = if *folded > 0 {
            s.dim(&format!("  (+{folded} lines in block)"))
        } else {
            String::new()
        };
        out.push_str(&format!(
            " {} {} {} {} {}{fold}\n",
            s.dim(&format!("{id:<4}")),
            sign,
            s.cyan(&format!("{:<11}", format!("{side}:{line}"))),
            s.dim(&format!("[{sec}]")),
            text
        ));
    }
    if changes_view.len() > a.max_changes {
        out.push_str(&s.dim(&format!(
            "  ... {} more (use --max-changes or --json)\n",
            changes_view.len() - a.max_changes
        )));
    }

    out.push_str(&format!(
        "\n{} ({}): {}\n",
        s.heading("Findings"),
        shown_f.len(),
        counts_line(&shown_f, &s)
    ));
    for f in &shown_f {
        out.push_str(&finding_text(f, &s));
    }

    if let Some(run) = &bf_run {
        let ok = run.questions.iter().filter(|q| q.status == "ok").count();
        let mock = if run.version.get("mock").and_then(Value::as_bool) == Some(true) {
            s.yellow(" [MOCK SERVER]")
        } else {
            String::new()
        };
        out.push_str(&format!(
            "\n{} {}{mock}: {}/{} questions ok, {} findings: {}\n",
            s.heading("Batfish"),
            s.dim(&run.url),
            ok,
            run.questions.len(),
            shown_b.len(),
            counts_line(&shown_b, &s)
        ));
        for f in &shown_b {
            out.push_str(&finding_text(f, &s));
        }
    } else if !batfish_json.is_null() {
        out.push_str(&format!(
            "\n{} {}\n",
            s.heading("Batfish"),
            s.yellow(batfish_json["status"].as_str().unwrap_or(""))
        ));
    }

    if let Some((r, nred, nmask)) = &llm_review {
        let verified = r.claims.len();
        out.push_str(&format!(
            "\n{} {}\n",
            s.heading("AI review"),
            s.dim(&format!("{} via {} ({:.1}s; {verified} cited claims; {nred} redactions{}; every claim must cite evidence)", r.model, r.endpoint, r.latency_ms as f64 / 1000.0, if mask_ips { format!(", {nmask} IPs masked") } else { String::new() }))
        ));
        for (sec, label) in [
            ("SUMMARY", "Summary"),
            ("BLAST RADIUS", "Blast radius"),
            ("ROLLBACK", "Rollback"),
        ] {
            let claims = r.section(sec);
            let dropped: Vec<_> = r.dropped.iter().filter(|d| d.section == sec).collect();
            if claims.is_empty() && (dropped.is_empty() || !a.keep_uncited) {
                continue;
            }
            out.push_str(&format!(" {}\n", s.bold(label)));
            for c in claims {
                let body = wrap(&c.text, 100, "     ");
                out.push_str(&format!("   *{}", &body[4..]));
            }
            if a.keep_uncited {
                for d in dropped {
                    out.push_str(&format!(
                        "   {} {} {}\n",
                        s.red("x"),
                        s.yellow(&format!("[UNVERIFIED: {}]", d.reason)),
                        s.dim(&d.text)
                    ));
                }
            }
        }
        if !r.dropped.is_empty() && !a.keep_uncited {
            out.push_str(&s.yellow(&format!(
                " {} model claim(s) dropped: no valid citation (show with --keep-uncited)\n",
                r.dropped.len()
            )));
        }
        if !r.unknown_ids.is_empty() {
            out.push_str(&s.yellow(&format!(
                " ignored citations to unknown evidence: {}\n",
                r.unknown_ids.join(", ")
            )));
        }
    } else if a.no_llm {
        out.push_str(&s.dim("\nAI review disabled (--no-llm)\n"));
    }

    let comment = if analysis.vendor == Vendor::Junos {
        "#"
    } else {
        "!"
    };
    out.push_str(&format!(
        "\n{} {}\n",
        s.heading("Rollback"),
        s.dim("(deterministic; review before applying) [R1]")
    ));
    if analysis.rollback.is_empty() && rollback_lines.is_empty() {
        out.push_str("  nothing to roll back\n");
    } else {
        for l in &rollback_lines {
            if l.trim_start().starts_with(comment) {
                out.push_str(&format!("  {}\n", s.dim(l)));
            } else {
                out.push_str(&format!("  {l}\n"));
            }
        }
    }
    for n in &rollback_notes {
        out.push_str(&format!("  {} {n}\n", s.yellow("note:")));
    }
    if !analysis.notes.is_empty() {
        out.push_str(&format!("\n{}\n", s.heading("Notes")));
        for n in &analysis.notes {
            out.push_str(&format!("  - {n}\n"));
        }
    }
    if let Some(p) = log.path() {
        out.push_str(&s.dim(&format!(
            "\naudit: {} (session {})\n",
            p.display(),
            log.session()
        )));
    }
    if code == 2 {
        out.push_str(&s.red(&format!(
            "\nfail-on {}: findings at or above threshold (exit 2)\n",
            fail_on.map(|f| f.as_str()).unwrap_or("")
        )));
    }
    print!("{out}");
    Ok(code)
}

//! Smaller subcommands: lint, redact, policy, config, phase-2 stubs.

use crate::config;
use crate::output::{counts_line, finding_text, redact_findings};
use crate::review::read_input;
use crate::style::{ColorChoice, Style};
use anyhow::Result;
use clap::{Args, Subcommand};
use netlens_core::policy::{DENY_ANY_WORDS, DENY_FIRST_WORDS};
use netlens_core::{Severity, Vendor};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct LintArgs {
    /// Configuration file ("-" reads stdin)
    pub file: PathBuf,
    /// Force the vendor: ios | junos | eos
    #[arg(long)]
    pub vendor: Option<String>,
    /// JSON output
    #[arg(long)]
    pub json: bool,
    /// Exit 2 if any finding is at or above this severity
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,
    /// Show secrets in evidence lines
    #[arg(long)]
    pub reveal_secrets: bool,
}

#[derive(Args, Debug)]
pub struct RedactArgs {
    /// Config or log file ("-" or omitted reads stdin)
    pub file: Option<PathBuf>,
    /// Also replace IP addresses with IP4_n/IP6_n placeholders
    #[arg(long)]
    pub mask_ips: bool,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Check whether a command would be allowed (exit 0) or denied (exit 2)
    Check {
        /// ios | junos | eos
        #[arg(long, default_value = "ios")]
        vendor: String,
        /// The command, e.g. "show ip bgp summary"
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        command: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List allowlist patterns and hard-deny words
    List {
        /// ios | junos | eos
        #[arg(long, default_value = "ios")]
        vendor: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print effective settings and their source (flag/env/config/default)
    Show,
    /// Print the config file path that is used
    Path,
    /// Print an example config file
    Example,
}

#[derive(Args, Debug)]
pub struct PhaseTwoArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    pub rest: Vec<String>,
}

fn parse_vendor(s: &str) -> Result<Vendor> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

pub fn lint(a: LintArgs, color: ColorChoice) -> Result<u8> {
    let text = read_input(&a.file)?;
    let vendor = a.vendor.as_deref().map(parse_vendor).transpose()?;
    let fail_on: Option<Severity> = a
        .fail_on
        .as_deref()
        .map(|s| s.parse())
        .transpose()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let (cfg, det, findings) = netlens_core::analyze_single(&text, vendor);
    let shown = if a.reveal_secrets {
        findings.clone()
    } else {
        redact_findings(&findings, &mut netlens_core::redact::Redactor::new())
    };
    let max = netlens_core::finding::SeverityCounts::of(&findings).max();
    let code = match (fail_on, max) {
        (Some(t), Some(m)) if m >= t => 2,
        _ => 0,
    };
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vendor": cfg.vendor.as_str(),
                "vendor_detection": det.as_ref().map(|d| json!({"vendor": d.vendor.as_str(), "confident": d.confident, "reason": d.reason})),
                "findings": shown,
                "exit_code": code,
            }))?
        );
        return Ok(code);
    }
    let s = Style::new(color);
    println!(
        "{}  {}  {}",
        s.bold("netlens lint"),
        s.cyan(cfg.vendor.display_name()),
        s.dim(&a.file.display().to_string())
    );
    println!(
        "\n{} ({}): {}",
        s.heading("Findings"),
        shown.len(),
        counts_line(&shown, &s)
    );
    for f in &shown {
        print!("{}", finding_text(f, &s));
    }
    Ok(code)
}

pub fn redact(a: RedactArgs) -> Result<u8> {
    let p = a.file.unwrap_or_else(|| PathBuf::from("-"));
    let text = read_input(&p)?;
    let mut r = netlens_core::redact::Redactor::new();
    let mut out = r.redact_text(&text);
    let mut masked = 0;
    if a.mask_ips {
        let mut m = netlens_core::ipmask::IpMasker::new();
        out = m.mask(&out);
        masked = m.len();
    }
    print!("{out}");
    if a.mask_ips {
        eprintln!(
            "netlens: redacted {} secret value(s), masked {masked} IP address(es)",
            r.count
        );
    } else {
        eprintln!("netlens: redacted {} secret value(s)", r.count);
    }
    Ok(0)
}

pub fn policy(cmd: PolicyCmd, config_flag: Option<&Path>, color: ColorChoice) -> Result<u8> {
    let loaded = config::load(config_flag)?;
    let pol = config::policy(&loaded.file)?;
    let s = Style::new(color);
    match cmd {
        PolicyCmd::Check {
            vendor,
            command,
            json,
        } => {
            let v = parse_vendor(&vendor)?;
            let cmd = command.join(" ");
            let gate = config::gate(&loaded.file)?;
            let res = gate.vet(v, &cmd);
            if json {
                let result = match &res {
                    Ok(vt) => {
                        json!({"verdict": "allowed", "send": vt.command, "canonical": vt.canonical})
                    }
                    Err(r) => {
                        json!({"verdict": "denied", "stage": r.stage, "kind": r.kind, "reason": r.reason})
                    }
                };
                println!(
                    "{}",
                    serde_json::to_string(
                        &json!({"vendor": v.as_str(), "command": cmd, "result": result})
                    )?
                );
            } else {
                match &res {
                    Ok(vt) => println!(
                        "{} {}  {}",
                        s.green("ALLOWED"),
                        vt.command,
                        s.dim(&format!(
                            "(canonical: {}; still needs y/N approval before it runs)",
                            vt.canonical
                        ))
                    ),
                    Err(r) => println!("{} {cmd}  {r}", s.red("DENIED")),
                }
            }
            Ok(if res.is_ok() { 0 } else { 2 })
        }
        PolicyCmd::List { vendor } => {
            let v = parse_vendor(&vendor)?;
            let gate = config::gate(&loaded.file)?;
            println!("A command must pass BOTH layers (the stricter rule wins), then your y/N.\n");
            println!(
                "{} ({}; netlens-allowlist, matched on the canonical form)",
                s.heading("Layer 1: allowlist"),
                v.display_name()
            );
            for p in gate
                .allowlist()
                .patterns(netlens_core::gate::to_allowlist_vendor(v))
            {
                println!("  {p}");
            }
            println!(
                "  denied verbs: {}",
                netlens_allowlist::allowlist::DENY_VERBS.join(" ")
            );
            println!(
                "\n{} ({})",
                s.heading("Layer 2: netlens policy"),
                v.display_name()
            );
            for p in pol.patterns(v) {
                println!("  {p}");
            }
            println!("\n{} (first word, any vendor)", s.heading("Hard deny"));
            println!("  {}", DENY_FIRST_WORDS.join(" "));
            println!("\n{} (anywhere in the command)", s.heading("Hard deny"));
            println!("  {}", DENY_ANY_WORDS.join(" "));
            Ok(0)
        }
    }
}

pub fn config(cmd: ConfigCmd, config_flag: Option<&Path>) -> Result<u8> {
    match cmd {
        ConfigCmd::Example => {
            print!("{}", config::EXAMPLE);
        }
        ConfigCmd::Path => match config::config_path(config_flag) {
            Some((p, _)) => println!(
                "{}{}",
                p.display(),
                if p.exists() { "" } else { "  (not present)" }
            ),
            None => println!("(no HOME; pass --config)"),
        },
        ConfigCmd::Show => {
            let l = config::load(config_flag)?;
            let ms = config::model_settings(&l.file, None, None, None, false);
            let audit = config::audit_path(&l.file, None);
            println!(
                "config_file   = {}",
                l.path
                    .as_ref()
                    .map(|p| format!(
                        "{}{}",
                        p.display(),
                        if l.found { "" } else { " (not present)" }
                    ))
                    .unwrap_or_else(|| "-".into())
            );
            println!("model_url     = {}  ({})", ms.url.value, ms.url.source);
            println!("model         = {}  ({})", ms.model.value, ms.model.source);
            println!(
                "api_key       = {}",
                ms.api_key
                    .as_ref()
                    .map(|k| format!("set ({})", k.source))
                    .unwrap_or_else(|| "unset".into())
            );
            println!("timeout_secs  = {}", ms.timeout_secs);
            println!("think         = {}", ms.think);
            println!("mask_ips      = {}", l.file.mask_ips.unwrap_or(false));
            println!(
                "audit_path    = {}",
                audit
                    .map(|(p, _)| p.display().to_string())
                    .unwrap_or_else(|| "-".into())
            );
            println!("audit_prompts = {}", l.file.audit_prompts.unwrap_or(false));
            println!(
                "batfish_url   = {}",
                l.file.batfish_url.clone().unwrap_or_else(|| "-".into())
            );
        }
    }
    Ok(0)
}

pub fn phase_two(name: &str, color: ColorChoice) -> Result<u8> {
    let s = Style::stderr(color);
    let what = match name {
        "troubleshoot" => "read-only troubleshooting: allowlisted show commands over SSH, each approved with y/N, correlated with syslog",
        _ => "MCP server over stdio (review/lint/redact as MCP tools)",
    };
    eprintln!(
        "{} `netlens {name}` is coming in phase 2 ({what}).",
        s.yellow(&s.bold("not yet available:"))
    );
    if name == "troubleshoot" {
        eprintln!("Available now: `netlens policy check --vendor ios -- show ip bgp summary` shows what the command policy allows.");
    }
    Ok(1)
}

pub fn rules(json: bool, color: ColorChoice) -> Result<u8> {
    let rules = netlens_core::rules::RULES;
    if json {
        let v: Vec<_> = rules
            .iter()
            .map(|r| json!({"id": r.id, "severity": r.severity.as_str(), "summary": r.summary}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(0);
    }
    let s = Style::new(color);
    for r in rules {
        println!(
            "{}  {} {}",
            s.bold(&format!("{:<12}", r.id)),
            s.sev(r.severity),
            r.summary
        );
    }
    Ok(0)
}

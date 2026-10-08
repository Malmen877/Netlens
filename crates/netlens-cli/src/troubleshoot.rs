//! `netlens troubleshoot`: approved, read-only show-command troubleshooting.

use crate::config;
use crate::style::{wrap, ColorChoice, Style};
use anyhow::{bail, Context, Result};
use clap::Args;
use netlens_core::audit::AuditLog;
use netlens_core::gate::Vetted;
use netlens_core::runner::{DeviceRunner, MockDevice, SshRunner};
use netlens_core::ssh::SshTarget;
use netlens_core::Vendor;
use netlens_llm::troubleshoot::{
    Decision, Event, Operator, Options, Report, ScriptedBackend, Troubleshooter, DEFAULT_MAX_STEPS,
    MAX_STEPS_LIMIT,
};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Args, Debug)]
#[command(
    after_help = "Examples:\n  netlens troubleshoot --host edge-r1 --vendor ios --syslog edge-r1.log \"BGP to 198.51.100.2 flapping\"\n  netlens troubleshoot --mock-device examples/troubleshoot/ios/bgp-flap-mtu --model-url mock:// --auto-approve\n\nEvery proposed command passes the read-only gate (allowlist + policy) and needs your y/N before it runs."
)]
pub struct TroubleshootArgs {
    /// The symptom in plain words (default with --mock-device: the scenario's symptom)
    pub symptom: Option<String>,
    /// Device to connect to over SSH (uses your ~/.ssh/config, agent and known_hosts)
    #[arg(long, value_name = "HOST", required_unless_present = "mock_device")]
    pub host: Option<String>,
    /// Device vendor: ios | junos | eos (required for --host)
    #[arg(long)]
    pub vendor: Option<String>,
    /// SSH user
    #[arg(long, short = 'l')]
    pub user: Option<String>,
    /// SSH port
    #[arg(long, short = 'p')]
    pub port: Option<u16>,
    /// SSH identity file
    #[arg(long, short = 'i', value_name = "PATH")]
    pub identity: Option<PathBuf>,
    /// Per-command SSH timeout in seconds
    #[arg(long, default_value_t = 60, value_name = "SECS")]
    pub ssh_timeout: u64,
    /// Syslog file to correlate (filtered deterministically around the symptom)
    #[arg(long, value_name = "FILE")]
    pub syslog: Option<PathBuf>,
    /// Offline: replay a recorded scenario directory instead of SSH
    #[arg(long, value_name = "DIR", conflicts_with = "host")]
    pub mock_device: Option<PathBuf>,
    /// Approve every gated command without asking (only with --mock-device)
    #[arg(long, requires = "mock_device")]
    pub auto_approve: bool,
    /// Scripted replies for --model-url mock:// (default: DIR/mock-llm.json)
    #[arg(long, value_name = "FILE")]
    pub mock_script: Option<PathBuf>,
    /// Maximum number of commands the model may propose
    #[arg(long, default_value_t = DEFAULT_MAX_STEPS, value_name = "N")]
    pub max_steps: usize,
    /// OpenAI-compatible base URL [env NETLENS_MODEL_URL; default http://localhost:11434/v1]
    #[arg(long, value_name = "URL")]
    pub model_url: Option<String>,
    /// Model name [env NETLENS_MODEL; default qwen3:14b]
    #[arg(long, value_name = "NAME")]
    pub model: Option<String>,
    /// Model request timeout in seconds
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,
    /// Allow Qwen3-style thinking (slower)
    #[arg(long)]
    pub think: bool,
    /// Replace IP addresses with IP4_n/IP6_n placeholders before the model sees them
    #[arg(long)]
    pub mask_ips: bool,
    /// JSON report on stdout
    #[arg(long)]
    pub json: bool,
    /// Audit log path [env NETLENS_AUDIT]
    #[arg(long, value_name = "PATH", conflicts_with = "no_audit")]
    pub audit: Option<PathBuf>,
    /// Do not write the audit log
    #[arg(long)]
    pub no_audit: bool,
    /// Store full (redacted) prompts in the audit log
    #[arg(long)]
    pub audit_prompts: bool,
}

struct Tty {
    s: Style,
    interactive: bool,
}

impl Operator for Tty {
    fn approve(&mut self, step: usize, max: usize, vetted: &Vetted, _reason: &str) -> Decision {
        if !self.interactive {
            return Decision::Quit;
        }
        let s = &self.s;
        eprint!(
            "  {} run `{}`? [y/N/q] ",
            s.bold(&format!("[{step}/{max}]")),
            s.cyan(&vetted.command)
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
            return Decision::Quit;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Decision::Approve,
            "q" | "quit" => Decision::Quit,
            _ => Decision::Decline,
        }
    }

    fn event(&mut self, ev: Event<'_>) {
        let s = &self.s;
        match ev {
            Event::Syslog { hits, terms } => {
                eprintln!(
                    "{} {} new line(s) (terms: {})",
                    s.dim("syslog"),
                    hits.len(),
                    terms.join(", ")
                );
            }
            Event::Proposed {
                step,
                max,
                command,
                reason,
            } => {
                eprintln!(
                    "\n{} {}  {}",
                    s.bold(&format!("step {step}/{max}")),
                    s.cyan(command),
                    s.dim(reason)
                );
            }
            Event::Rejected {
                command: _,
                rejection,
                ..
            } => eprintln!("  {} {rejection}", s.red(&s.bold("BLOCKED"))),
            Event::Declined { .. } => eprintln!("  {}", s.yellow("declined, not run")),
            Event::Duplicate { id, .. } => eprintln!("  {}", s.dim(&format!("already ran ({id})"))),
            Event::AutoApproved { .. } => {
                eprintln!("  {}", s.dim("auto-approved (mock device)"))
            }
            Event::Ran {
                id,
                lines,
                error,
                latency_ms,
                ..
            } => match error {
                Some(e) => eprintln!("  {} {e}", s.red("failed:")),
                None => eprintln!(
                    "  {} {lines} lines ({latency_ms} ms)",
                    s.green(&format!("{id} ok"))
                ),
            },
            Event::ModelRetry { reason } => {
                eprintln!(
                    "  {} {reason}",
                    s.yellow("model reply not usable, retrying:")
                )
            }
        }
    }
}

fn open_audit(file: &config::FileConfig, a: &TroubleshootArgs) -> Result<AuditLog> {
    if a.no_audit {
        return Ok(AuditLog::disabled());
    }
    match config::audit_path(file, a.audit.clone()) {
        None => Ok(AuditLog::disabled()),
        Some((p, explicit)) => match AuditLog::open(&p) {
            Ok(l) => Ok(l),
            Err(e) if explicit => bail!("cannot open audit log {}: {e}", p.display()),
            Err(e) => {
                eprintln!(
                    "warning: audit log disabled: cannot open {}: {e}",
                    p.display()
                );
                Ok(AuditLog::disabled())
            }
        },
    }
}

pub fn run(a: TroubleshootArgs, config_flag: Option<&Path>, color: ColorChoice) -> Result<u8> {
    let loaded = config::load(config_flag)?;
    let file = &loaded.file;
    let gate = config::gate(file)?;
    if a.auto_approve && a.mock_device.is_none() {
        bail!("--auto-approve is only allowed with --mock-device: commands for real devices always need your y/N");
    }
    if a.max_steps == 0 || a.max_steps > MAX_STEPS_LIMIT {
        bail!("--max-steps must be between 1 and {MAX_STEPS_LIMIT}");
    }
    let vendor_flag: Option<Vendor> = a
        .vendor
        .as_deref()
        .map(|s| s.parse())
        .transpose()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // ---- runner
    let mut mock_dir = None;
    let (mut runner, vendor, host, default_symptom, default_syslog): (
        Box<dyn DeviceRunner>,
        Vendor,
        String,
        Option<String>,
        Option<PathBuf>,
    ) = if let Some(dir) = &a.mock_device {
        let m = MockDevice::load(dir).map_err(|e| anyhow::anyhow!("--mock-device: {e}"))?;
        let v = m.vendor();
        if let Some(f) = vendor_flag {
            if f != v {
                bail!(
                    "--vendor {} does not match the scenario ({})",
                    f.key(),
                    v.key()
                );
            }
        }
        mock_dir = Some(dir.clone());
        let host = m.scenario.hostname.clone();
        let sym = m.scenario.symptom.clone();
        let sl = dir.join(&m.scenario.syslog);
        (Box::new(m), v, host, Some(sym), Some(sl))
    } else {
        let host = a.host.clone().context("--host is required")?;
        let v = vendor_flag.context("--vendor ios|junos|eos is required with --host")?;
        let mut t = SshTarget::new(&host).map_err(|e| anyhow::anyhow!(e))?;
        t.user = a.user.clone();
        t.port = a.port;
        t.identity = a.identity.clone();
        (
            Box::new(SshRunner {
                target: t,
                timeout: Duration::from_secs(a.ssh_timeout),
            }),
            v,
            host,
            None,
            None,
        )
    };
    let interactive = std::io::stdin().is_terminal();
    if !runner.is_mock() && !interactive {
        bail!("troubleshoot needs an interactive terminal: every command must be approved with y/N (stdin is not a TTY)");
    }
    let symptom = a
        .symptom
        .clone()
        .or(default_symptom)
        .context("describe the symptom, e.g. \"BGP to 198.51.100.2 flapping\"")?;
    let syslog_path = a.syslog.clone().or(default_syslog);
    let syslog_text = match &syslog_path {
        Some(p) => Some(crate::review::read_input(p)?),
        None => None,
    };

    // ---- model
    let ms = config::model_settings(
        file,
        a.model_url.clone(),
        a.model.clone(),
        a.timeout,
        a.think,
    );
    let cfg = ms.to_model_config();
    let backend: Box<dyn netlens_llm::ChatBackend> = if cfg.is_mock() {
        let script = a
            .mock_script
            .clone()
            .or_else(|| mock_dir.as_ref().map(|d| d.join("mock-llm.json")))
            .context("--model-url mock:// needs a scripted reply file: use --mock-device DIR (with DIR/mock-llm.json) or --mock-script FILE")?;
        let text = std::fs::read_to_string(&script)
            .with_context(|| format!("cannot read mock script {}", script.display()))?;
        Box::new(
            ScriptedBackend::from_json(&text, format!("scripted mock, {}", script.display()))
                .map_err(|e| anyhow::anyhow!("mock script {}: {e}", script.display()))?,
        )
    } else {
        netlens_llm::backend_for(&cfg)
    };
    let model_label = if cfg.is_mock() {
        "mock (scripted)".to_string()
    } else {
        cfg.model.clone()
    };
    let endpoint = if cfg.is_mock() {
        "mock://".to_string()
    } else {
        cfg.endpoint()
    };

    let log = open_audit(file, &a)?;
    let es = Style::stderr(color);
    eprintln!(
        "{}  {}  {}  model {} via {}",
        es.heading("netlens troubleshoot"),
        host,
        vendor.display_name(),
        model_label,
        endpoint
    );
    eprintln!("{} {}", es.dim("symptom:"), symptom);
    if runner.is_mock() {
        eprintln!(
            "{}",
            es.yellow(&format!(
                "[MOCK DEVICE] {} - no network access",
                runner.describe()
            ))
        );
    }
    let mut op = Tty {
        s: es,
        interactive: interactive || a.auto_approve,
    };
    if runner.is_mock() && !a.auto_approve && !interactive {
        // piped stdin: still read answers from it (tests, scripted demos)
        op.interactive = true;
    }
    let report = Troubleshooter {
        host: &host,
        vendor,
        symptom: &symptom,
        syslog: syslog_text.as_deref(),
        gate: &gate,
        chat: backend.as_ref(),
        model_name: &model_label,
        endpoint: &endpoint,
        runner: runner.as_mut(),
        audit: &log,
        opts: Options {
            max_steps: a.max_steps,
            mask_ips: a.mask_ips || file.mask_ips.unwrap_or(false),
            store_prompts: a.audit_prompts || file.audit_prompts.unwrap_or(false),
            auto_approve: a.auto_approve,
            ..Default::default()
        },
    }
    .run(&mut op);

    if a.json {
        let mut v = serde_json::to_value(&report)?;
        v["audit"] = serde_json::json!({"path": log.path().map(|p| p.display().to_string()), "session": log.session()});
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print_report(&report, &Style::new(color));
        if let Some(p) = log.path() {
            eprintln!(
                "\n{}",
                es.dim(&format!(
                    "audit: {} (session {})",
                    p.display(),
                    log.session()
                ))
            );
        }
    }
    Ok(match report.outcome.as_str() {
        "answered" => 0,
        _ => 1,
    })
}

fn print_report(r: &Report, s: &Style) {
    println!();
    let ran = r.steps.iter().filter(|x| x.outcome == "ran").count();
    let blocked = r.steps.iter().filter(|x| x.outcome == "rejected").count();
    println!(
        "{}  {} command(s) run, {} blocked by the gate, {} syslog line(s) shown",
        s.heading("Diagnosis"),
        ran,
        blocked,
        r.syslog_lines_shown
    );
    match (&r.root_cause, r.outcome.as_str()) {
        (Some(rc), _) => {
            let tag = if r.unverified {
                s.red(&s.bold("UNVERIFIED (no valid evidence)"))
            } else {
                s.bold(&format!(
                    "Root cause ({} confidence)",
                    r.confidence.as_deref().unwrap_or("unstated")
                ))
            };
            println!(" {tag}");
            println!("{}", wrap(rc, 96, "   "));
        }
        (None, outcome) => {
            println!(
                " {} {}",
                s.red(&s.bold("No diagnosis:")),
                match outcome {
                    "aborted" => "stopped by the operator".to_string(),
                    _ => r.error.clone().unwrap_or_else(|| "no final answer".into()),
                }
            );
        }
    }
    if !r.evidence.is_empty() {
        println!(" {}", s.bold("Evidence (quoted, validated)"));
        for e in &r.evidence {
            println!("   [{}] {}", s.cyan(&e.cite), s.dim(&e.source));
            println!("       \"{}\"", e.quote);
        }
    }
    if !r.dropped_evidence.is_empty() {
        println!(
            " {} {} evidence item(s) dropped:",
            s.yellow("!"),
            r.dropped_evidence.len()
        );
        for d in &r.dropped_evidence {
            println!("   [{}] \"{}\"  {}", d.cite, d.quote, s.dim(&d.reason));
        }
    }
    if !r.next_checks.is_empty() {
        println!(" {}", s.bold("Next read-only checks"));
        for c in &r.next_checks {
            println!("   {c}");
        }
    }
    for c in &r.rejected_next_checks {
        println!(
            "   {} {}  {}",
            s.red("dropped suggestion:"),
            c.command,
            s.dim(&c.reason)
        );
    }
}

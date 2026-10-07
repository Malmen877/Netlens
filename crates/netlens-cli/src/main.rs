//! netlens: local, read-only AI copilot for network engineers.

mod cmds;
mod config;
mod output;
mod review;
mod style;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use style::{ColorChoice, Style};

/// Exit codes: 0 ok, 1 error, 2 findings at/above --fail-on (or command denied by policy).
#[derive(Parser, Debug)]
#[command(name = "netlens", version, about = "Local, read-only AI copilot for network engineers", long_about = None)]
#[command(
    after_help = "Examples:\n  netlens review before.cfg after.cfg --no-llm\n  netlens review --diff change.diff --model qwen3:14b\n  git diff | netlens review --diff - --fail-on high\n\nModel: any OpenAI-compatible endpoint (default Ollama at http://localhost:11434/v1). Secrets are redacted before anything reaches the model."
)]
pub struct Cli {
    /// When to use colors (NO_COLOR is honoured in auto mode)
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
    /// Config file (default: $NETLENS_CONFIG or ~/.config/netlens/config.toml)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Review a config change: findings, AI risk summary with citations, rollback
    Review(review::ReviewArgs),
    /// Lint a single configuration file (no diff, no model)
    Lint(cmds::LintArgs),
    /// List the deterministic rules
    Rules {
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// Redact secrets from a config or log (what the model would see)
    Redact(cmds::RedactArgs),
    /// Inspect the read-only command policy used by troubleshoot
    Policy {
        #[command(subcommand)]
        cmd: cmds::PolicyCmd,
    },
    /// Show effective configuration and where each value comes from
    Config {
        #[command(subcommand)]
        cmd: cmds::ConfigCmd,
    },
    /// Interactive read-only troubleshooting over SSH (coming in phase 2)
    Troubleshoot(cmds::PhaseTwoArgs),
    /// Run as an MCP server over stdio (coming in phase 2)
    Mcp(cmds::PhaseTwoArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = cli.color;
    let res = match cli.cmd {
        Cmd::Review(a) => review::run(a, cli.config.as_deref(), color),
        Cmd::Lint(a) => cmds::lint(a, color),
        Cmd::Rules { json } => cmds::rules(json, color),
        Cmd::Redact(a) => cmds::redact(a),
        Cmd::Policy { cmd } => cmds::policy(cmd, cli.config.as_deref(), color),
        Cmd::Config { cmd } => cmds::config(cmd, cli.config.as_deref()),
        Cmd::Troubleshoot(_) => cmds::phase_two("troubleshoot", color),
        Cmd::Mcp(_) => cmds::phase_two("mcp", color),
    };
    match res {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            let s = Style::stderr(color);
            eprintln!("{} {e:#}", s.red(&s.bold("error:")));
            ExitCode::from(1)
        }
    }
}

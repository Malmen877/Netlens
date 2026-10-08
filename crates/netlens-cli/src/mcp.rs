//! `netlens mcp`: the read-only tools as an MCP server over stdio (rmcp).
//!
//! Tools: `review`, `lint`, `redact`, `vet_command`. All take text, not file
//! paths, so the server never reads files on behalf of a client, and none
//! touches a device: MCP has no human-approval channel, so SSH is not exposed
//! in v1. Results are deterministic and redacted; no model is called.

use crate::config;
use crate::output::redact_findings;
use anyhow::Result;
use clap::Args;
use netlens_core::audit::AuditLog;
use netlens_core::gate::CommandGate;
use netlens_core::redact::Redactor;
use netlens_core::{analyze, Input, Vendor};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Args, Debug)]
pub struct McpArgs {
    /// Audit log path [env NETLENS_AUDIT]
    #[arg(long, value_name = "PATH", conflicts_with = "no_audit")]
    pub audit: Option<PathBuf>,
    /// Do not write the audit log
    #[arg(long)]
    pub no_audit: bool,
}

/// Largest accepted text input (bytes).
const MAX_INPUT: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReviewReq {
    /// Running/before configuration text (use with `after`)
    #[serde(default)]
    pub before: Option<String>,
    /// Candidate/after configuration text (use with `before`)
    #[serde(default)]
    pub after: Option<String>,
    /// A unified diff instead of before/after
    #[serde(default)]
    pub diff: Option<String>,
    /// ios | junos | eos (default: autodetect)
    #[serde(default)]
    pub vendor: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LintReq {
    /// Configuration text
    pub config: String,
    /// ios | junos | eos (default: autodetect)
    #[serde(default)]
    pub vendor: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RedactReq {
    /// Config or log text
    pub text: String,
    /// Also replace IP addresses with IP4_n/IP6_n placeholders
    #[serde(default)]
    pub mask_ips: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VetReq {
    /// ios | junos | eos
    pub vendor: String,
    /// The proposed command, e.g. "show ip bgp summary"
    pub command: String,
}

#[derive(Clone)]
pub struct NetlensMcp {
    tool_router: ToolRouter<Self>,
    gate: Arc<CommandGate>,
    audit: Arc<AuditLog>,
}

fn parse_vendor(v: &Option<String>) -> Result<Option<Vendor>, String> {
    v.as_deref().map(|s| s.parse()).transpose()
}

fn too_big(parts: &[&Option<String>]) -> bool {
    parts
        .iter()
        .map(|p| p.as_ref().map(|s| s.len()).unwrap_or(0))
        .sum::<usize>()
        > MAX_INPUT
}

fn ok_json(v: Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::json(v)?]))
}

fn tool_error(msg: impl Into<String>) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![ContentBlock::text(msg)]))
}

#[tool_router]
impl NetlensMcp {
    pub fn new(gate: CommandGate, audit: AuditLog) -> Self {
        NetlensMcp {
            tool_router: Self::tool_router(),
            gate: Arc::new(gate),
            audit: Arc::new(audit),
        }
    }

    fn log(&self, tool: &str, input: &str, ok: bool) {
        let _ = self.audit.record(
            "mcp.tool",
            json!({"tool": tool, "input_sha256": netlens_core::sha256_hex(input.as_bytes()),
                   "input_bytes": input.len(), "ok": ok}),
        );
    }

    #[tool(
        description = "Deterministic pre-change review of a network config change (Cisco IOS/IOS-XE, Junos, Arista EOS). Pass `before` and `after` config text, or a unified `diff`. Returns the semantic changes, rule findings with evidence lines, and a deterministic rollback snippet. Secrets are redacted. Read-only: never touches a device."
    )]
    fn review(&self, Parameters(r): Parameters<ReviewReq>) -> Result<CallToolResult, McpError> {
        let key = format!(
            "{}\u{0}{}\u{0}{}",
            r.before.as_deref().unwrap_or(""),
            r.after.as_deref().unwrap_or(""),
            r.diff.as_deref().unwrap_or("")
        );
        if too_big(&[&r.before, &r.after, &r.diff]) {
            self.log("review", &key, false);
            return tool_error("input too large (limit 4 MiB)");
        }
        let vendor = match parse_vendor(&r.vendor) {
            Ok(v) => v,
            Err(e) => return tool_error(e),
        };
        let input = match (&r.before, &r.after, &r.diff) {
            (_, _, Some(d)) => Input::Diff(d),
            (Some(b), Some(a), None) => Input::Files {
                before: b,
                after: a,
            },
            _ => {
                self.log("review", &key, false);
                return tool_error("pass `before` and `after`, or `diff`");
            }
        };
        let a = match analyze(&input, vendor) {
            Ok(a) => a,
            Err(e) => {
                self.log("review", &key, false);
                return tool_error(e);
            }
        };
        let mut red = Redactor::new();
        let changes: Vec<Value> = a
            .diff
            .changes
            .iter()
            .map(|c| {
                json!({"id": c.id, "kind": c.kind, "section": c.section, "line": c.line,
                       "path": c.path.iter().map(|p| red.redact_line(p)).collect::<Vec<_>>(),
                       "folded": c.folded})
            })
            .collect();
        let findings = redact_findings(&a.findings, &mut red);
        let rollback: Vec<String> = a
            .rollback
            .lines
            .iter()
            .map(|l| red.redact_line(l))
            .collect();
        self.log("review", &key, true);
        ok_json(json!({
            "vendor": a.vendor.key(),
            "partial": a.partial,
            "summary": {"added": a.diff.added, "removed": a.diff.removed, "findings": findings.len(),
                        "counts": netlens_core::finding::SeverityCounts::of(&a.findings)},
            "changes": changes,
            "findings": findings,
            "notes": a.notes,
            "rollback": {"lines": rollback, "notes": a.rollback.notes},
            "redactions": red.count,
        }))
    }

    #[tool(
        description = "Lint a single network configuration (IOS/IOS-XE, Junos, EOS): risky or insecure settings with evidence lines. Secrets are redacted."
    )]
    fn lint(&self, Parameters(r): Parameters<LintReq>) -> Result<CallToolResult, McpError> {
        if r.config.len() > MAX_INPUT {
            return tool_error("input too large (limit 4 MiB)");
        }
        let vendor = match parse_vendor(&r.vendor) {
            Ok(v) => v,
            Err(e) => return tool_error(e),
        };
        let (cfg, _det, findings) = netlens_core::analyze_single(&r.config, vendor);
        let shown = redact_findings(&findings, &mut Redactor::new());
        self.log("lint", &r.config, true);
        ok_json(json!({"vendor": cfg.vendor.key(), "findings": shown}))
    }

    #[tool(
        description = "Redact secrets (passwords, keys, hashes, SNMP communities, PEM blocks) from config or log text, optionally masking IP addresses. Shows exactly what netlens would send to a model."
    )]
    fn redact(&self, Parameters(r): Parameters<RedactReq>) -> Result<CallToolResult, McpError> {
        if r.text.len() > MAX_INPUT {
            return tool_error("input too large (limit 4 MiB)");
        }
        let mut red = Redactor::new();
        let mut out = red.redact_text(&r.text);
        let mut masked = 0;
        if r.mask_ips {
            let mut m = netlens_core::ipmask::IpMasker::new();
            out = m.mask(&out);
            masked = m.len();
        }
        self.log("redact", &r.text, true);
        ok_json(json!({"text": out, "redactions": red.count, "masked_ips": masked}))
    }

    #[tool(
        description = "Check whether netlens' read-only command gate would allow a device command (allowlist + policy; the stricter wins). Returns the normalized command to send and its canonical form, or why it is denied. Does not run anything."
    )]
    fn vet_command(&self, Parameters(r): Parameters<VetReq>) -> Result<CallToolResult, McpError> {
        let vendor: Vendor = match r.vendor.parse() {
            Ok(v) => v,
            Err(e) => return tool_error(e),
        };
        let res = self.gate.vet(vendor, &r.command);
        self.log("vet_command", &r.command, true);
        ok_json(match res {
            Ok(v) => json!({"allowed": true, "send": v.command, "canonical": v.canonical,
                            "note": "allowed by the gate; running it still needs a human y/N in `netlens troubleshoot`"}),
            Err(e) => {
                json!({"allowed": false, "stage": e.stage, "kind": e.kind, "reason": e.reason})
            }
        })
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NetlensMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("netlens", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "netlens: read-only network config review. Tools take config/log TEXT. \
                 No tool can change or even connect to a device.",
            )
    }
}

pub fn run(a: McpArgs, config_flag: Option<&Path>) -> Result<u8> {
    let loaded = config::load(config_flag)?;
    let gate = config::gate(&loaded.file)?;
    let audit = if a.no_audit {
        AuditLog::disabled()
    } else {
        match config::audit_path(&loaded.file, a.audit.clone()) {
            Some((p, _)) => AuditLog::open(&p).unwrap_or_else(|_| AuditLog::disabled()),
            None => AuditLog::disabled(),
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let service = NetlensMcp::new(gate, audit)
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| anyhow::anyhow!("mcp: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("mcp: {e}"))?;
        anyhow::Ok(())
    })?;
    Ok(0)
}

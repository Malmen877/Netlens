//! Append-only JSONL audit log of every model call and (phase 2) every
//! command proposed, approved, rejected or run.

use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// `$XDG_STATE_HOME/netlens/audit.jsonl`, else `~/.local/state/netlens/audit.jsonl`.
pub fn default_path() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join("netlens").join("audit.jsonl"));
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|h| PathBuf::from(h).join(".local/state/netlens/audit.jsonl"))
}

/// RFC 3339 UTC timestamp with millisecond precision.
pub fn rfc3339_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs() as i64, d.subsec_millis())
}

fn rfc3339(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: Option<PathBuf>,
    session: String,
}

impl AuditLog {
    /// Open (create) the log file; fails early if it is not writable.
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLog {
            path: Some(path.to_path_buf()),
            session: new_session_id(),
        })
    }

    /// A no-op log (`--no-audit`).
    pub fn disabled() -> Self {
        AuditLog {
            path: None,
            session: new_session_id(),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    /// Append one event. `fields` must be a JSON object.
    pub fn record(&self, event: &str, fields: Value) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut obj = Map::new();
        obj.insert("ts".into(), json!(rfc3339_now()));
        obj.insert("session".into(), json!(self.session));
        obj.insert("event".into(), json!(event));
        obj.insert("netlens".into(), json!(env!("CARGO_PKG_VERSION")));
        if let Value::Object(m) = fields {
            obj.extend(m);
        }
        let mut line = serde_json::to_string(&Value::Object(obj))?;
        line.push('\n');
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(line.as_bytes())
    }

    /// Record a model call. Only the hash and size of the (already redacted)
    /// prompt are stored unless `store_prompt` is set.
    #[allow(clippy::too_many_arguments)]
    pub fn model_call(
        &self,
        model: &str,
        endpoint: &str,
        redacted_prompt: &str,
        response_bytes: usize,
        latency_ms: u128,
        ok: bool,
        error: Option<&str>,
        store_prompt: bool,
    ) -> io::Result<()> {
        let mut v = json!({
            "model": model,
            "endpoint": endpoint,
            "prompt_sha256": crate::sha256_hex(redacted_prompt.as_bytes()),
            "prompt_bytes": redacted_prompt.len(),
            "response_bytes": response_bytes,
            "latency_ms": latency_ms as u64,
            "ok": ok,
        });
        if let Some(e) = error {
            v["error"] = json!(e);
        }
        if store_prompt {
            v["prompt"] = json!(redacted_prompt);
        }
        self.record("model.call", v)
    }

    /// Record a command lifecycle event: `command.proposed`, `.approved`,
    /// `.rejected`, `.denied_by_policy`, `.run`.
    pub fn command(&self, event: &str, host: &str, command: &str, extra: Value) -> io::Result<()> {
        let mut v = json!({ "host": host, "command": command });
        if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
            m.extend(e);
        }
        self.record(&format!("command.{event}"), v)
    }
}

fn new_session_id() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}-{:x}", d.as_millis(), std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_791_331_200, 5), "2026-10-07T00:00:00.005Z");
        assert_eq!(rfc3339(951_782_400, 0), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        log.model_call(
            "qwen3:14b",
            "http://localhost:11434/v1",
            "redacted prompt",
            42,
            1234,
            true,
            None,
            false,
        )
        .unwrap();
        log.command(
            "proposed",
            "r1",
            "show ip bgp summary",
            json!({"reason": "check peers"}),
        )
        .unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "model.call");
        assert_eq!(lines[0]["prompt_bytes"], 15);
        assert!(lines[0].get("prompt").is_none());
        assert_eq!(lines[0]["prompt_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(lines[1]["event"], "command.proposed");
        assert_eq!(lines[1]["host"], "r1");
        assert_eq!(lines[0]["session"], lines[1]["session"]);
    }

    #[test]
    fn disabled_is_noop() {
        let log = AuditLog::disabled();
        log.record("x", json!({})).unwrap();
        assert!(log.path().is_none());
    }
}

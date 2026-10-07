//! Minimal Batfish client speaking the same v2 REST protocol as pybatfish
//! (coordinator port 9996, `/v2/...`, `X-Batfish-Version` header).
//!
//! Flow per review: create a throwaway network, upload `before` and `after`
//! snapshots (zip with `snapshot/configs/<host>.cfg`), queue parse work and
//! poll it, load question templates from the server, ask each question on
//! both snapshots (or differentially), turn new/changed rows into citable
//! [`Finding`]s with ids B1.., then delete the network.

use netlens_core::finding::{assign_ids, Evidence, Finding, Severity};
use netlens_core::section::Section;
use netlens_core::Vendor;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use std::time::{Duration, Instant};
use thiserror::Error;

/// pybatfish version we claim to be (the server checks it is present/compatible).
pub const CLIENT_VERSION: &str = "2025.7.7.2423";

#[derive(Debug, Error)]
pub enum BatfishError {
    #[error("cannot reach Batfish at {url}: {detail} (start it with `docker compose up -d batfish`, see docs/batfish.md)")]
    Unreachable { url: String, detail: String },
    #[error("Batfish returned HTTP {status} for {what}: {body}")]
    Http {
        status: u16,
        what: String,
        body: String,
    },
    #[error("unexpected Batfish response for {what}: {detail}")]
    Protocol { what: String, detail: String },
    #[error("Batfish work for {what} ended with {status}: {log}")]
    WorkFailed {
        what: String,
        status: String,
        log: String,
    },
    #[error("Batfish work for {0} did not finish within the timeout")]
    Timeout(String),
}

type Result<T> = std::result::Result<T, BatfishError>;

pub struct BatfishClient {
    base: String,
    agent: ureq::Agent,
    api_key: String,
    pub work_timeout: Duration,
}

/// Accept `http://host:9996`, `http://host` (adds :9996) or `host:port`.
pub fn normalize_url(url: &str) -> String {
    let mut u = url.trim().trim_end_matches('/').to_string();
    if !u.contains("://") {
        u = format!("http://{u}");
    }
    if u.ends_with("/v2") {
        u.truncate(u.len() - 3);
    }
    let host_part = u.split_once("://").map(|(_, r)| r).unwrap_or(&u);
    if !host_part.contains(':') {
        u.push_str(":9996");
    }
    format!("{u}/v2")
}

impl BatfishClient {
    pub fn new(url: &str, timeout: Duration) -> Self {
        BatfishClient {
            base: normalize_url(url),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout(timeout)
                .build(),
            api_key: "00000000000000000000000000000000".into(),
            work_timeout: timeout,
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn req(&self, method: &str, tail: &str) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{tail}", self.base))
            .set("X-Batfish-Apikey", &self.api_key)
            .set("X-Batfish-Version", CLIENT_VERSION)
    }

    fn map_err(&self, what: &str, e: ureq::Error) -> BatfishError {
        match e {
            ureq::Error::Status(status, r) => BatfishError::Http {
                status,
                what: what.to_string(),
                body: r
                    .into_string()
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect(),
            },
            ureq::Error::Transport(t) => BatfishError::Unreachable {
                url: self.base.clone(),
                detail: t.to_string(),
            },
        }
    }

    fn json_of(&self, what: &str, r: ureq::Response) -> Result<Value> {
        let s = r.into_string().map_err(|e| BatfishError::Protocol {
            what: what.into(),
            detail: e.to_string(),
        })?;
        if s.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&s).map_err(|e| BatfishError::Protocol {
            what: what.into(),
            detail: format!("{e}: {}", s.chars().take(200).collect::<String>()),
        })
    }

    pub fn version(&self) -> Result<Value> {
        let r = self
            .req("GET", "/version")
            .call()
            .map_err(|e| self.map_err("version", e))?;
        self.json_of("version", r)
    }

    pub fn init_network(&self, name: &str) -> Result<()> {
        self.req("POST", "/networks")
            .query("name", name)
            .call()
            .map_err(|e| self.map_err("init network", e))?;
        Ok(())
    }

    pub fn delete_network(&self, name: &str) -> Result<()> {
        self.req("DELETE", &format!("/networks/{name}"))
            .call()
            .map_err(|e| self.map_err("delete network", e))?;
        Ok(())
    }

    pub fn upload_snapshot(&self, network: &str, snapshot: &str, zip: &[u8]) -> Result<()> {
        self.req("POST", &format!("/networks/{network}/snapshots/{snapshot}"))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(zip)
            .map_err(|e| self.map_err("upload snapshot", e))?;
        Ok(())
    }

    fn work_item(network: &str, snapshot: &str, params: Value) -> (String, Value) {
        let id = uuid::Uuid::new_v4().to_string();
        let mut rp = Map::new();
        rp.insert("testrig".into(), json!(snapshot));
        if let Value::Object(m) = params {
            rp.extend(m);
        }
        let item = json!({
            "containerName": network,
            "id": id,
            "requestParams": Value::Object(rp),
            "testrigName": snapshot,
        });
        (id, item)
    }

    fn run_work(&self, network: &str, snapshot: &str, params: Value, what: &str) -> Result<()> {
        let (id, item) = Self::work_item(network, snapshot, params);
        self.req("POST", &format!("/networks/{network}/work"))
            .send_json(item)
            .map_err(|e| self.map_err(what, e))?;
        let start = Instant::now();
        let mut sleep = Duration::from_millis(100);
        loop {
            let r = self
                .req("GET", &format!("/networks/{network}/work/{id}"))
                .call()
                .map_err(|e| self.map_err(what, e))?;
            let v = self.json_of(what, r)?;
            let status = v
                .get("workstatus")
                .and_then(Value::as_str)
                .ok_or_else(|| BatfishError::Protocol {
                    what: what.into(),
                    detail: format!("no workstatus in {v}"),
                })?
                .to_string();
            match status.as_str() {
                "TERMINATEDNORMALLY" => return Ok(()),
                "TERMINATEDABNORMALLY"
                | "TERMINATEDBYUSER"
                | "ASSIGNMENTERROR"
                | "REQUEUEFAILURE" => {
                    let log = self
                        .req(
                            "GET",
                            &format!("/networks/{network}/snapshots/{snapshot}/worklog/{id}"),
                        )
                        .call()
                        .ok()
                        .and_then(|r| r.into_string().ok())
                        .unwrap_or_default();
                    return Err(BatfishError::WorkFailed {
                        what: what.into(),
                        status,
                        log: log.chars().take(500).collect(),
                    });
                }
                _ => {}
            }
            if start.elapsed() > self.work_timeout {
                return Err(BatfishError::Timeout(what.into()));
            }
            std::thread::sleep(sleep);
            sleep = (sleep * 3 / 2).min(Duration::from_secs(1));
        }
    }

    pub fn parse_snapshot(&self, network: &str, snapshot: &str) -> Result<()> {
        self.run_work(
            network,
            snapshot,
            json!({"si": "", "sv": "", "initinfo": ""}),
            &format!("parse snapshot {snapshot}"),
        )
    }

    /// Question templates keyed by name (values are JSON strings or objects).
    pub fn question_templates(&self) -> Result<Map<String, Value>> {
        let r = self
            .req("GET", "/question_templates")
            .query("verbose", "true")
            .call()
            .map_err(|e| self.map_err("question templates", e))?;
        match self.json_of("question templates", r)? {
            Value::Object(m) => Ok(m),
            other => Err(BatfishError::Protocol {
                what: "question templates".into(),
                detail: format!("expected object, got {other}"),
            }),
        }
    }

    pub fn ask(
        &self,
        network: &str,
        question: &Value,
        qname: &str,
        snapshot: &str,
        reference: Option<&str>,
    ) -> Result<Value> {
        self.req("PUT", &format!("/networks/{network}/questions/{qname}"))
            .set("Content-Type", "application/octet-stream")
            .send_string(&question.to_string())
            .map_err(|e| self.map_err("upload question", e))?;
        let mut params = json!({"answer": "", "questionname": qname});
        if let Some(r) = reference {
            params["deltatestrig"] = json!(r);
            params["differential"] = json!("");
        }
        self.run_work(network, snapshot, params, &format!("question {qname}"))?;
        let mut req = self
            .req(
                "GET",
                &format!("/networks/{network}/questions/{qname}/answer"),
            )
            .query("snapshot", snapshot);
        if let Some(r) = reference {
            req = req.query("referenceSnapshot", r);
        }
        let r = req.call().map_err(|e| self.map_err("get answer", e))?;
        self.json_of("answer", r)
    }
}

/// Find a template by name and turn it into a question with a unique instance name.
pub fn instantiate(templates: &Map<String, Value>, name: &str, instance: &str) -> Option<Value> {
    let pick = |v: &Value| -> Option<Value> {
        match v {
            Value::String(s) => serde_json::from_str(s).ok(),
            Value::Object(_) => Some(v.clone()),
            _ => None,
        }
    };
    let mut q = templates
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| pick(v))
        .or_else(|| {
            templates.values().filter_map(pick).find(|q| {
                q.pointer("/instance/instanceName")
                    .and_then(Value::as_str)
                    .map(|n| n.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            })
        })?;
    q.pointer_mut("/instance")?
        .as_object_mut()?
        .insert("instanceName".into(), json!(instance));
    Some(q)
}

/// Rows of a table answer.
pub fn rows(answer: &Value) -> Vec<Value> {
    answer
        .pointer("/answerElements/0/rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Human-readable cell value.
pub fn cell(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(a) => a.iter().map(cell).collect::<Vec<_>>().join(", "),
        Value::Object(o) => {
            if let (Some(f), Some(l)) = (o.get("filename"), o.get("lines")) {
                format!("{}:{}", cell(f), cell(l))
            } else if let Some(n) = o
                .get("name")
                .or_else(|| o.get("hostname"))
                .or_else(|| o.get("value"))
            {
                cell(n)
            } else {
                Value::Object(o.clone()).to_string()
            }
        }
    }
}

fn first_line(row: &Value) -> usize {
    for k in ["Lines", "Source_Lines"] {
        if let Some(l) = row
            .get(k)
            .and_then(|v| v.get("lines"))
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_u64)
        {
            return l as usize;
        }
    }
    0
}

/// The questions netlens asks, with how to read them.
pub struct QuestionSpec {
    pub name: &'static str,
    pub severity: Severity,
    pub section: Section,
    pub columns: &'static [&'static str],
    pub kind: QKind,
    pub title: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QKind {
    /// Report rows present in `after` but not in `before`.
    NewRows,
    /// Compare a status column per key; report changes and disappeared rows.
    Status {
        key: &'static [&'static str],
        status: &'static str,
    },
    /// Ask once with before as reference; every row is a difference.
    Differential,
}

pub const QUESTIONS: &[QuestionSpec] = &[
    QuestionSpec {
        name: "initIssues",
        severity: Severity::Medium,
        section: Section::Other,
        columns: &["Type", "Details", "Line_Text"],
        kind: QKind::NewRows,
        title: "Batfish parse/convert issue",
    },
    QuestionSpec {
        name: "undefinedReferences",
        severity: Severity::High,
        section: Section::RoutePolicy,
        columns: &["Struct_Type", "Ref_Name", "Context"],
        kind: QKind::NewRows,
        title: "Batfish: undefined reference",
    },
    QuestionSpec {
        name: "unusedStructures",
        severity: Severity::Low,
        section: Section::RoutePolicy,
        columns: &["Structure_Type", "Structure_Name"],
        kind: QKind::NewRows,
        title: "Batfish: unused structure",
    },
    QuestionSpec {
        name: "filterLineReachability",
        severity: Severity::Medium,
        section: Section::Acl,
        columns: &["Sources", "Unreachable_Line", "Blocking_Lines", "Reason"],
        kind: QKind::NewRows,
        title: "Batfish: unreachable filter line",
    },
    QuestionSpec {
        name: "bgpSessionCompatibility",
        severity: Severity::High,
        section: Section::Bgp,
        columns: &["Node", "Remote_IP", "Configured_Status"],
        kind: QKind::Status {
            key: &["Node", "VRF", "Remote_IP"],
            status: "Configured_Status",
        },
        title: "Batfish: BGP session configuration",
    },
    QuestionSpec {
        name: "bgpSessionStatus",
        severity: Severity::High,
        section: Section::Bgp,
        columns: &["Node", "Remote_IP", "Established_Status"],
        kind: QKind::Status {
            key: &["Node", "VRF", "Remote_IP"],
            status: "Established_Status",
        },
        title: "Batfish: BGP session status",
    },
    QuestionSpec {
        name: "ospfSessionCompatibility",
        severity: Severity::High,
        section: Section::Ospf,
        columns: &["Interface", "Remote_Interface", "Session_Status"],
        kind: QKind::Status {
            key: &["Interface", "VRF", "Remote_Interface"],
            status: "Session_Status",
        },
        title: "Batfish: OSPF session",
    },
    QuestionSpec {
        name: "differentialReachability",
        severity: Severity::High,
        section: Section::Other,
        columns: &["Flow", "Snapshot_Traces", "Reference_Traces"],
        kind: QKind::Differential,
        title: "Batfish: reachability changed",
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct QuestionOutcome {
    pub name: String,
    pub status: String,
    pub rows_before: usize,
    pub rows_after: usize,
    pub findings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatfishRun {
    pub url: String,
    pub version: Value,
    pub questions: Vec<QuestionOutcome>,
    pub findings: Vec<Finding>,
}

/// Hostname from config text (falls back to "device").
pub fn hostname(text: &str, vendor: Vendor) -> String {
    for l in text.lines() {
        let t = l.trim().trim_end_matches(';');
        let name = match vendor {
            Vendor::Junos => t
                .strip_prefix("set system host-name ")
                .or_else(|| t.strip_prefix("host-name ")),
            _ => t.strip_prefix("hostname "),
        };
        if let Some(n) = name {
            let n: String = n
                .trim()
                .trim_matches('"')
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                .collect();
            if !n.is_empty() {
                return n;
            }
        }
    }
    "device".into()
}

/// Build a single-device snapshot zip (`snapshot/configs/<host>.cfg`).
pub fn snapshot_zip(text: &str, vendor: Vendor) -> Vec<u8> {
    let host = hostname(text, vendor);
    let body = if vendor == Vendor::AristaEos && !text.starts_with("!RANCID-CONTENT-TYPE") {
        format!("!RANCID-CONTENT-TYPE: arista\n{text}")
    } else {
        text.to_string()
    };
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zw.start_file(format!("snapshot/configs/{host}.cfg"), opts)
            .expect("zip entry");
        zw.write_all(body.as_bytes()).expect("zip write");
        zw.finish().expect("zip finish");
    }
    buf.into_inner()
}

/// Read config files back out of a snapshot zip (used by the mock server and tests).
pub fn read_snapshot_zip(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(mut z) = zip::ZipArchive::new(Cursor::new(data)) {
        for i in 0..z.len() {
            if let Ok(mut f) = z.by_index(i) {
                if f.is_dir() {
                    continue;
                }
                let name = f.name().to_string();
                let mut s = String::new();
                if f.read_to_string(&mut s).is_ok() {
                    out.push((name, s));
                }
            }
        }
    }
    out
}

fn summarize(row: &Value, cols: &[&str]) -> String {
    cols.iter()
        .filter_map(|c| row.get(*c).map(|v| format!("{c}={}", cell(v))))
        .collect::<Vec<_>>()
        .join("; ")
}

fn key_of(row: &Value, key: &[&str]) -> String {
    key.iter()
        .map(|k| row.get(*k).map(cell).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("|")
}

const MAX_PER_QUESTION: usize = 10;

/// Run the whole Batfish review. Errors only for connectivity/setup problems;
/// individual question failures are recorded in the outcome list.
pub fn run_review(
    url: &str,
    before: &str,
    after: &str,
    vendor: Vendor,
    timeout: Duration,
) -> Result<BatfishRun> {
    let c = BatfishClient::new(url, timeout);
    let version = c.version()?;
    let network = format!(
        "netlens-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    c.init_network(&network)?;
    let result = (|| -> Result<(Vec<QuestionOutcome>, Vec<Finding>)> {
        c.upload_snapshot(&network, "before", &snapshot_zip(before, vendor))?;
        c.parse_snapshot(&network, "before")?;
        c.upload_snapshot(&network, "after", &snapshot_zip(after, vendor))?;
        c.parse_snapshot(&network, "after")?;
        let templates = c.question_templates()?;
        let mut outcomes = Vec::new();
        let mut findings = Vec::new();
        for spec in QUESTIONS {
            let mut out = QuestionOutcome {
                name: spec.name.into(),
                status: "ok".into(),
                rows_before: 0,
                rows_after: 0,
                findings: 0,
                error: None,
            };
            let ask = |snap: &str, reference: Option<&str>| -> Result<Vec<Value>> {
                let qname = format!(
                    "__netlens_{}_{}",
                    spec.name,
                    &uuid::Uuid::new_v4().simple().to_string()[..8]
                );
                let q = instantiate(&templates, spec.name, &qname).ok_or_else(|| {
                    BatfishError::Protocol {
                        what: spec.name.into(),
                        detail: "question template not available on this server".into(),
                    }
                })?;
                Ok(rows(&c.ask(&network, &q, &qname, snap, reference)?))
            };
            let res: Result<Vec<Finding>> = (|| {
                let mut fs = Vec::new();
                match spec.kind {
                    QKind::Differential => {
                        let r = ask("after", Some("before"))?;
                        out.rows_after = r.len();
                        for row in r.iter().take(MAX_PER_QUESTION) {
                            fs.push(Finding::new(&format!("BF-{}", spec.name), spec.severity, spec.section, spec.title.to_string(), "Batfish found flows whose forwarding outcome differs between before and after.").with(Evidence::after(0, summarize(row, spec.columns))));
                        }
                    }
                    QKind::NewRows => {
                        let b = ask("before", None)?;
                        let a = ask("after", None)?;
                        out.rows_before = b.len();
                        out.rows_after = a.len();
                        let bset: BTreeSet<String> =
                            b.iter().map(|r| summarize(r, spec.columns)).collect();
                        let new: Vec<&Value> = a
                            .iter()
                            .filter(|r| !bset.contains(&summarize(r, spec.columns)))
                            .collect();
                        for row in new.iter().take(MAX_PER_QUESTION) {
                            let mut sev = spec.severity;
                            if spec.name == "filterLineReachability"
                                && row.get("Different_Action").and_then(Value::as_bool)
                                    == Some(true)
                            {
                                sev = Severity::High;
                            }
                            let headline = spec
                                .columns
                                .first()
                                .and_then(|c0| row.get(*c0))
                                .map(cell)
                                .unwrap_or_default();
                            let name2 = spec
                                .columns
                                .get(1)
                                .and_then(|c1| row.get(*c1))
                                .map(cell)
                                .unwrap_or_default();
                            fs.push(Finding::new(&format!("BF-{}", spec.name), sev, spec.section, format!("{}: {} {}", spec.title, headline, name2).trim().to_string(), "Reported by Batfish for the after snapshot and not present before the change.").with(Evidence::after(first_line(row), summarize(row, spec.columns))));
                        }
                        if new.len() > MAX_PER_QUESTION {
                            fs.push(Finding::new(
                                &format!("BF-{}", spec.name),
                                Severity::Info,
                                spec.section,
                                format!(
                                    "{}: {} more rows not shown",
                                    spec.title,
                                    new.len() - MAX_PER_QUESTION
                                ),
                                "Run the question in pybatfish for the full table.",
                            ));
                        }
                    }
                    QKind::Status { key, status } => {
                        let b = ask("before", None)?;
                        let a = ask("after", None)?;
                        out.rows_before = b.len();
                        out.rows_after = a.len();
                        for brow in &b {
                            let k = key_of(brow, key);
                            let bs = brow.get(status).map(cell).unwrap_or_default();
                            match a.iter().find(|r| key_of(r, key) == k) {
                                None => fs.push(Finding::new(&format!("BF-{}", spec.name), spec.severity, spec.section, format!("{}: session {} no longer present", spec.title, k.replace('|', " ")), "Batfish no longer computes this session in the after snapshot (removed or shut).").with(Evidence::before(0, summarize(brow, spec.columns)))),
                                Some(arow) => {
                                    let as_ = arow.get(status).map(cell).unwrap_or_default();
                                    if as_ != bs {
                                        fs.push(Finding::new(&format!("BF-{}", spec.name), spec.severity, spec.section, format!("{}: {} {} -> {}", spec.title, k.replace('|', " "), bs, as_), "Batfish computes a different session state after the change.").with(Evidence::before(0, summarize(brow, spec.columns))).with(Evidence::after(0, summarize(arow, spec.columns))));
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(fs)
            })();
            match res {
                Ok(fs) => {
                    out.findings = fs.len();
                    findings.extend(fs);
                }
                Err(e) => {
                    out.status = "error".into();
                    out.error = Some(e.to_string());
                }
            }
            outcomes.push(out);
        }
        Ok((outcomes, findings))
    })();
    let _ = c.delete_network(&network);
    let (questions, mut findings) = result?;
    assign_ids(&mut findings, "B");
    Ok(BatfishRun {
        url: c.base().to_string(),
        version,
        questions,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            normalize_url("http://localhost:9996"),
            "http://localhost:9996/v2"
        );
        assert_eq!(normalize_url("localhost"), "http://localhost:9996/v2");
        assert_eq!(normalize_url("http://bf:9996/v2/"), "http://bf:9996/v2");
    }

    #[test]
    fn zip_roundtrip_and_hostname() {
        let z = snapshot_zip("hostname edge-r1\ninterface Gi1\n", Vendor::CiscoIos);
        let files = read_snapshot_zip(&z);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "snapshot/configs/edge-r1.cfg");
        assert!(files[0].1.starts_with("hostname edge-r1"));
        assert_eq!(
            hostname("system {\n    host-name mx1;\n}\n", Vendor::Junos),
            "mx1"
        );
        let e = read_snapshot_zip(&snapshot_zip("hostname leaf1\n", Vendor::AristaEos));
        assert!(e[0].1.starts_with("!RANCID-CONTENT-TYPE: arista"));
    }

    #[test]
    fn template_instantiation() {
        let mut t = Map::new();
        t.insert("undefinedReferences".into(), json!("{\"class\":\"org.batfish.question.UndefinedReferencesQuestion\",\"instance\":{\"instanceName\":\"undefinedReferences\",\"variables\":{}}}"));
        let q = instantiate(&t, "undefinedreferences", "__x").unwrap();
        assert_eq!(q["instance"]["instanceName"], "__x");
        assert!(instantiate(&t, "nope", "__y").is_none());
    }

    #[test]
    fn cells() {
        assert_eq!(
            cell(&json!({"filename": "configs/r1.cfg", "lines": [12, 13]})),
            "configs/r1.cfg:12, 13"
        );
        assert_eq!(cell(&json!({"name": "r1", "id": "x"})), "r1");
        assert_eq!(
            first_line(&json!({"Lines": {"filename": "f", "lines": [42]}})),
            42
        );
    }
}

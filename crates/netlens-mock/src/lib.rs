//! Mock servers for tests, CI and demos (no GPU, no Docker needed):
//!
//! * [`spawn_llm`]: an OpenAI-compatible `/v1/chat/completions` endpoint
//!   backed by the deterministic [`netlens_llm::mock`] model.
//! * [`spawn_batfish`]: enough of the Batfish v2 REST API for
//!   `netlens review --batfish`. Answers are computed from netlens' own
//!   parser, so they are plausible but are NOT real Batfish results.

use netlens_core::facts::{extract, Facts};
use netlens_core::{parse::parse, vendor::detect};
use netlens_llm::client::ChatMessage;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tiny_http::{Header, Method, Request, Response, Server};

pub struct MockServer {
    pub url: String,
    server: Arc<Server>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Stop the server and wait for its thread.
    pub fn stop(mut self) {
        self.shutdown();
    }
    fn shutdown(&mut self) {
        self.server.unblock();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn json_resp(status: u16, v: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(v.to_string().into_bytes())
        .with_status_code(status)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("header"),
        )
}

fn body_of(req: &mut Request) -> Vec<u8> {
    let mut b = Vec::new();
    let _ = req.as_reader().read_to_end(&mut b);
    b
}

fn spawn<F>(addr: &str, mut handler: F) -> std::io::Result<MockServer>
where
    F: FnMut(&mut Request) -> Response<std::io::Cursor<Vec<u8>>> + Send + 'static,
{
    let server = Arc::new(Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?);
    let port = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(0);
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("127.0.0.1");
    let host = if host == "0.0.0.0" { "127.0.0.1" } else { host };
    let s2 = server.clone();
    let handle = std::thread::spawn(move || {
        for mut req in s2.incoming_requests() {
            let resp = handler(&mut req);
            let _ = req.respond(resp);
        }
    });
    Ok(MockServer {
        url: format!("http://{host}:{port}"),
        server,
        handle: Some(handle),
    })
}

// ---------------------------------------------------------------- LLM

/// Start the mock OpenAI-compatible server. Use `127.0.0.1:0` for a free port.
/// The base URL to pass to netlens is `<url>/v1`.
pub fn spawn_llm(addr: &str) -> std::io::Result<MockServer> {
    spawn(addr, |req| {
        let path = req.url().split('?').next().unwrap_or("").to_string();
        match (req.method().clone(), path.as_str()) {
            (Method::Get, "/v1/models") | (Method::Get, "/models") => json_resp(
                200,
                &json!({"object": "list", "data": [{"id": "netlens-mock", "object": "model", "owned_by": "netlens"}]}),
            ),
            (Method::Post, "/v1/chat/completions") | (Method::Post, "/chat/completions") => {
                let body: Value = match serde_json::from_slice(&body_of(req)) {
                    Ok(v) => v,
                    Err(e) => {
                        return json_resp(
                            400,
                            &json!({"error": {"message": format!("bad json: {e}")}}),
                        )
                    }
                };
                let msgs: Vec<ChatMessage> = body["messages"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|m| ChatMessage {
                                role: m["role"].as_str().unwrap_or("user").to_string(),
                                content: m["content"].as_str().unwrap_or("").to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if msgs.is_empty() {
                    return json_resp(400, &json!({"error": {"message": "messages is required"}}));
                }
                let model = body["model"].as_str().unwrap_or("netlens-mock").to_string();
                let content = netlens_llm::mock::respond(&msgs);
                json_resp(
                    200,
                    &json!({
                        "id": "chatcmpl-mock",
                        "object": "chat.completion",
                        "created": 0,
                        "model": model,
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                    }),
                )
            }
            _ => json_resp(
                404,
                &json!({"error": {"message": format!("no route {path}")}}),
            ),
        }
    })
}

// ------------------------------------------------------------ Batfish

#[derive(Default)]
struct BfState {
    /// (network, snapshot) -> list of (file name, text)
    snapshots: HashMap<(String, String), Vec<(String, String)>>,
    /// (network, question) -> question json
    questions: HashMap<(String, String), Value>,
    networks: Vec<String>,
}

const TEMPLATES: &[&str] = &[
    "initIssues",
    "undefinedReferences",
    "unusedStructures",
    "filterLineReachability",
    "bgpSessionCompatibility",
    "bgpSessionStatus",
    "ospfSessionCompatibility",
    "differentialReachability",
];

fn templates() -> Value {
    let mut m = Map::new();
    for t in TEMPLATES {
        let mut c = t.chars();
        let class = format!(
            "org.batfish.question.{}{}Question",
            c.next().map(|x| x.to_ascii_uppercase()).unwrap_or('X'),
            c.as_str()
        );
        let q = json!({
            "class": class,
            "differential": *t == "differentialReachability",
            "instance": {"instanceName": t, "description": format!("mock {t}"), "variables": {}}
        });
        m.insert(t.to_string(), Value::String(q.to_string()));
    }
    Value::Object(m)
}

fn table(rows: Vec<Value>) -> Value {
    json!({
        "question": {},
        "status": "SUCCESS",
        "answerElements": [{"class": "org.batfish.datamodel.table.TableAnswerElement", "metadata": {"columnMetadata": []}, "rows": rows}]
    })
}

fn facts_of(files: &[(String, String)]) -> Vec<(String, String, Facts)> {
    files
        .iter()
        .map(|(name, text)| {
            let vendor = detect(text).vendor;
            let cfg = parse(text, vendor);
            let node = netlens_batfish::hostname(text, vendor);
            let fname = name.trim_start_matches("snapshot/").to_string();
            (node, fname, extract(&cfg))
        })
        .collect()
}

fn lines(fname: &str, line: usize) -> Value {
    json!({"filename": fname, "lines": [line]})
}

fn answer(question: &str, files: &[(String, String)]) -> Value {
    let mut rows = Vec::new();
    for (node, fname, f) in facts_of(files) {
        let v = f.vendor;
        match question {
            "undefinedReferences" => {
                for r in &f.refs {
                    if !f.is_defined(r.kind, &r.name) {
                        rows.push(json!({"File_Name": fname, "Struct_Type": r.kind.name(v), "Ref_Name": r.name, "Context": r.loc.text.trim(), "Lines": lines(&fname, r.loc.line)}));
                    }
                }
            }
            "unusedStructures" => {
                for ((kind, name), loc) in &f.defs {
                    if f.refs_to(*kind, name).is_empty() {
                        rows.push(json!({"Structure_Type": kind.name(v), "Structure_Name": name, "Source_Lines": lines(&fname, loc.line)}));
                    }
                }
            }
            "filterLineReachability" => {
                for acl in f.acls.values() {
                    if let Some(pos) = acl.entries.iter().position(|e| e.catch_all) {
                        let blocker = &acl.entries[pos];
                        for e in &acl.entries[pos + 1..] {
                            rows.push(json!({"Sources": [format!("{node}: {}", acl.name)], "Unreachable_Line": e.content, "Unreachable_Line_Action": format!("{:?}", e.action).to_uppercase(), "Blocking_Lines": [blocker.content], "Different_Action": e.action != blocker.action, "Reason": "BLOCKING_LINES", "Additional_Info": null}));
                        }
                    }
                }
            }
            "bgpSessionCompatibility" | "bgpSessionStatus" => {
                let local_as = f.bgp.asn.as_ref().map(|(a, _)| a.clone());
                for p in f.bgp.peers.values().filter(|p| !p.is_group) {
                    // Batfish does not compute sessions for shut/deactivated neighbors.
                    if p.shutdown.is_some() {
                        continue;
                    }
                    let remote_as = p.remote_as.as_ref().map(|(a, _)| a.clone());
                    let ebgp = remote_as != local_as;
                    let mut row = json!({"Node": node, "VRF": "default", "Local_AS": local_as, "Local_Interface": null, "Local_IP": null, "Remote_AS": remote_as, "Remote_Node": null, "Remote_Interface": null, "Remote_IP": p.key, "Address_Families": ["IPV4_UNICAST"], "Session_Type": if ebgp {"EBGP_SINGLEHOP"} else {"IBGP"}});
                    if question == "bgpSessionStatus" {
                        row["Established_Status"] = json!("NOT_ESTABLISHED");
                    } else {
                        row["Configured_Status"] = json!("UNKNOWN_REMOTE");
                    }
                    rows.push(row);
                }
            }
            _ => {}
        }
    }
    table(rows)
}

/// Start the mock Batfish coordinator. Pass `<url>` to `--batfish`.
pub fn spawn_batfish(addr: &str) -> std::io::Result<MockServer> {
    let state = Arc::new(Mutex::new(BfState::default()));
    spawn(addr, move |req| {
        if !req
            .headers()
            .iter()
            .any(|h| h.field.equiv("X-Batfish-Version"))
        {
            return json_resp(400, &json!("missing X-Batfish-Version header"));
        }
        let url = req.url().to_string();
        let (path, query) = url.split_once('?').unwrap_or((&url, ""));
        let q: HashMap<&str, &str> = query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let method = req.method().clone();
        let body = body_of(req);
        let mut st = state.lock().expect("mock state");
        match (method, parts.as_slice()) {
            (Method::Get, ["v2", "version"]) => json_resp(
                200,
                &json!({"Batfish": "netlens-mock", "api_version": "2.0", "mock": true}),
            ),
            (Method::Get, ["v2", "question_templates"]) => json_resp(200, &templates()),
            (Method::Post, ["v2", "networks"]) => match q.get("name") {
                Some(n) => {
                    st.networks.push(n.to_string());
                    json_resp(200, &Value::Null)
                }
                None => json_resp(400, &json!("name required")),
            },
            (Method::Delete, ["v2", "networks", n]) => {
                let n = n.to_string();
                st.networks.retain(|x| *x != n);
                st.snapshots.retain(|(net, _), _| *net != n);
                st.questions.retain(|(net, _), _| *net != n);
                json_resp(200, &Value::Null)
            }
            (Method::Post, ["v2", "networks", n, "snapshots", s]) => {
                if !st.networks.iter().any(|x| x == n) {
                    return json_resp(404, &json!(format!("network {n} not found")));
                }
                let files = netlens_batfish::read_snapshot_zip(&body);
                if files.is_empty() {
                    return json_resp(400, &json!("snapshot zip is empty or invalid"));
                }
                st.snapshots.insert((n.to_string(), s.to_string()), files);
                json_resp(200, &Value::Null)
            }
            (Method::Post, ["v2", "networks", n, "work"]) => {
                let item: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let snap = item
                    .pointer("/requestParams/testrig")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if item.get("id").is_none()
                    || !st
                        .snapshots
                        .contains_key(&(n.to_string(), snap.to_string()))
                {
                    return json_resp(400, &json!("bad work item or unknown snapshot"));
                }
                json_resp(200, &Value::Null)
            }
            (Method::Get, ["v2", "networks", _n, "work", _id]) => json_resp(
                200,
                &json!({"workstatus": "TERMINATEDNORMALLY", "taskstatus": "{}"}),
            ),
            (Method::Put, ["v2", "networks", n, "questions", qn]) => {
                match serde_json::from_slice::<Value>(&body) {
                    Ok(v) => {
                        st.questions.insert((n.to_string(), qn.to_string()), v);
                        json_resp(200, &Value::Null)
                    }
                    Err(e) => json_resp(400, &json!(format!("bad question: {e}"))),
                }
            }
            (Method::Get, ["v2", "networks", n, "questions", qn, "answer"]) => {
                let Some(qj) = st.questions.get(&(n.to_string(), qn.to_string())) else {
                    return json_resp(404, &json!("question not found"));
                };
                let class = qj["class"].as_str().unwrap_or("");
                let name = TEMPLATES
                    .iter()
                    .find(|t| {
                        class
                            .to_ascii_lowercase()
                            .ends_with(&format!("{}question", t.to_ascii_lowercase()))
                    })
                    .copied()
                    .unwrap_or("");
                let snap = q.get("snapshot").copied().unwrap_or("");
                let Some(files) = st.snapshots.get(&(n.to_string(), snap.to_string())) else {
                    return json_resp(404, &json!("snapshot not found"));
                };
                json_resp(200, &answer(name, files))
            }
            _ => json_resp(404, &json!(format!("mock batfish: no route {path}"))),
        }
    })
}

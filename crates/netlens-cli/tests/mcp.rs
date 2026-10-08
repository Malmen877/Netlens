//! `netlens mcp`: speak JSON-RPC over stdio to the real binary, list the
//! tools and call them.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Server {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
}

impl Server {
    fn start() -> Self {
        let home = std::env::temp_dir().join("netlens-mcp-test-home");
        std::fs::create_dir_all(&home).unwrap();
        let mut child = Command::new(assert_cmd::cargo::cargo_bin("netlens"))
            .args(["mcp", "--no-audit"])
            .env("HOME", &home)
            .env_remove("NETLENS_CONFIG")
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Server { child, out }
    }

    fn send(&mut self, v: Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    }

    fn response(&mut self, id: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < deadline, "no response for id {id}");
            let mut line = String::new();
            if self.out.read_line(&mut line).unwrap() == 0 {
                panic!("server closed stdout before answering id {id}");
            }
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }

    fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                         "params": {"name": name, "arguments": args}}));
        let r = self.response(id);
        let res = &r["result"];
        assert!(res.is_object(), "{r}");
        res.clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn payload(res: &Value) -> Value {
    serde_json::from_str(res["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn lists_tools_and_calls_them() {
    let mut s = Server::start();
    s.send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "netlens-test", "version": "0"}}}),
    );
    let init = s.response(1);
    assert_eq!(init["result"]["serverInfo"]["name"], "netlens");
    s.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    s.send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let list = s.response(2);
    let mut names: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["lint", "redact", "review", "vet_command"]);

    // vet_command: read-only gate, nothing runs
    let r = payload(&s.call(
        3,
        "vet_command",
        json!({"vendor": "ios", "command": "sh ip int br"}),
    ));
    assert_eq!(r["allowed"], true);
    assert_eq!(r["canonical"], "show ip interface brief");
    let r = payload(&s.call(
        4,
        "vet_command",
        json!({"vendor": "junos", "command": "request system reboot"}),
    ));
    assert_eq!(r["allowed"], false);

    // review: deterministic findings, secrets redacted
    let before = std::fs::read_to_string(root().join("examples/ios-xe/before.cfg")).unwrap();
    let after = std::fs::read_to_string(root().join("examples/ios-xe/after.cfg")).unwrap();
    let res = s.call(5, "review", json!({"before": before, "after": after}));
    assert_eq!(res["isError"], false);
    let r = payload(&res);
    assert_eq!(r["vendor"], "ios");
    assert!(r["findings"].as_array().unwrap().len() >= 5);
    let raw = r.to_string();
    assert!(raw.contains("NL-BGP-002"));
    assert!(!raw.contains("N3tM0n-R0"), "SNMP community leaked");

    // redact
    let r = payload(&s.call(6, "redact", json!({"text": "snmp-server community N3tM0n-R0 RO\ninterface Gi1\n ip address 192.0.2.1 255.255.255.0\n", "mask_ips": true})));
    let t = r["text"].as_str().unwrap();
    assert!(!t.contains("N3tM0n-R0") && !t.contains("192.0.2.1"), "{t}");

    // lint
    let r = payload(&s.call(7, "lint", json!({"config": after})));
    assert!(!r["findings"].as_array().unwrap().is_empty());

    // bad input is a tool error, not a crash
    let res = s.call(8, "review", json!({"before": "x"}));
    assert_eq!(res["isError"], true);
}

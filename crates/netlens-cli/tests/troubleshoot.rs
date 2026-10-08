//! End-to-end tests for `netlens troubleshoot` against the recorded
//! scenarios (mock device) with the scripted mock model.

use assert_cmd::Command;
use netlens_allowlist::fixtures::{fixtures_root, scenario_dirs, Scenario};
use serde_json::Value;
use std::path::Path;

fn netlens() -> Command {
    let home = std::env::temp_dir().join("netlens-troubleshoot-test-home");
    std::fs::create_dir_all(&home).unwrap();
    let mut c = Command::cargo_bin("netlens").unwrap();
    c.env("HOME", &home).env("NO_COLOR", "1");
    for k in [
        "NETLENS_MODEL_URL",
        "NETLENS_MODEL",
        "NETLENS_API_KEY",
        "NETLENS_CONFIG",
        "NETLENS_AUDIT",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
    ] {
        c.env_remove(k);
    }
    c
}

fn audit_events(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn run_json(args: &[&str], stdin: Option<&str>) -> (Value, i32) {
    let mut c = netlens();
    c.args(args);
    if let Some(s) = stdin {
        c.write_stdin(s);
    }
    let out = c.output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "bad JSON ({e}); stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (v, out.status.code().unwrap_or(-1))
}

#[test]
fn all_five_scenarios_end_to_end() {
    let dirs = scenario_dirs(fixtures_root()).unwrap();
    assert_eq!(dirs.len(), 5);
    for dir in dirs {
        let sc = Scenario::load(&dir).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let audit = tmp.path().join("audit.jsonl");
        let d = dir.to_str().unwrap();
        let (r, code) = run_json(
            &[
                "troubleshoot",
                "--mock-device",
                d,
                "--model-url",
                "mock://",
                "--auto-approve",
                "--json",
                "--audit-prompts",
                "--audit",
                audit.to_str().unwrap(),
            ],
            None,
        );
        let name = dir.display().to_string();
        assert_eq!(code, 0, "{name}");
        assert_eq!(r["outcome"], "answered", "{name}");
        assert_eq!(r["unverified"], false, "{name}");
        assert_eq!(
            r["root_cause"].as_str().unwrap(),
            sc.root_cause.text.trim(),
            "{name}"
        );
        // Every key evidence line is quoted and validated against what the model saw.
        let ev = r["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), sc.key_evidence.len(), "{name}: {ev:#?}");
        for k in &sc.key_evidence {
            assert!(
                ev.iter()
                    .any(|e| e["quote"].as_str().unwrap() == k.line.trim()),
                "{name}: missing evidence {}",
                k.line
            );
        }
        // The unsafe proposal was blocked and the loop continued.
        let steps = r["steps"].as_array().unwrap();
        let rej = steps
            .iter()
            .position(|s| s["outcome"] == "rejected")
            .unwrap_or_else(|| panic!("{name}: no rejected step"));
        assert!(steps[rej + 1..].iter().any(|s| s["outcome"] == "ran"));
        assert!(steps.len() <= 8);
        // Audit: proposals, the rejection, approvals, executions, model calls.
        let evs = audit_events(&audit);
        let count = |e: &str| evs.iter().filter(|x| x["event"] == e).count();
        assert_eq!(count("troubleshoot.start"), 1);
        assert_eq!(count("troubleshoot.end"), 1);
        assert_eq!(count("command.rejected"), 1, "{name}");
        assert_eq!(count("command.proposed"), steps.len());
        assert_eq!(
            count("command.exec"),
            steps.iter().filter(|s| s["outcome"] == "ran").count()
        );
        assert!(evs
            .iter()
            .filter(|x| x["event"] == "command.approval")
            .all(|x| x["auto"] == true));
        assert_eq!(
            count("model.call"),
            r["model_calls"].as_u64().unwrap() as usize
        );
        // Secrets never reach the model (prompts are stored in full here).
        let raw = std::fs::read_to_string(&audit).unwrap();
        assert!(
            !raw.contains("FIXTURE-PLACEHOLDER"),
            "{name}: secret in prompt"
        );
    }
}

#[test]
fn fabricated_quotes_and_unsafe_suggestions_are_dropped() {
    let d = fixtures_root().join("ios/bgp-flap-mtu");
    let (r, _) = run_json(
        &[
            "troubleshoot",
            "--mock-device",
            d.to_str().unwrap(),
            "--model-url",
            "mock://",
            "--auto-approve",
            "--json",
            "--no-audit",
        ],
        None,
    );
    let dropped = r["dropped_evidence"].as_array().unwrap();
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0]["cite"], "O3");
    assert!(dropped[0]["reason"]
        .as_str()
        .unwrap()
        .contains("not found verbatim"));
    assert_eq!(r["next_checks"][0], "show ip bgp neighbors");
    assert_eq!(r["rejected_next_checks"][0]["command"], "clear ip bgp *");
}

fn write_script(dir: &Path, replies: Value) -> String {
    let p = dir.join("script.json");
    std::fs::write(&p, serde_json::json!({ "replies": replies }).to_string()).unwrap();
    p.display().to_string()
}

#[test]
fn unsafe_proposals_are_rejected_and_the_loop_continues() {
    let tmp = tempfile::tempdir().unwrap();
    let audit = tmp.path().join("audit.jsonl");
    let unsafe_cmds = [
        "configure terminal",
        "reload",
        "show ip bgp summary\nreload",
        "show running-config | redirect flash:x.txt",
        "terminal length 0",
        "ping 198.51.100.2",
    ];
    let mut replies: Vec<Value> = unsafe_cmds
        .iter()
        .map(|c| serde_json::json!({"action": "run", "command": c, "reason": "test"}))
        .collect();
    replies.push(
        serde_json::json!({"action": "run", "command": "show ip bgp summary", "reason": "safe"}),
    );
    replies.push(serde_json::json!({"action": "final", "root_cause": "x",
        "evidence": [{"cite": "O7", "quote": "198.51.100.2"}], "next_checks": []}));
    let script = write_script(tmp.path(), Value::Array(replies));
    let d = fixtures_root().join("ios/bgp-flap-mtu");
    let (r, code) = run_json(
        &[
            "troubleshoot",
            "--mock-device",
            d.to_str().unwrap(),
            "--model-url",
            "mock://",
            "--mock-script",
            &script,
            "--auto-approve",
            "--json",
            "--audit",
            audit.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0);
    let steps = r["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 7);
    for s in &steps[..6] {
        assert_eq!(s["outcome"], "rejected", "{s}");
    }
    assert_eq!(steps[6]["outcome"], "ran");
    assert_eq!(r["evidence"].as_array().unwrap().len(), 1);
    let evs = audit_events(&audit);
    assert_eq!(
        evs.iter()
            .filter(|e| e["event"] == "command.rejected")
            .count(),
        6
    );
    let execs: Vec<_> = evs
        .iter()
        .filter(|e| e["event"] == "command.exec")
        .collect();
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0]["sent"], "show ip bgp summary");
}

#[test]
fn operator_can_decline_and_the_step_cap_holds() {
    let tmp = tempfile::tempdir().unwrap();
    let replies: Vec<Value> = (0..12)
        .map(|i| {
            serde_json::json!({"action": "run",
                "command": if i % 2 == 0 { "show ip bgp summary" } else { "show interfaces description" },
                "reason": "loop"})
        })
        .collect();
    let script = write_script(tmp.path(), Value::Array(replies));
    let d = fixtures_root().join("ios/bgp-flap-mtu");
    // No --auto-approve: answers come from stdin (allowed for the mock device only).
    let (r, code) = run_json(
        &[
            "troubleshoot",
            "--mock-device",
            d.to_str().unwrap(),
            "--model-url",
            "mock://",
            "--mock-script",
            &script,
            "--max-steps",
            "3",
            "--json",
            "--no-audit",
        ],
        Some("n\ny\ny\ny\n"),
    );
    assert_eq!(code, 1, "no final answer -> exit 1");
    assert_eq!(r["outcome"], "no-answer");
    let steps = r["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0]["outcome"], "declined");
    assert_eq!(steps[1]["outcome"], "ran");
    assert_eq!(steps[2]["outcome"], "ran");
}

#[test]
fn real_devices_need_a_tty_and_auto_approve_needs_the_mock() {
    netlens()
        .args([
            "troubleshoot",
            "--host",
            "r1.example",
            "--vendor",
            "ios",
            "BGP down",
        ])
        .write_stdin("y\n")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("interactive terminal"));
    netlens()
        .args([
            "troubleshoot",
            "--host",
            "r1.example",
            "--vendor",
            "ios",
            "--auto-approve",
            "x",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("only allowed with --mock-device"));
    netlens()
        .args([
            "troubleshoot",
            "--host",
            "-oProxyCommand=x",
            "--vendor",
            "ios",
            "x",
        ])
        .assert()
        .failure();
}

#[test]
fn model_protocol_errors_end_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(
        tmp.path(),
        serde_json::json!(["I think it's MTU.", "still no json", "nope"]),
    );
    let d = fixtures_root().join("ios/bgp-flap-mtu");
    let (r, code) = run_json(
        &[
            "troubleshoot",
            "--mock-device",
            d.to_str().unwrap(),
            "--model-url",
            "mock://",
            "--mock-script",
            &script,
            "--auto-approve",
            "--json",
            "--no-audit",
        ],
        None,
    );
    assert_eq!(code, 1);
    assert_eq!(r["outcome"], "model-error");
    assert!(r["error"].as_str().unwrap().contains("JSON protocol"));
}

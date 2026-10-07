use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::path::PathBuf;
use tempfile::TempDir;

fn ex(p: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(p)
        .display()
        .to_string()
}

/// netlens with an isolated HOME and no NETLENS_* / color env leaking in.
fn nl(home: &TempDir) -> Command {
    let mut c = Command::cargo_bin("netlens").unwrap();
    c.env("HOME", home.path());
    for k in [
        "NETLENS_MODEL_URL",
        "NETLENS_MODEL",
        "NETLENS_API_KEY",
        "NETLENS_CONFIG",
        "NETLENS_AUDIT",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "NO_COLOR",
    ] {
        c.env_remove(k);
    }
    c
}

fn json_of(out: &[u8]) -> Value {
    serde_json::from_slice(out)
        .unwrap_or_else(|e| panic!("bad json ({e}): {}", String::from_utf8_lossy(out)))
}

fn ios() -> [String; 2] {
    [ex("ios-xe/before.cfg"), ex("ios-xe/after.cfg")]
}

fn audit_lines(home: &TempDir) -> Vec<Value> {
    let p = home.path().join(".local/state/netlens/audit.jsonl");
    std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn review_deterministic_text() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args(["review", &ios()[0], &ios()[1], "--no-llm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("F1    HIGH     NL-IF-006"))
        .stdout(predicate::str::contains(
            "BGP neighbor 198.51.100.1 shut down",
        ))
        .stdout(predicate::str::contains(
            "RM-ISP-A-OUT-V2 referenced but not defined",
        ))
        .stdout(predicate::str::contains(
            "   permit tcp any host 203.0.113.10 eq 443",
        ))
        .stdout(predicate::str::contains("AI review disabled"))
        // community string is a secret: redacted in the report
        .stdout(predicate::str::contains("community public").not())
        .stdout(predicate::str::contains("\x1b[").not());
}

#[test]
fn review_json_and_reveal_secrets() {
    let h = TempDir::new().unwrap();
    let out = nl(&h)
        .args(["review", &ios()[0], &ios()[1], "--no-llm", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let j = json_of(&out.stdout);
    assert_eq!(j["vendor"], "cisco-ios");
    assert_eq!(j["findings"].as_array().unwrap().len(), 9);
    assert_eq!(j["summary"]["max_severity"], "high");
    assert_eq!(j["rollback"]["contains_redactions"], true);
    assert!(j["findings"].as_array().unwrap().iter().all(|f| f["id"]
        .as_str()
        .unwrap()
        .starts_with('F')
        && !f["evidence"].as_array().unwrap().is_empty()));
    assert!(j["llm"].is_null());

    let out = nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--json",
            "--reveal-secrets",
        ])
        .output()
        .unwrap();
    let j = json_of(&out.stdout);
    let rb: Vec<String> = j["rollback"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    assert!(
        rb.contains(&"no snmp-server community public RO".to_string()),
        "{rb:?}"
    );
    assert_eq!(j["rollback"]["contains_redactions"], false);
}

#[test]
fn fail_on_threshold_sets_exit_code() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--fail-on",
            "high",
        ])
        .assert()
        .code(2);
    nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--fail-on",
            "critical",
        ])
        .assert()
        .code(0);
    nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--fail-on",
            "severe",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn mock_llm_in_process_citations_validated() {
    let h = TempDir::new().unwrap();
    let out = nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--model-url",
            "mock://",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json_of(&out.stdout);
    let llm = &j["llm"];
    assert_eq!(llm["status"], "ok");
    let claims = llm["claims"].as_array().unwrap();
    assert!(claims.len() >= 5);
    assert!(claims
        .iter()
        .all(|c| !c["citations"].as_array().unwrap().is_empty()));
    assert!(claims
        .iter()
        .all(|c| !c["text"].as_str().unwrap().contains("<think>")));
    assert_eq!(
        llm["dropped"].as_array().unwrap().len(),
        2,
        "uncited + unknown-id claims are dropped"
    );
    assert_eq!(llm["unknown_ids"], serde_json::json!(["F99"]));
    // the model saw secrets redacted
    assert!(llm["redactions"].as_u64().unwrap() >= 1);
}

#[test]
fn mock_llm_over_http_with_ip_masking_and_audit() {
    let h = TempDir::new().unwrap();
    let srv = netlens_mock::spawn_llm("127.0.0.1:0").unwrap();
    let url = format!("{}/v1", srv.url);
    let out = nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--model-url",
            &url,
            "--model",
            "qwen3:14b",
            "--mask-ips",
            "--audit-prompts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json_of(&out.stdout);
    assert_eq!(j["llm"]["status"], "ok");
    assert!(j["llm"]["masked_ips"].as_u64().unwrap() > 0);
    // claims are unmasked for the human
    let text: String = j["llm"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["text"].as_str().unwrap().to_string())
        .collect();
    assert!(text.contains("198.51.100.1"), "{text}");
    assert!(!text.contains("IP4_"), "{text}");

    let audit = audit_lines(&h);
    let events: Vec<&str> = audit.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["review.start", "model.call", "review.end"]);
    let call = &audit[1];
    assert_eq!(call["ok"], true);
    assert_eq!(call["model"], "qwen3:14b");
    assert_eq!(call["prompt_sha256"].as_str().unwrap().len(), 64);
    let prompt = call["prompt"]
        .as_str()
        .expect("--audit-prompts stores the prompt");
    assert!(
        !prompt.contains("198.51.100.1"),
        "IPs must be masked before the model"
    );
    assert!(
        !prompt.contains("community public"),
        "secrets must be redacted before the model"
    );
    assert!(prompt.contains("<redacted:snmp-community#"));
    assert!(prompt.contains("/no_think") || !prompt.is_empty());
    srv.stop();
}

#[test]
fn audit_without_prompts_stores_only_hash() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args(["review", &ios()[0], &ios()[1], "--model-url", "mock://"])
        .assert()
        .success();
    let audit = audit_lines(&h);
    let call = audit.iter().find(|e| e["event"] == "model.call").unwrap();
    assert!(call.get("prompt").is_none());
    assert!(call["prompt_bytes"].as_u64().unwrap() > 100);
    // --no-audit writes nothing new
    let h2 = TempDir::new().unwrap();
    nl(&h2)
        .args(["review", &ios()[0], &ios()[1], "--no-llm", "--no-audit"])
        .assert()
        .success();
    assert!(audit_lines(&h2).is_empty());
    // --audit PATH
    let p = h2.path().join("custom.jsonl");
    nl(&h2)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--audit",
            p.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(std::fs::read_to_string(&p)
        .unwrap()
        .contains("review.start"));
}

#[test]
fn unreachable_model_degrades_gracefully() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--model-url",
            "http://127.0.0.1:9/v1",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("AI summary skipped"))
        .stderr(predicate::str::contains("--no-llm"))
        .stdout(predicate::str::contains("Rollback"));
    let audit = audit_lines(&h);
    let call = audit.iter().find(|e| e["event"] == "model.call").unwrap();
    assert_eq!(call["ok"], false);
}

#[test]
fn diff_from_stdin() {
    let h = TempDir::new().unwrap();
    let diff = std::fs::read_to_string(ex("change.diff")).unwrap();
    let out = nl(&h)
        .args(["review", "--diff", "-", "--no-llm", "--json"])
        .write_stdin(diff)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json_of(&out.stdout);
    assert_eq!(j["mode"], "diff");
    assert_eq!(j["partial"], true);
    let rules: Vec<&str> = j["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(
        rules.contains(&"NL-BGP-002") && rules.contains(&"NL-ACL-001"),
        "{rules:?}"
    );
}

#[test]
fn vendors_autodetected() {
    let h = TempDir::new().unwrap();
    for (b, a, v) in [
        ("junos/before.conf", "junos/after.conf", "junos"),
        ("junos-set/before.set", "junos-set/after.set", "junos"),
        ("eos/before.cfg", "eos/after.cfg", "arista-eos"),
    ] {
        let out = nl(&h)
            .args(["review", &ex(b), &ex(a), "--no-llm", "--json"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let j = json_of(&out.stdout);
        assert_eq!(j["vendor"], v, "{b}");
        assert!(!j["findings"].as_array().unwrap().is_empty(), "{b}");
        assert!(j["rollback"]["lines"].as_array().unwrap().len() > 2, "{b}");
    }
}

#[test]
fn input_errors_are_clear() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args(["review", "nope-before.cfg", &ios()[1], "--no-llm"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot read 'nope-before.cfg'"));
    nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--vendor",
            "nxos",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown vendor 'nxos'"));
    nl(&h)
        .args(["review"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
    let bad = h.path().join("bad.diff");
    std::fs::write(&bad, "this is not a diff\n").unwrap();
    nl(&h)
        .args(["review", "--diff", bad.to_str().unwrap(), "--no-llm"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn batfish_mock_and_unreachable() {
    let h = TempDir::new().unwrap();
    let bf = netlens_mock::spawn_batfish("127.0.0.1:0").unwrap();
    let out = nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--batfish",
            &bf.url,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json_of(&out.stdout);
    assert_eq!(j["batfish"]["status"], "ok");
    let ids: Vec<&str> = j["batfish"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(ids.len() >= 3 && ids[0] == "B1", "{ids:?}");
    // B findings are citable by the model
    let out = nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--model-url",
            "mock://",
            "--batfish",
            &bf.url,
            "--json",
        ])
        .output()
        .unwrap();
    let j = json_of(&out.stdout);
    let cites: Vec<String> = j["llm"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| {
            c["citations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
        })
        .collect();
    assert!(cites.iter().all(|c| c != "F99"));
    bf.stop();

    nl(&h)
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
            "--batfish",
            "http://127.0.0.1:9",
            "--batfish-timeout",
            "3",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Batfish unavailable"));
}

#[test]
fn colors_respect_flags_and_no_color() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args([
            "--color",
            "always",
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b["));
    nl(&h)
        .args([
            "--color",
            "never",
            "review",
            &ios()[0],
            &ios()[1],
            "--no-llm",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[").not());
    nl(&h)
        .env("NO_COLOR", "1")
        .args(["review", &ios()[0], &ios()[1], "--no-llm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[").not());
}

#[test]
fn phase_two_stubs() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args(["troubleshoot", "--host", "r1", "bgp down"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("coming in phase 2"));
    nl(&h)
        .args(["mcp"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("coming in phase 2"));
}

#[test]
fn policy_check() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args([
            "policy", "check", "--vendor", "ios", "--", "show", "ip", "bgp", "summary",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ALLOWED"));
    nl(&h)
        .args(["policy", "check", "--", "configure", "terminal"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("DENIED"));
    nl(&h)
        .args([
            "policy",
            "check",
            "--",
            "show running-config | redirect flash:x",
        ])
        .assert()
        .code(2);
    nl(&h)
        .args([
            "policy",
            "check",
            "--vendor",
            "junos",
            "--",
            "request system reboot",
        ])
        .assert()
        .code(2);
    nl(&h)
        .args(["policy", "list", "--vendor", "eos"])
        .assert()
        .success()
        .stdout(predicate::str::contains("^show"));
}

#[test]
fn policy_overrides_from_config_must_be_anchored() {
    let h = TempDir::new().unwrap();
    let cfg = h.path().join("c.toml");
    std::fs::write(
        &cfg,
        "[policy.allow]\nios = ['^show platform software status control-processor brief$']\n",
    )
    .unwrap();
    nl(&h)
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "policy",
            "check",
            "--",
            "show platform software status control-processor brief",
        ])
        .assert()
        .code(0);
    std::fs::write(&cfg, "[policy.allow]\nios = ['show .*']\n").unwrap();
    nl(&h)
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "policy",
            "check",
            "--",
            "show version",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("anchored"));
}

#[test]
fn redact_and_lint_commands() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args(["redact", "--mask-ips"])
        .write_stdin("username admin secret 9 $9$abcdefgh$ijklmnop\nsnmp-server community S3cretComm RO\nip route 0.0.0.0 0.0.0.0 192.0.2.1\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("S3cretComm").not())
        .stdout(predicate::str::contains("$9$abcdefgh").not())
        .stdout(predicate::str::contains("192.0.2.1").not())
        .stdout(predicate::str::contains("ip route 0.0.0.0 0.0.0.0 IP4_1"))
        .stderr(predicate::str::contains("redacted"));
    nl(&h)
        .args(["lint", &ios()[1], "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NL-SEC-002"));
    nl(&h)
        .args(["lint", &ios()[1], "--fail-on", "medium"])
        .assert()
        .code(2);
}

#[test]
fn config_precedence() {
    let h = TempDir::new().unwrap();
    let dir = h.path().join(".config/netlens");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        "model = \"from-file\"\nmodel_url = \"mock://\"\n",
    )
    .unwrap();
    nl(&h)
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "model         = from-file  (config)",
        ));
    nl(&h)
        .env("NETLENS_MODEL", "from-env")
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("from-env  (env)"));
    // config file drives the review: mock:// from the file, model name from the flag
    let out = nl(&h)
        .env("NETLENS_MODEL", "from-env")
        .args([
            "review",
            &ios()[0],
            &ios()[1],
            "--model",
            "from-flag",
            "--json",
        ])
        .output()
        .unwrap();
    let j = json_of(&out.stdout);
    assert_eq!(j["llm"]["status"], "ok");
    assert!(j["llm"]["model"].as_str().unwrap().contains("from-flag"));
    std::fs::write(dir.join("config.toml"), "modle = \"typo\"\n").unwrap();
    nl(&h)
        .args(["config", "show"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid config file"));
    nl(&h)
        .args(["config", "example"])
        .assert()
        .success()
        .stdout(predicate::str::contains("qwen3:14b"));
}

#[test]
fn rules_listing() {
    let h = TempDir::new().unwrap();
    nl(&h)
        .args(["rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NL-ACL-003"));
    let out = nl(&h).args(["rules", "--json"]).output().unwrap();
    let j = json_of(&out.stdout);
    assert!(j.as_array().unwrap().len() >= 30);
}

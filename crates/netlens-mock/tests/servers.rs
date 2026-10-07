use netlens_core::Vendor;
use std::time::Duration;

const BEFORE: &str = include_str!("../../../examples/ios-xe/before.cfg");
const AFTER: &str = include_str!("../../../examples/ios-xe/after.cfg");

#[test]
fn mock_llm_speaks_openai_and_cites() {
    let s = netlens_mock::spawn_llm("127.0.0.1:0").unwrap();
    let cfg = netlens_llm::ModelConfig {
        url: format!("{}/v1", s.url),
        model: "qwen3:14b".into(),
        ..Default::default()
    };
    let backend = netlens_llm::backend_for(&cfg);
    let msgs = vec![netlens_llm::ChatMessage::user(
        "EVIDENCE:\n[F1] severity=high rule=NL-BGP-002 section=bgp | neighbor shut\n[R1] rollback",
    )];
    let c = backend.chat(&msgs).unwrap();
    assert!(!c.text.contains("<think>"), "think block must be stripped");
    assert!(c.text.contains("[F1]") && c.text.contains("SUMMARY:"));
    let models: serde_json::Value = ureq::get(&format!("{}/v1/models", s.url))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(models["data"][0]["id"], "netlens-mock");
    s.stop();
}

#[test]
fn batfish_client_against_mock() {
    let s = netlens_mock::spawn_batfish("127.0.0.1:0").unwrap();
    let run = netlens_batfish::run_review(
        &s.url,
        BEFORE,
        AFTER,
        Vendor::CiscoIos,
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(
        run.questions.iter().all(|q| q.status == "ok"),
        "{:#?}",
        run.questions
    );
    let titles: Vec<String> = run
        .findings
        .iter()
        .map(|f| format!("{} {}", f.id, f.title))
        .collect();
    assert!(
        titles
            .iter()
            .any(|t| t.contains("undefined reference") && t.contains("RM-ISP-A-OUT-V2")),
        "{titles:#?}"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("BGP session") && t.contains("198.51.100.1")),
        "{titles:#?}"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("unused structure") && t.contains("RM-ISP-A-OUT")),
        "{titles:#?}"
    );
    assert_eq!(run.findings[0].id, "B1");
    s.stop();
}

#[test]
fn batfish_requires_version_header_and_reports_unreachable() {
    let s = netlens_mock::spawn_batfish("127.0.0.1:0").unwrap();
    let r = ureq::get(&format!("{}/v2/version", s.url)).call();
    assert!(matches!(r, Err(ureq::Error::Status(400, _))));
    s.stop();
    let e = netlens_batfish::run_review(
        "http://127.0.0.1:9",
        BEFORE,
        AFTER,
        Vendor::CiscoIos,
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert!(e.to_string().contains("cannot reach Batfish"), "{e}");
}

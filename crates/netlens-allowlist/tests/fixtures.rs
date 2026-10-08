//! Validates every fixture scenario: files exist, commands pass the default
//! allowlist, evidence lines appear verbatim, syslog matches the hostname.

use netlens_allowlist::fixtures::{fixtures_root, scenario_dirs, Scenario};
use netlens_allowlist::{check, AllowlistConfig, Vendor};
use std::collections::HashSet;

fn scenarios() -> Vec<Scenario> {
    scenario_dirs(fixtures_root())
        .expect("fixtures dir")
        .into_iter()
        .map(|d| Scenario::load(&d).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

#[test]
fn scenario_inventory() {
    let all = scenarios();
    assert!((4..=6).contains(&all.len()), "{} scenarios", all.len());
    let vendors: HashSet<Vendor> = all.iter().map(|s| s.vendor).collect();
    for v in Vendor::ALL {
        assert!(vendors.contains(&v), "no scenario for {v}");
    }
    let ids: Vec<String> = all
        .iter()
        .map(|s| {
            format!(
                "{}/{}",
                s.vendor,
                s.dir.file_name().unwrap().to_string_lossy()
            )
        })
        .collect();
    for want in [
        "ios/bgp-flap-mtu",
        "eos/bgp-flap-crc",
        "ios/ospf-exstart-mtu",
        "ios/interface-errdisabled",
        "junos/bgp-auth-mismatch",
    ] {
        assert!(ids.iter().any(|i| i == want), "missing {want}: {ids:?}");
    }
}

#[test]
fn scenario_dir_matches_vendor() {
    for s in scenarios() {
        let parent = s
            .dir
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(parent, s.vendor.to_string(), "{}", s.dir.display());
    }
}

#[test]
fn every_command_maps_to_a_file_and_passes_the_allowlist() {
    let cfg = AllowlistConfig::default();
    for s in scenarios() {
        assert!(
            s.commands.len() >= 4,
            "{}: too few commands",
            s.dir.display()
        );
        let mut seen = HashSet::new();
        for c in &s.commands {
            assert!(
                seen.insert(c.command.to_ascii_lowercase()),
                "{}: duplicate {:?}",
                s.dir.display(),
                c.command
            );
            if let Err(e) = check(s.vendor, &c.command, &cfg) {
                panic!("{}: fixture command fails allowlist: {e}", s.dir.display());
            }
            let out = s
                .output(&c.command)
                .expect("mapped")
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                !out.trim().is_empty(),
                "{}: {} is empty",
                s.dir.display(),
                c.file
            );
            assert!(
                out.ends_with('\n'),
                "{}: {} lacks trailing newline",
                s.dir.display(),
                c.file
            );
            // Lookup is whitespace- and case-insensitive, like a device.
            let messy = format!("  {}  ", c.command.to_ascii_uppercase().replace(' ', "   "));
            assert_eq!(s.file_for(&messy), Some(c.file.as_str()));
        }
        assert!(s.output("show tech-support").is_none());
    }
}

#[test]
fn every_file_in_a_scenario_is_referenced() {
    for s in scenarios() {
        let mut referenced: HashSet<String> = s.commands.iter().map(|c| c.file.clone()).collect();
        referenced.insert(s.syslog.clone());
        referenced.insert("scenario.toml".into());
        // scripted model replies for the offline demo / e2e tests (netlens troubleshoot)
        referenced.insert("mock-llm.json".into());
        for entry in std::fs::read_dir(&s.dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            assert!(
                referenced.contains(&name),
                "{}: unreferenced file {name}",
                s.dir.display()
            );
        }
    }
}

#[test]
fn every_evidence_line_exists_verbatim() {
    for s in scenarios() {
        assert!(
            s.key_evidence.len() >= 3,
            "{}: too little evidence",
            s.dir.display()
        );
        let mut files_with_evidence = HashSet::new();
        for ev in &s.key_evidence {
            let path = s.dir.join(&ev.file);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(
                text.lines().any(|l| l == ev.line),
                "{}: evidence line not found verbatim in {}:\n{:?}",
                s.dir.display(),
                ev.file,
                ev.line
            );
            files_with_evidence.insert(ev.file.clone());
        }
        assert!(
            files_with_evidence.contains(&s.syslog),
            "{}: no syslog evidence",
            s.dir.display()
        );
        assert!(
            files_with_evidence.len() >= 3,
            "{}: evidence should span 3+ files",
            s.dir.display()
        );
    }
}

#[test]
fn syslog_matches_hostname_and_metadata_is_complete() {
    for s in scenarios() {
        let log = s.syslog_text().unwrap();
        assert!(log.lines().count() >= 10, "{}", s.dir.display());
        for l in log.lines() {
            assert!(
                l.contains(&format!(" {} ", s.hostname)),
                "{}: line without hostname: {l}",
                s.dir.display()
            );
        }
        for (k, v) in [
            ("title", &s.title),
            ("description", &s.description),
            ("symptom", &s.symptom),
            ("root_cause.id", &s.root_cause.id),
            ("root_cause.text", &s.root_cause.text),
        ] {
            assert!(!v.trim().is_empty(), "{}: empty {k}", s.dir.display());
        }
        assert!(
            s.root_cause
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-'),
            "{}: root_cause.id should be kebab-case",
            s.dir.display()
        );
    }
}

#[test]
fn fixtures_use_documentation_addresses_only() {
    // Every dotted quad in the fixtures must be in a documentation range,
    // a netmask, multicast, or 0.0.0.0/255.255.255.255.
    let ok = |a: [u32; 4]| {
        matches!(a, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
            || a[0] == 255
            || a[0] == 224
            || a == [0, 0, 0, 0]
    };
    for s in scenarios() {
        for entry in std::fs::read_dir(&s.dir).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            for word in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
                let parts: Vec<&str> = word.split('.').collect();
                if parts.len() != 4 {
                    continue;
                }
                let Ok(nums) = parts
                    .iter()
                    .map(|p| p.parse::<u32>())
                    .collect::<Result<Vec<_>, _>>()
                else {
                    continue;
                };
                if nums.iter().any(|n| *n > 255) {
                    continue;
                }
                let a = [nums[0], nums[1], nums[2], nums[3]];
                assert!(
                    ok(a),
                    "{}: non-documentation address {word}",
                    path.display()
                );
            }
        }
    }
}

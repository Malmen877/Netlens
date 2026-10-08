//! Secret redaction. Runs before anything reaches a model, and (by default)
//! before anything is printed.
//!
//! Each distinct secret value gets a stable placeholder such as
//! `<redacted:secret#2>` for the lifetime of a [`Redactor`], so a model can
//! still tell "the BGP password changed" (different placeholders) from
//! "unchanged" without ever seeing a value.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

struct Rule {
    re: Regex,
    kind: &'static str,
}

fn r(p: &str, kind: &'static str) -> Rule {
    Rule {
        re: Regex::new(p).unwrap_or_else(|e| panic!("bad redaction regex {p}: {e}")),
        kind,
    }
}

// Every rule captures the secret in the named group `s`.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // Crypt-style hashes anywhere: Junos $9$/$1$/$5$/$6$, IOS type 8/9 ($8$, $9$), EOS sha512.
        r(
            r#"(?P<s>\$(?:1|5|6|8|9|sha1|sha256|sha512|y|2[aby]?)\$[^\s";]+)"#,
            "hash",
        ),
        // password / secret with optional type (IOS/EOS/NX), usernames, enable, line, neighbor.
        r(
            r#"(?i)(?:^|[\s"])(?:secret|password)(?:\s+(?:0|4|5|6|7|8|9|sha512|sha256|md5|encrypted|clear|cleartext))?\s+(?P<s>"[^"]*"|[^\s"]+)"#,
            "secret",
        ),
        // Keys and key-like credentials with an optional type digit.
        r(
            r#"(?i)\b(?:authentication-key|encrypted-password|key-string|community-string|auth-password|priv-password|wpa-psk\s+(?:ascii|hex)|authentication\s+text|area-password|domain-password|pre-shared-key(?:\s+(?:ascii-text|hexadecimal))?)(?:\s+(?:0|6|7))?\s+(?P<s>"[^"]*"|\S+)"#,
            "key",
        ),
        r(
            r#"(?i)\bpre-shared-key\s+(?:local|remote)(?:\s+(?:0|6))?\s+(?P<s>\S+)"#,
            "psk",
        ),
        r(
            r#"(?i)\bcrypto\s+isakmp\s+key(?:\s+(?:0|6))?\s+(?P<s>\S+)"#,
            "psk",
        ),
        r(
            r#"(?i)\bmessage-digest-key\s+\d+\s+md5(?:\s+(?:0|7))?\s+(?P<s>\S+)"#,
            "key",
        ),
        r(
            r#"(?i)\bntp\s+authentication-key\s+\d+\s+(?:md5|sha1|sha256|hmac-sha1|hmac-sha256)\s+(?P<s>\S+)"#,
            "key",
        ),
        r(r#"(?i)\bmd5\s+\d+\s+key\s+(?P<s>"[^"]*"|\S+)"#, "key"),
        // `key [type] VALUE` as the last thing on a line (tacacs/radius server blocks,
        // `tacacs-server key`, `server-private ... key`). `key 1` alone (key chain id) is left alone.
        r(
            r#"(?i)(?:^|\s)key\s+(?:(?:0|6|7)\s+)?(?P<s>"[^"]*"|[^\s"]+)\s*;?\s*$"#,
            "key",
        ),
        // SNMP communities and v3 user keys.
        r(
            r#"(?i)\bsnmp-server\s+community\s+(?P<s>\S+)"#,
            "snmp-community",
        ),
        r(
            r#"(?i)\bsnmp-server\s+host\s+\S+(?:\s+(?:informs|traps))?(?:\s+version\s+(?:1|2c|3\s+(?:auth|noauth|priv)))?\s+(?P<s>[^\s]+)"#,
            "snmp-community",
        ),
        r(
            r#"(?i)^\s*(?:set\s+)?snmp\s+community\s+(?P<s>"[^"]*"|[^\s{;]+)"#,
            "snmp-community",
        ),
        r(
            r#"(?i)\bsnmp\s+(?:trap-group\s+\S+\s+)?targets?\b.*\bcommunity\s+(?P<s>\S+)"#,
            "snmp-community",
        ),
        r(
            r#"(?i)\bauth\s+(?:md5|sha|sha-?\d+)\s+(?:0x)?(?P<s>\S+)"#,
            "key",
        ),
        r(
            r#"(?i)\bpriv\s+(?:des|3des|des56|aes(?:\s*\d+)?)\s+(?:0x)?(?P<s>\S+)"#,
            "key",
        ),
        // IOS certificate hex blobs (inside `crypto pki certificate chain`).
        r(
            r#"^\s*(?P<s>(?:[0-9A-Fa-f]{8}\s+){2,}[0-9A-Fa-f]{2,8})\s*$"#,
            "cert",
        ),
        r(
            r#"^\s*(?P<s>(?:[0-9A-Fa-f]{8}\s+){3,}[0-9A-Fa-f]{8})\s*$"#,
            "cert",
        ),
        // PEM body lines (also caught statefully in redact_text).
        r(r#"^\s*(?P<s>[A-Za-z0-9+/]{40,}={0,2})\s*$"#, "cert"),
    ]
});

/// Words that look like a secret position but aren't one.
fn is_false_positive(value: &str, kind: &str) -> bool {
    let v = value.trim_matches('"').to_ascii_lowercase();
    if kind == "secret" {
        return matches!(
            v.as_str(),
            "encryption"
                | "required"
                | "level"
                | "min-length"
                | "<redacted"
                | "prompt"
                | "policy"
                | "reuse"
        ) || value.starts_with("<redacted:");
    }
    value.starts_with("<redacted:")
}

/// A redaction session with stable placeholders.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    map: HashMap<String, String>,
    counter: usize,
    /// Total number of replacements made.
    pub count: usize,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    fn placeholder(&mut self, value: &str, kind: &str) -> String {
        if let Some(p) = self.map.get(value) {
            return p.clone();
        }
        self.counter += 1;
        let p = format!("<redacted:{kind}#{}>", self.counter);
        self.map.insert(value.to_string(), p.clone());
        p
    }

    /// Redact one line (no multi-line context).
    pub fn redact_line(&mut self, line: &str) -> String {
        self.redact_line_ctx(line, "")
    }

    /// Redact one line with the enclosing block context (e.g. "snmp" for a
    /// Junos curly `community public {` line).
    pub fn redact_line_ctx(&mut self, line: &str, context: &str) -> String {
        let mut spans: Vec<(usize, usize, &'static str)> = Vec::new();
        static RE_KEY_ID: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^\s*key \d+\s*$").unwrap());
        let key_id_line = RE_KEY_ID.is_match(line);
        for rule in RULES.iter() {
            if key_id_line && rule.kind == "key" {
                continue; // `key 1` inside a key chain is an id, not a secret
            }
            for c in rule.re.captures_iter(line) {
                if let Some(m) = c.name("s") {
                    if !is_false_positive(m.as_str(), rule.kind) {
                        spans.push((m.start(), m.end(), rule.kind));
                    }
                }
            }
        }
        // Junos curly: `community NAME {` / `community NAME;` inside `snmp`.
        if context.split_whitespace().next() == Some("snmp") {
            static RE_C: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r#"^\s*community\s+(?P<s>"[^"]*"|[^\s{;]+)"#).unwrap());
            if let Some(m) = RE_C.captures(line).and_then(|c| c.name("s")) {
                spans.push((m.start(), m.end(), "snmp-community"));
            }
        }
        if spans.is_empty() {
            return line.to_string();
        }
        // Merge overlapping spans (keep the widest, first kind).
        spans.sort_by_key(|s| (s.0, std::cmp::Reverse(s.1)));
        let mut merged: Vec<(usize, usize, &'static str)> = Vec::new();
        for s in spans {
            if let Some(last) = merged.last_mut() {
                if s.0 < last.1 {
                    last.1 = last.1.max(s.1);
                    continue;
                }
            }
            merged.push(s);
        }
        let mut out = String::with_capacity(line.len());
        let mut pos = 0;
        for (a, b, kind) in merged {
            out.push_str(&line[pos..a]);
            let value = &line[a..b];
            let ph = self.placeholder(value, kind);
            out.push_str(&ph);
            self.count += 1;
            pos = b;
        }
        out.push_str(&line[pos..]);
        out
    }

    /// Redact a whole config/log text, tracking block context and PEM blocks.
    pub fn redact_text(&mut self, text: &str) -> String {
        let mut out = Vec::new();
        let mut in_pem = false;
        // Context stack: (indent or brace depth marker, header text)
        let mut ctx: Vec<(usize, String)> = Vec::new();
        let mut depth = 0usize;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("-----BEGIN") {
                in_pem = true;
                out.push(line.to_string());
                continue;
            }
            if t.starts_with("-----END") {
                in_pem = false;
                out.push(line.to_string());
                continue;
            }
            if in_pem {
                if t.is_empty() {
                    out.push(String::new());
                } else {
                    let ph = self.placeholder(t, "cert");
                    self.count += 1;
                    let indent = &line[..line.len() - line.trim_start().len()];
                    out.push(format!("{indent}{ph}"));
                }
                continue;
            }
            // Brace context (Junos curly).
            while let Some((d, _)) = ctx.last() {
                if *d > depth {
                    ctx.pop();
                } else {
                    break;
                }
            }
            let context = ctx.first().map(|(_, h)| h.clone()).unwrap_or_default();
            out.push(self.redact_line_ctx(line, &context));
            if t.ends_with('{') {
                depth += 1;
                ctx.push((depth, t.trim_end_matches('{').trim().to_string()));
            }
            if t == "}" || t.ends_with('}') {
                depth = depth.saturating_sub(1);
                while let Some((d, _)) = ctx.last() {
                    if *d > depth {
                        ctx.pop();
                    } else {
                        break;
                    }
                }
            }
        }
        let mut s = out.join("\n");
        if text.ends_with('\n') {
            s.push('\n');
        }
        s
    }

    /// Redact a free-form string that may contain several lines.
    pub fn redact_str(&mut self, s: &str) -> String {
        if s.contains('\n') {
            self.redact_text(s)
        } else {
            self.redact_line(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(s: &str) -> String {
        Redactor::new().redact_line(s)
    }

    fn assert_hidden(line: &str, secret: &str) {
        let out = red(line);
        assert!(
            !out.contains(secret),
            "secret {secret:?} leaked in {out:?} (from {line:?})"
        );
        assert!(out.contains("<redacted:"), "no placeholder in {out:?}");
    }

    #[test]
    fn ios_enable_and_users() {
        assert_hidden(
            "enable secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
            "nhEmQVczB7dqsO",
        );
        assert_hidden(
            "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
            "hx5rVt7rPNoS4wqbXKX7m0",
        );
        assert_hidden("enable password 7 0822455D0A16", "0822455D0A16");
        assert_hidden("enable password cisco123", "cisco123");
        assert_hidden(
            "username admin privilege 15 secret 9 $9$abcdefgh$ijklmnop",
            "ijklmnop",
        );
        assert_hidden("username netops password 0 Sup3rS3cret!", "Sup3rS3cret!");
        assert_hidden(
            "username netops privilege 15 password 7 104D000A0618",
            "104D000A0618",
        );
    }

    #[test]
    fn line_and_type7() {
        assert_hidden(" password 7 13061E010803", "13061E010803");
        assert_hidden(" password letmein", "letmein");
    }

    #[test]
    fn tacacs_radius() {
        assert_hidden("tacacs-server key 7 0822455D0A16", "0822455D0A16");
        assert_hidden(
            "tacacs-server host 10.1.1.5 key 7 060506324F41",
            "060506324F41",
        );
        assert_hidden(" key 7 060506324F41584B56", "060506324F41584B56");
        assert_hidden(
            "radius-server host 10.1.1.6 auth-port 1812 acct-port 1813 key RadiusKey1",
            "RadiusKey1",
        );
        assert_hidden(
            " server-private 10.1.1.7 key 7 01100F175804",
            "01100F175804",
        );
        assert_hidden("radius-server key PlainKey", "PlainKey");
    }

    #[test]
    fn key_chain_id_is_not_redacted() {
        assert_eq!(red(" key 1"), " key 1");
        assert_hidden("  key-string 7 045802150C2E", "045802150C2E");
        assert_hidden("  key-string MyKeyString", "MyKeyString");
    }

    #[test]
    fn routing_protocol_auth() {
        assert_hidden(" neighbor 10.0.0.2 password 7 02050D480809", "02050D480809");
        assert_hidden(" neighbor 10.0.0.2 password s3cr3t", "s3cr3t");
        assert_hidden(" ip ospf authentication-key 7 110A1016141D", "110A1016141D");
        assert_hidden(
            " ip ospf message-digest-key 1 md5 7 094F471A1A0A",
            "094F471A1A0A",
        );
        assert_hidden(" ip ospf message-digest-key 1 md5 PlainMd5", "PlainMd5");
        assert_hidden(" isis password IsisPw", "IsisPw");
        assert_hidden(" area-password AreaPw", "AreaPw");
        assert_hidden(
            " standby 1 authentication md5 key-string HsrpKey",
            "HsrpKey",
        );
        assert_hidden(" vrrp 1 authentication text VrrpPw", "VrrpPw");
        assert_hidden("ntp authentication-key 1 md5 NtpSecret 7", "NtpSecret");
    }

    #[test]
    fn snmp() {
        assert_hidden("snmp-server community S3cretComm RO 99", "S3cretComm");
        assert_hidden("snmp-server community public RO", "public");
        assert_hidden("snmp-server host 10.9.9.9 version 2c TrapComm", "TrapComm");
        assert_hidden("snmp-server host 10.9.9.9 TrapComm2", "TrapComm2");
        assert_hidden(
            "snmp-server user monitor NMS v3 auth sha AuthPass1 priv aes 128 PrivPass1",
            "AuthPass1",
        );
        assert_hidden(
            "snmp-server user monitor NMS v3 auth sha AuthPass1 priv aes 128 PrivPass1",
            "PrivPass1",
        );
        assert_hidden(
            "set snmp community n0tPublic authorization read-only",
            "n0tPublic",
        );
        assert_hidden(
            "snmp community \"quoted comm\" authorization read-only",
            "quoted comm",
        );
    }

    #[test]
    fn psk() {
        assert_hidden(
            "crypto isakmp key IsakmpKey address 203.0.113.1",
            "IsakmpKey",
        );
        assert_hidden(
            " pre-shared-key address 203.0.113.1 key Ikev2Key",
            "Ikev2Key",
        );
        assert_hidden(" pre-shared-key local LocalPsk", "LocalPsk");
        assert_hidden(" pre-shared-key ascii-text \"$9$abc.DEF\"", "abc.DEF");
        assert_hidden(" wpa-psk ascii 0 WifiPass", "WifiPass");
    }

    #[test]
    fn junos() {
        assert_hidden(
            "set system root-authentication encrypted-password \"$6$abc$defghijk\"",
            "defghijk",
        );
        assert_hidden(
            "set system login user ops authentication encrypted-password \"$1$xyz$uvw\"",
            "uvw",
        );
        assert_hidden(
            "set protocols bgp group EBGP authentication-key \"$9$Hk5FCtpB1hrv8\"",
            "Hk5FCtpB1hrv8",
        );
        assert_hidden(
            "set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key \"$9$xyz\"",
            "xyz",
        );
        assert_hidden(
            "set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key PlainOspf",
            "PlainOspf",
        );
        assert_hidden(
            "set system tacplus-server 10.1.1.5 secret \"$9$aaaBBB\"",
            "aaaBBB",
        );
        assert_hidden(
            "            authentication-key \"$9$Hk5FCtp\"; ## SECRET-DATA",
            "Hk5FCtp",
        );
        assert_hidden(
            "    encrypted-password \"$6$abc$def\"; ## SECRET-DATA",
            "$6$abc$def",
        );
    }

    #[test]
    fn eos() {
        assert_hidden(
            "username admin privilege 15 role network-admin secret sha512 $6$saltsalt$hashhashhash",
            "hashhashhash",
        );
        assert_hidden("enable password sha512 $6$s$h", "$6$s$h");
        assert_hidden(
            "   neighbor 10.0.0.1 password 7 Q8ODyzbJrJ3Rg8p3Aeh6Gg==",
            "Q8ODyzbJrJ3Rg8p3Aeh6Gg==",
        );
        assert_hidden(
            "tacacs-server host 10.1.1.1 key 7 070C285F4D06",
            "070C285F4D06",
        );
    }

    #[test]
    fn certificates_and_pem() {
        assert_hidden(
            "  3082024E 308201B7 A0030201 02020101 300D0609 2A864886",
            "3082024E",
        );
        let pem = "crypto key\n-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYFORTESTSONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nNOTAREALKEYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n-----END RSA PRIVATE KEY-----\n";
        let out = Redactor::new().redact_text(pem);
        assert!(!out.contains("FAKEKEYFORTESTSONLY"), "{out}");
        assert!(!out.contains("NOTAREALKEY"), "{out}");
        assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn junos_curly_snmp_context() {
        let cfg = "snmp {\n    community S3cr3tRO {\n        authorization read-only;\n    }\n}\npolicy-options {\n    community CUST-A members 65001:100;\n}\n";
        let out = Redactor::new().redact_text(cfg);
        assert!(!out.contains("S3cr3tRO"), "{out}");
        assert!(
            out.contains("community CUST-A members"),
            "policy community must stay: {out}"
        );
    }

    #[test]
    fn harmless_lines_untouched() {
        for l in [
            "service password-encryption",
            "password encryption aes",
            "security passwords min-length 10",
            "interface GigabitEthernet1",
            " ip address 10.0.0.1 255.255.255.0",
            "crypto key generate rsa modulus 2048",
            "router bgp 65001",
            " neighbor 10.0.0.2 remote-as 65002",
            "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
            "aaa authentication login default group tacacs+ local",
            " key 1",
        ] {
            assert_eq!(red(l), l, "over-redacted {l:?}");
        }
    }

    #[test]
    fn stable_placeholders() {
        let mut r = Redactor::new();
        let a = r.redact_line(" neighbor 10.0.0.2 password 7 AAAA1111");
        let b = r.redact_line(" neighbor 10.0.0.3 password 7 AAAA1111");
        let c = r.redact_line(" neighbor 10.0.0.4 password 7 BBBB2222");
        let pa = a.split_whitespace().last().unwrap().to_string();
        let pb = b.split_whitespace().last().unwrap().to_string();
        let pc = c.split_whitespace().last().unwrap().to_string();
        assert_eq!(pa, pb);
        assert_ne!(pa, pc);
        assert_eq!(r.count, 3);
    }

    #[test]
    fn idempotent() {
        let mut r = Redactor::new();
        let once = r.redact_line("username admin secret 9 $9$abc$def");
        let twice = r.redact_line(&once);
        assert_eq!(once, twice);
    }
}

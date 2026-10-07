//! Parsers: IOS/EOS indentation blocks, Junos curly braces and Junos `set`.
//!
//! All parsers take numbered source lines so the same code serves full files
//! and unified-diff fragments (where line numbers come from hunk headers).

use crate::model::{flatten, Config, Node, Stmt};
use crate::vendor::Vendor;

/// A source line with its 1-based line number (0 = synthetic).
pub type SrcLine<'a> = (usize, &'a str);

/// Parse a complete configuration text.
pub fn parse(text: &str, vendor: Vendor) -> Config {
    let lines: Vec<SrcLine> = text.lines().enumerate().map(|(i, l)| (i + 1, l)).collect();
    parse_lines(&lines, vendor)
}

/// Parse numbered lines (a full file or one diff hunk).
pub fn parse_lines(lines: &[SrcLine], vendor: Vendor) -> Config {
    match vendor {
        Vendor::CiscoIos | Vendor::AristaEos => {
            let tree = parse_indented(lines);
            let stmts = flatten(&tree);
            Config {
                vendor,
                tree,
                stmts,
                partial: false,
            }
        }
        Vendor::Junos => {
            let stmts = if is_set_style(lines) {
                parse_junos_set(lines)
            } else {
                parse_junos_curly(lines)
            };
            Config {
                vendor,
                tree: Vec::new(),
                stmts,
                partial: false,
            }
        }
    }
}

/// Collapse runs of whitespace and trim.
pub fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn indent_of(raw: &str) -> usize {
    let mut n = 0;
    for c in raw.chars() {
        match c {
            ' ' => n += 1,
            '\t' => n += 4,
            _ => break,
        }
    }
    n
}

/// Lines IOS/EOS emit that carry no configuration meaning.
fn is_noise_ios(t: &str) -> bool {
    t.is_empty()
        || t.starts_with('!')
        || t == "end"
        || t == "exit"
        || t == "exit-address-family"
        || t == "exit-vrf"
        || t == "exit-peer-policy"
        || t == "exit-peer-session"
        || t == "exit-service-family"
        || t.starts_with("Building configuration")
        || t.starts_with("Current configuration")
        || t.starts_with("Last configuration change")
}

/// Parse an indentation-structured config (IOS, IOS-XE, EOS).
pub fn parse_indented(lines: &[SrcLine]) -> Vec<Node> {
    let mut roots: Vec<Node> = Vec::new();
    // Stack of (indent, node) for open blocks.
    let mut stack: Vec<(usize, Node)> = Vec::new();

    fn close_to(stack: &mut Vec<(usize, Node)>, roots: &mut Vec<Node>, indent: Option<usize>) {
        while let Some((ind, _)) = stack.last() {
            if let Some(i) = indent {
                if *ind < i {
                    break;
                }
            }
            let (_, node) = stack.pop().expect("non-empty");
            match stack.last_mut() {
                Some((_, parent)) => parent.children.push(node),
                None => roots.push(node),
            }
        }
    }

    let mut i = 0;
    while i < lines.len() {
        let (no, raw) = lines[i];
        let raw = raw.trim_end_matches('\r');
        let t = raw.trim();
        if is_noise_ios(t) {
            i += 1;
            continue;
        }
        let indent = indent_of(raw);
        close_to(&mut stack, &mut roots, Some(indent));

        // Multi-line banners: `banner motd ^C ... ^C` (or any delimiter char).
        if let Some(delim) = banner_delimiter(t) {
            let mut node = Node::new(normalize(t), no);
            let after_open = banner_rest(t, &delim);
            if !after_open.contains(delim.as_str()) {
                i += 1;
                while i < lines.len() {
                    let (bno, braw) = lines[i];
                    let bt = braw.trim_end_matches('\r');
                    node.children.push(Node::new(normalize(bt), bno));
                    if bt.contains(delim.as_str()) {
                        break;
                    }
                    i += 1;
                }
            }
            push_leaf_or_block(&mut stack, indent, node);
            i += 1;
            continue;
        }

        stack.push((indent, Node::new(normalize(t), no)));
        i += 1;
    }
    close_to(&mut stack, &mut roots, None);
    roots
}

fn push_leaf_or_block(stack: &mut Vec<(usize, Node)>, indent: usize, node: Node) {
    stack.push((indent, node));
}

/// For `banner <type> <delim>...` return the delimiter.
fn banner_delimiter(t: &str) -> Option<String> {
    let mut parts = t.splitn(3, ' ');
    if parts.next()? != "banner" {
        return None;
    }
    let kind = parts.next()?;
    if !matches!(
        kind,
        "motd" | "login" | "exec" | "incoming" | "slip-ppp" | "prompt-timeout" | "config-save"
    ) {
        return None;
    }
    let rest = parts.next()?.trim_start();
    if rest.starts_with("^C") {
        Some("^C".into())
    } else {
        rest.chars().next().map(|c| c.to_string())
    }
}

fn banner_rest<'a>(t: &'a str, delim: &str) -> &'a str {
    match t.find(delim) {
        Some(p) => &t[p + delim.len()..],
        None => "",
    }
}

// ---------------------------------------------------------------- Junos ----

fn is_set_style(lines: &[SrcLine]) -> bool {
    let mut set = 0;
    let mut other = 0;
    for (_, l) in lines {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("/*") {
            continue;
        }
        if t.starts_with("set ")
            || t.starts_with("deactivate ")
            || t.starts_with("delete ")
            || t.starts_with("activate ")
        {
            set += 1;
        } else {
            other += 1;
        }
    }
    set > 0 && set >= other
}

/// Split a Junos statement into tokens, keeping quoted strings intact
/// (quotes included).
pub fn junos_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if in_q {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '"' {
                in_q = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_q = true;
                cur.push(c);
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse Junos `display set` output. `set` lines become statements; a
/// `deactivate X` line is kept verbatim (as `deactivate X`).
pub fn parse_junos_set(lines: &[SrcLine]) -> Vec<Stmt> {
    let mut out = Vec::new();
    for &(no, raw) in lines {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let toks = junos_tokens(t);
        if toks.is_empty() {
            continue;
        }
        let words: Vec<String> = match toks[0].as_str() {
            "set" => toks[1..].to_vec(),
            "deactivate" => toks.clone(),
            _ => continue,
        };
        if words.is_empty() {
            continue;
        }
        // `set ... members [ 10 20 ]` -> one statement per list element.
        let open = words.iter().position(|w| w == "[");
        let close = words.iter().position(|w| w == "]");
        if let (Some(o), Some(c)) = (open, close) {
            if o < c {
                for item in &words[o + 1..c] {
                    let mut v: Vec<String> = words[..o].to_vec();
                    v.push(item.clone());
                    v.extend(words[c + 1..].iter().cloned());
                    out.push(Stmt {
                        path: vec![v.join(" ")],
                        line: no,
                    });
                }
                continue;
            }
        }
        out.push(Stmt {
            path: vec![words.join(" ")],
            line: no,
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Open,
    Close,
    Semi,
    LBracket,
    RBracket,
}

fn tokenize_curly(lines: &[SrcLine]) -> Vec<(usize, Tok)> {
    let mut out = Vec::new();
    let mut in_block_comment = false;
    for &(no, raw) in lines {
        let mut chars = raw.chars().peekable();
        let mut cur = String::new();
        let flush = |cur: &mut String, out: &mut Vec<(usize, Tok)>| {
            if !cur.is_empty() {
                out.push((no, Tok::Word(std::mem::take(cur))));
            }
        };
        while let Some(c) = chars.next() {
            if in_block_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            match c {
                '/' if chars.peek() == Some(&'*') && cur.is_empty() => {
                    chars.next();
                    in_block_comment = true;
                }
                '#' if cur.is_empty() => {
                    // Comment to end of line (e.g. "## Last commit: ...").
                    break;
                }
                '"' => {
                    cur.push('"');
                    while let Some(q) = chars.next() {
                        cur.push(q);
                        if q == '\\' {
                            if let Some(n) = chars.next() {
                                cur.push(n);
                            }
                        } else if q == '"' {
                            break;
                        }
                    }
                }
                '{' => {
                    flush(&mut cur, &mut out);
                    out.push((no, Tok::Open));
                }
                '}' => {
                    flush(&mut cur, &mut out);
                    out.push((no, Tok::Close));
                }
                ';' => {
                    flush(&mut cur, &mut out);
                    out.push((no, Tok::Semi));
                }
                '[' => {
                    flush(&mut cur, &mut out);
                    out.push((no, Tok::LBracket));
                }
                ']' => {
                    flush(&mut cur, &mut out);
                    out.push((no, Tok::RBracket));
                }
                c if c.is_whitespace() => flush(&mut cur, &mut out),
                _ => cur.push(c),
            }
        }
        flush(&mut cur, &mut out);
    }
    out
}

/// Parse Junos curly-brace config into `set`-style statements, the same
/// shape `show configuration | display set` produces. Tolerant of
/// unbalanced braces (diff fragments).
pub fn parse_junos_curly(lines: &[SrcLine]) -> Vec<Stmt> {
    let toks = tokenize_curly(lines);
    let mut out = Vec::new();
    // Stack of path frames: words pushed per open block.
    let mut frames: Vec<Vec<String>> = Vec::new();
    // Current statement words, with line of first word.
    let mut words: Vec<String> = Vec::new();
    let mut first_line = 0usize;
    let mut bracket: Option<Vec<String>> = None;
    let mut inactive = false;

    let path_prefix =
        |frames: &Vec<Vec<String>>| -> Vec<String> { frames.iter().flatten().cloned().collect() };

    for (no, tok) in toks {
        match tok {
            Tok::Word(w) => {
                if let Some(b) = bracket.as_mut() {
                    b.push(w);
                    continue;
                }
                if words.is_empty() {
                    first_line = no;
                    if w == "inactive:" {
                        inactive = true;
                        continue;
                    }
                    if w == "protect:" || w == "replace:" {
                        continue;
                    }
                }
                words.push(w);
            }
            Tok::LBracket => {
                if words.is_empty() {
                    first_line = no;
                }
                bracket = Some(Vec::new());
            }
            Tok::RBracket => {
                if let Some(b) = bracket.take() {
                    // Placeholder marker; expanded at statement end.
                    words.push(format!("\u{1}{}", b.join("\u{2}")));
                }
            }
            Tok::Open => {
                let mut full = path_prefix(&frames);
                full.extend(words.iter().cloned());
                if inactive && !full.is_empty() {
                    out.push(Stmt {
                        path: vec![format!("deactivate {}", full.join(" "))],
                        line: first_line,
                    });
                }
                frames.push(std::mem::take(&mut words));
                inactive = false;
            }
            Tok::Close => {
                if !words.is_empty() {
                    emit_leaf(
                        &mut out,
                        &path_prefix(&frames),
                        &words,
                        first_line,
                        inactive,
                    );
                    words.clear();
                    inactive = false;
                }
                frames.pop();
            }
            Tok::Semi => {
                if !words.is_empty() {
                    emit_leaf(
                        &mut out,
                        &path_prefix(&frames),
                        &words,
                        first_line,
                        inactive,
                    );
                }
                words.clear();
                inactive = false;
            }
        }
    }
    if !words.is_empty() {
        emit_leaf(
            &mut out,
            &path_prefix(&frames),
            &words,
            first_line,
            inactive,
        );
    }
    out
}

fn emit_leaf(
    out: &mut Vec<Stmt>,
    prefix: &[String],
    words: &[String],
    line: usize,
    inactive: bool,
) {
    // Expand a bracket list `[ a b ]` into one statement per element.
    let mut variants: Vec<Vec<String>> = vec![prefix.to_vec()];
    for w in words {
        if let Some(list) = w.strip_prefix('\u{1}') {
            let items: Vec<&str> = list.split('\u{2}').filter(|s| !s.is_empty()).collect();
            let mut next = Vec::new();
            for v in &variants {
                for it in &items {
                    let mut nv = v.clone();
                    nv.push((*it).to_string());
                    next.push(nv);
                }
            }
            variants = next;
        } else {
            for v in variants.iter_mut() {
                v.push(w.clone());
            }
        }
    }
    for v in variants {
        let text = v.join(" ");
        if inactive {
            out.push(Stmt {
                path: vec![format!("deactivate {text}")],
                line,
            });
        }
        out.push(Stmt {
            path: vec![text],
            line,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(c: &Config) -> Vec<String> {
        c.stmts.iter().map(|s| s.path.join(" / ")).collect()
    }

    #[test]
    fn ios_blocks_and_noise() {
        let cfg = "Building configuration...\n!\nhostname r1\n!\ninterface Gi1\n description  uplink \n shutdown\n!\nrouter bgp 65001\n address-family ipv4\n  neighbor 10.0.0.2 activate\n exit-address-family\nend\n";
        let c = parse(cfg, Vendor::CiscoIos);
        assert_eq!(c.tree.len(), 3);
        assert_eq!(c.tree[1].children.len(), 2);
        assert_eq!(c.tree[1].children[0].text, "description uplink");
        assert_eq!(
            c.tree[2].children[0].children[0].text,
            "neighbor 10.0.0.2 activate"
        );
        assert_eq!(c.tree[2].children[0].children[0].line, 11);
        let t = texts(&c);
        assert!(t.contains(
            &"router bgp 65001 / address-family ipv4 / neighbor 10.0.0.2 activate".to_string()
        ));
    }

    #[test]
    fn ios_banner_multiline() {
        let cfg = "banner motd ^C\nAuthorized access only\n  really\n^C\nhostname r1\n";
        let c = parse(cfg, Vendor::CiscoIos);
        assert_eq!(c.tree.len(), 2);
        assert_eq!(c.tree[0].children.len(), 3);
        assert_eq!(c.tree[1].text, "hostname r1");
    }

    #[test]
    fn ios_banner_single_line() {
        let c = parse("banner motd #hello#\nhostname r1\n", Vendor::CiscoIos);
        assert_eq!(c.tree.len(), 2);
        assert!(c.tree[0].children.is_empty());
    }

    #[test]
    fn eos_three_space_indent() {
        let cfg = "interface Ethernet1\n   description to-spine\n   no switchport\n   ip address 10.0.0.1/31\n!\nrouter bgp 65001\n   neighbor 10.0.0.0 remote-as 65000\n";
        let c = parse(cfg, Vendor::AristaEos);
        assert_eq!(c.tree.len(), 2);
        assert_eq!(c.tree[0].children.len(), 3);
    }

    #[test]
    fn junos_curly_to_set() {
        let cfg = "## Last commit: 2026-10-01\nsystem {\n    host-name r1;\n}\ninterfaces {\n    ge-0/0/0 {\n        /* uplink */\n        unit 0 {\n            family inet {\n                address 10.0.0.1/30;\n            }\n        }\n    }\n}\nprotocols {\n    bgp {\n        group EBGP {\n            export [ EXPORT-A EXPORT-B ];\n            inactive: neighbor 10.0.0.2 {\n                peer-as 65002;\n            }\n        }\n    }\n}\n";
        let c = parse(cfg, Vendor::Junos);
        let t: Vec<String> = c.stmts.iter().map(|s| s.text().to_string()).collect();
        assert!(t.contains(&"system host-name r1".to_string()));
        assert!(
            t.contains(&"interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30".to_string())
        );
        assert!(t.contains(&"protocols bgp group EBGP export EXPORT-A".to_string()));
        assert!(t.contains(&"protocols bgp group EBGP export EXPORT-B".to_string()));
        assert!(t.contains(&"deactivate protocols bgp group EBGP neighbor 10.0.0.2".to_string()));
        assert!(t.contains(&"protocols bgp group EBGP neighbor 10.0.0.2 peer-as 65002".to_string()));
        let addr = c
            .stmts
            .iter()
            .find(|s| s.text().ends_with("10.0.0.1/30"))
            .unwrap();
        assert_eq!(addr.line, 10);
    }

    #[test]
    fn junos_quoted_strings_keep_spaces() {
        let cfg =
            "interfaces {\n    ge-0/0/1 {\n        description \"to core { a; b }\";\n    }\n}\n";
        let c = parse(cfg, Vendor::Junos);
        assert_eq!(c.stmts.len(), 1);
        assert_eq!(
            c.stmts[0].text(),
            "interfaces ge-0/0/1 description \"to core { a; b }\""
        );
    }

    #[test]
    fn junos_set_style() {
        let cfg = "set system host-name r1\n# comment\nset interfaces ge-0/0/0 description \"wan link\"\ndeactivate protocols bgp group EBGP neighbor 10.0.0.2\n";
        let c = parse(cfg, Vendor::Junos);
        assert_eq!(c.stmts.len(), 3);
        assert_eq!(
            c.stmts[1].text(),
            "interfaces ge-0/0/0 description \"wan link\""
        );
        assert_eq!(
            c.stmts[2].text(),
            "deactivate protocols bgp group EBGP neighbor 10.0.0.2"
        );
        assert_eq!(c.stmts[2].line, 4);
    }

    #[test]
    fn junos_curly_tolerates_unbalanced_fragment() {
        let lines = vec![
            (10, "        address 10.0.0.1/30;"),
            (11, "    }"),
            (12, "}"),
            (13, "}"),
        ];
        let s = parse_junos_curly(&lines);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].text(), "address 10.0.0.1/30");
    }

    #[test]
    fn tokens_respect_quotes() {
        assert_eq!(
            junos_tokens("set a b \"c d\" e"),
            vec!["set", "a", "b", "\"c d\"", "e"]
        );
    }
}

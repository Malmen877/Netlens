//! Remove reasoning blocks (`<think>...</think>`) emitted by Qwen3 and
//! similar models before the answer is parsed.

/// Strip `<think>` blocks. Handles several blocks, a closing tag without an
/// opening one (the template injected `<think>`), and an unterminated block
/// (truncated output: everything after `<think>` is dropped).
pub fn strip_think(s: &str) -> String {
    let mut out = s.to_string();
    // Closing tag with no opening tag before it: drop everything up to it.
    if let Some(close) = out.find("</think>") {
        let open = out.find("<think>");
        if open.is_none() || open.unwrap() > close {
            out = out[close + "</think>".len()..].to_string();
        }
    }
    while let Some(start) = out.find("<think>") {
        match out[start..].find("</think>") {
            Some(rel) => {
                let end = start + rel + "</think>".len();
                out.replace_range(start..end, "");
            }
            None => {
                out.truncate(start);
                break;
            }
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_blocks() {
        assert_eq!(
            strip_think("<think>\nhmm\n</think>\n\nSUMMARY:\n- x [F1]"),
            "SUMMARY:\n- x [F1]"
        );
        assert_eq!(strip_think("a<think>1</think>b<think>2</think>c"), "abc");
        assert_eq!(strip_think("reasoning only</think>answer"), "answer");
        assert_eq!(strip_think("answer<think>truncated..."), "answer");
        assert_eq!(strip_think("<think></think>"), "");
        assert_eq!(strip_think("no think here"), "no think here");
    }
}

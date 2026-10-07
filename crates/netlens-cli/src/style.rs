//! Minimal ANSI styling that honours NO_COLOR, --color and TTY detection.

use netlens_core::Severity;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub on: bool,
}

impl Style {
    pub fn new(choice: ColorChoice) -> Self {
        let on = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                std::env::var_os("NO_COLOR")
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
                    && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
                    && std::io::stdout().is_terminal()
            }
        };
        Style { on }
    }

    pub fn stderr(choice: ColorChoice) -> Self {
        let on = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                std::env::var_os("NO_COLOR")
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
                    && std::io::stderr().is_terminal()
            }
        };
        Style { on }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn heading(&self, s: &str) -> String {
        self.wrap("1;4", s)
    }

    /// Fixed-width, colored severity label.
    pub fn sev(&self, sev: Severity) -> String {
        let label = format!("{:<8}", sev.as_str().to_uppercase());
        let code = match sev {
            Severity::Critical => "1;97;41",
            Severity::High => "1;31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.wrap(code, &label)
    }
}

/// Greedy word wrap with a hanging indent.
pub fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for w in text.split_whitespace() {
        if !line.is_empty() && indent.len() + line.len() + 1 + w.len() > width {
            out.push_str(indent);
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(w);
    }
    if !line.is_empty() {
        out.push_str(indent);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

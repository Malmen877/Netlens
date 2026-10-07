//! The vendor-neutral configuration model.
//!
//! IOS/EOS configs are kept as an indentation tree ([`Node`]). Every config,
//! including Junos (curly or `set`), is also flattened into a list of
//! [`Stmt`]s: a path of normalized lines plus the source line number. The
//! semantic diff and most rules work on that flat form.

use crate::vendor::Vendor;
use serde::Serialize;

/// One line of an indentation-structured config with its children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    /// Whitespace-normalized text of the line.
    pub text: String,
    /// 1-based source line; 0 for synthetic context (e.g. a diff hunk header).
    pub line: usize,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(text: impl Into<String>, line: usize) -> Self {
        Node {
            text: text.into(),
            line,
            children: Vec::new(),
        }
    }
}

/// A flattened statement. For IOS/EOS `path` is the chain of block headers
/// ending with the line itself; for Junos it is a single element holding the
/// full `set`-style path (without the leading `set `).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Stmt {
    pub path: Vec<String>,
    pub line: usize,
}

impl Stmt {
    pub fn text(&self) -> &str {
        self.path.last().map(String::as_str).unwrap_or("")
    }

    /// Display form: Junos statements get their `set ` prefix back.
    pub fn display(&self, vendor: Vendor) -> String {
        if vendor == Vendor::Junos {
            junos_display(self.text())
        } else {
            self.text().to_string()
        }
    }
}

/// `interfaces ge-0/0/0 disable` -> `set interfaces ge-0/0/0 disable`;
/// `deactivate ...` stays as is.
pub fn junos_display(stmt: &str) -> String {
    if stmt.starts_with("deactivate ") {
        stmt.to_string()
    } else {
        format!("set {stmt}")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Config {
    pub vendor: Vendor,
    /// Indentation tree (IOS/EOS only; empty for Junos).
    pub tree: Vec<Node>,
    pub stmts: Vec<Stmt>,
    /// True when built from diff hunks rather than a full config.
    pub partial: bool,
}

impl Config {
    pub fn empty(vendor: Vendor) -> Self {
        Config {
            vendor,
            tree: Vec::new(),
            stmts: Vec::new(),
            partial: false,
        }
    }

    /// Statement text at a given source line (first match), for evidence.
    pub fn text_at(&self, line: usize) -> Option<String> {
        self.stmts
            .iter()
            .find(|s| s.line == line)
            .map(|s| s.display(self.vendor))
    }
}

/// Flatten a tree into statements (header chain + line).
pub fn flatten(tree: &[Node]) -> Vec<Stmt> {
    fn walk(nodes: &[Node], prefix: &mut Vec<String>, out: &mut Vec<Stmt>) {
        for n in nodes {
            prefix.push(n.text.clone());
            out.push(Stmt {
                path: prefix.clone(),
                line: n.line,
            });
            walk(&n.children, prefix, out);
            prefix.pop();
        }
    }
    let mut out = Vec::new();
    walk(tree, &mut Vec::new(), &mut out);
    out
}

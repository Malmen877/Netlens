//! Findings: the citable unit of evidence.

use crate::section::Section;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            o => Err(format!(
                "unknown severity '{o}' (expected info, low, medium, high or critical)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Before,
    After,
}

impl Side {
    pub fn as_str(&self) -> &'static str {
        match self {
            Side::Before => "before",
            Side::After => "after",
        }
    }
}

/// One quoted line of evidence: which file, which line, what it says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub side: Side,
    /// 1-based line; 0 when the line came from diff context without a number.
    pub line: usize,
    pub text: String,
}

impl Evidence {
    pub fn before(line: usize, text: impl Into<String>) -> Self {
        Evidence {
            side: Side::Before,
            line,
            text: text.into(),
        }
    }
    pub fn after(line: usize, text: impl Into<String>) -> Self {
        Evidence {
            side: Side::After,
            line,
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable citation id within one report: F1.. (rules) or B1.. (Batfish).
    pub id: String,
    /// Rule id, e.g. NL-BGP-002 or BF-UNDEFINED-REF.
    pub rule: String,
    pub severity: Severity,
    pub section: Section,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(
        rule: &str,
        severity: Severity,
        section: Section,
        title: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Finding {
            id: String::new(),
            rule: rule.to_string(),
            severity,
            section,
            title: title.into(),
            explanation: explanation.into(),
            evidence: Vec::new(),
        }
    }

    pub fn with(mut self, ev: Evidence) -> Self {
        self.evidence.push(ev);
        self
    }

    pub fn first_line(&self) -> usize {
        self.evidence.iter().map(|e| e.line).min().unwrap_or(0)
    }
}

/// Sort findings (severity desc, then evidence position, then rule) and
/// assign ids with the given prefix ("F" or "B").
pub fn assign_ids(findings: &mut [Finding], prefix: &str) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.first_line().cmp(&b.first_line()))
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.title.cmp(&b.title))
    });
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = format!("{prefix}{}", i + 1);
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn of<'a>(fs: impl IntoIterator<Item = &'a Finding>) -> Self {
        let mut c = SeverityCounts::default();
        for f in fs {
            match f.severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                Severity::Info => c.info += 1,
            }
        }
        c
    }

    pub fn max(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else if self.info > 0 {
            Some(Severity::Info)
        } else {
            None
        }
    }
}

//! Troubleshooting fixtures: recorded `show` outputs per scenario, for a mock
//! SSH runner and end-to-end tests.
//!
//! Layout: `fixtures/<vendor>/<scenario>/scenario.toml` plus one text file per
//! command and a `syslog.log` excerpt. `scenario.toml` maps exact command
//! strings to files; [`Scenario::output`] looks a command up the way a device
//! would see it (whitespace collapsed, case-insensitive).

use crate::allowlist::Vendor;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// Expected root cause of a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCause {
    /// Short stable id, e.g. `mtu-mismatch`.
    pub id: String,
    /// One or two sentences a good answer should contain.
    pub text: String,
}

/// One replayable command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFixture {
    /// Exact command string as an engineer would type it.
    pub command: String,
    /// File (relative to the scenario directory) with the device output.
    pub file: String,
}

/// A line that must appear verbatim in a file and that a good diagnosis
/// should cite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub file: String,
    /// Exact full line, including leading spaces.
    pub line: String,
    #[serde(default)]
    pub why: Option<String>,
}

/// A troubleshooting scenario (`scenario.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub vendor: Vendor,
    pub hostname: String,
    pub title: String,
    pub description: String,
    pub symptom: String,
    /// Syslog excerpt file, relative to the scenario directory.
    pub syslog: String,
    pub root_cause: RootCause,
    pub commands: Vec<CommandFixture>,
    pub key_evidence: Vec<Evidence>,
    /// Directory the scenario was loaded from (not part of the TOML).
    #[serde(skip)]
    pub dir: PathBuf,
}

/// Error loading a scenario.
#[derive(Debug)]
pub enum FixtureError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, String),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixtureError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            FixtureError::Parse(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for FixtureError {}

fn norm(cmd: &str) -> String {
    cmd.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

impl Scenario {
    /// Load `dir/scenario.toml`.
    pub fn load(dir: impl AsRef<Path>) -> Result<Self, FixtureError> {
        let dir = dir.as_ref().to_path_buf();
        let path = dir.join("scenario.toml");
        let text = std::fs::read_to_string(&path).map_err(|e| FixtureError::Io(path.clone(), e))?;
        let mut s: Scenario =
            toml::from_str(&text).map_err(|e| FixtureError::Parse(path, e.to_string()))?;
        s.dir = dir;
        Ok(s)
    }

    /// File name for a command, if recorded.
    pub fn file_for(&self, cmd: &str) -> Option<&str> {
        let n = norm(cmd);
        self.commands
            .iter()
            .find(|c| norm(&c.command) == n)
            .map(|c| c.file.as_str())
    }

    /// Recorded output for a command (`None` if the command is not recorded).
    pub fn output(&self, cmd: &str) -> Option<Result<String, FixtureError>> {
        let file = self.file_for(cmd)?;
        let path = self.dir.join(file);
        Some(std::fs::read_to_string(&path).map_err(|e| FixtureError::Io(path, e)))
    }

    /// The syslog excerpt.
    pub fn syslog_text(&self) -> Result<String, FixtureError> {
        let path = self.dir.join(&self.syslog);
        std::fs::read_to_string(&path).map_err(|e| FixtureError::Io(path, e))
    }
}

/// The shared fixture directory (`examples/troubleshoot/` at the repo root).
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/troubleshoot")
}

/// All scenario directories under `root` (`root/<vendor>/<scenario>/`), sorted.
pub fn scenario_dirs(root: impl AsRef<Path>) -> Result<Vec<PathBuf>, FixtureError> {
    let root = root.as_ref();
    let mut out = Vec::new();
    let rd = |p: &Path| std::fs::read_dir(p).map_err(|e| FixtureError::Io(p.to_path_buf(), e));
    for vendor in rd(root)? {
        let vendor = vendor
            .map_err(|e| FixtureError::Io(root.to_path_buf(), e))?
            .path();
        if !vendor.is_dir() {
            continue;
        }
        for sc in rd(&vendor)? {
            let sc = sc.map_err(|e| FixtureError::Io(vendor.clone(), e))?.path();
            if sc.join("scenario.toml").is_file() {
                out.push(sc);
            }
        }
    }
    out.sort();
    Ok(out)
}

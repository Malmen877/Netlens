//! Read-only command allowlist for netlens.
//!
//! Every command the copilot wants to run on a device goes through [`check`]
//! (or [`vet`], which also returns the normalized command to send). A command
//! is accepted only if it survives every stage of this pipeline:
//!
//! 1. **Length**: non-empty, at most [`MAX_COMMAND_LEN`] bytes.
//! 2. **Characters**: printable ASCII and plain spaces only. Control
//!    characters (including `\t`, `\r`, `\n`, NUL, ESC, DEL), Unicode format
//!    characters (zero-width, bidi controls, U+2028/2029) and any other
//!    non-ASCII character (Cyrillic or fullwidth lookalikes, NBSP) are rejected.
//! 3. **Shell metacharacters**: `;`, backtick, `$(`, `${`, `&`, `&&`, `||`,
//!    `>`, `<` and `?` (CLI help) are rejected outright.
//! 4. **Normalization**: trim, collapse runs of spaces, lowercase for matching
//!    (the original case is kept in the returned command and in errors).
//! 5. **Denylist** (compiled in, not configurable, always wins): the verb, every
//!    token of the command part, and the first word of every pipe segment are
//!    checked, including unique-prefix abbreviations such as `conf t`, `wr`,
//!    `del`, `| red`.
//! 6. **Show gate**: the first word must be `show`, `sho` or `sh`.
//! 7. **Pipes**: each `| filter` must be a known read-only filter for the vendor
//!    with valid arguments.
//! 8. **Allowlist**: the canonicalized command part (abbreviations expanded)
//!    must fully match one of the vendor's anchored regexes (defaults from
//!    `allowlist-defaults.toml` plus any user additions).

use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Maximum accepted command length in bytes (all accepted input is ASCII,
/// so bytes == characters).
pub const MAX_COMMAND_LEN: usize = 256;

/// The built-in allowlist, embedded at compile time.
pub const DEFAULTS_TOML: &str = include_str!("../allowlist-defaults.toml");

// ---------------------------------------------------------------------------
// Vendor
// ---------------------------------------------------------------------------

/// Device operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vendor {
    /// Cisco IOS and IOS-XE.
    #[serde(
        alias = "ios-xe",
        alias = "iosxe",
        alias = "ios_xe",
        alias = "cisco_ios",
        alias = "cisco_xe"
    )]
    Ios,
    /// Juniper Junos (and Junos Evolved).
    #[serde(alias = "juniper", alias = "juniper_junos", alias = "junos-evo")]
    Junos,
    /// Arista EOS.
    #[serde(alias = "arista", alias = "arista_eos")]
    Eos,
}

impl Vendor {
    /// All supported vendors.
    pub const ALL: [Vendor; 3] = [Vendor::Ios, Vendor::Junos, Vendor::Eos];

    /// Stable lowercase identifier (`ios`, `junos`, `eos`), also used as the
    /// TOML table name.
    pub fn as_str(self) -> &'static str {
        match self {
            Vendor::Ios => "ios",
            Vendor::Junos => "junos",
            Vendor::Eos => "eos",
        }
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by `Vendor::from_str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVendor(pub String);

impl fmt::Display for UnknownVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown vendor {:?} (expected ios, junos or eos)",
            self.0
        )
    }
}

impl std::error::Error for UnknownVendor {}

impl FromStr for Vendor {
    type Err = UnknownVendor;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ios" | "ios-xe" | "iosxe" | "ios_xe" | "cisco_ios" | "cisco_xe" => Ok(Vendor::Ios),
            "junos" | "juniper" | "juniper_junos" | "junos-evo" => Ok(Vendor::Junos),
            "eos" | "arista" | "arista_eos" => Ok(Vendor::Eos),
            _ => Err(UnknownVendor(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Rejection
// ---------------------------------------------------------------------------

/// Machine-readable reason a command was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionKind {
    /// Empty or whitespace-only command.
    Empty,
    /// Longer than [`MAX_COMMAND_LEN`] bytes.
    TooLong { len: usize, max: usize },
    /// A control or invisible formatting character (`\n`, `\r`, `\t`, NUL,
    /// ESC, DEL, zero-width, bidi, U+2028/2029, ...). `pos` is a byte offset.
    ControlChar { ch: char, pos: usize },
    /// Any other non-ASCII character (lookalike letters, NBSP, ...).
    NonAscii { ch: char, pos: usize },
    /// Shell or CLI metacharacter sequence (`;`, `&&`, `>`, backtick, ...).
    Injection { token: String },
    /// Hit the compiled-in denylist. `rule` names the denied verb or filter.
    Denied { rule: String },
    /// A pipe filter that is unknown, unsafe for this vendor, or has invalid
    /// arguments.
    InvalidPipe { filter: String },
    /// Passed all safety checks but matched no allowlist pattern.
    NotAllowed,
}

/// A rejected command: machine kind, human reason, and the original input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub kind: RejectionKind,
    pub reason: String,
    /// The command exactly as submitted.
    pub command: String,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug-format the command so control characters are escaped and
        // cannot mess with the operator's terminal.
        write!(f, "command {:?} rejected: {}", self.command, self.reason)
    }
}

impl std::error::Error for Rejection {}

/// A command that passed [`vet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vetted {
    /// Trimmed, whitespace-collapsed command in its original case. Send this
    /// string to the device.
    pub command: String,
    /// Lowercased command part with abbreviations expanded, as matched against
    /// the allowlist (useful for audit logs).
    pub canonical: String,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Error loading the allowlist configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// Not valid TOML.
    Parse(String),
    /// The user tried to configure the denylist. It is compiled in and cannot
    /// be extended, reduced or disabled.
    DenylistNotConfigurable { key: String },
    /// A key netlens does not know about.
    UnknownKey { key: String },
    /// A key has the wrong type.
    InvalidType { key: String, expected: &'static str },
    /// A pattern failed to compile.
    InvalidPattern {
        vendor: Vendor,
        pattern: String,
        error: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(e) => write!(f, "allowlist config is not valid TOML: {e}"),
            ConfigError::DenylistNotConfigurable { key } => write!(
                f,
                "allowlist config key `{key}` is not allowed: the denylist is compiled in and cannot be configured"
            ),
            ConfigError::UnknownKey { key } => write!(
                f,
                "unknown allowlist config key `{key}` (expected [ios], [junos] or [eos] tables with an `allow` array)"
            ),
            ConfigError::InvalidType { key, expected } => {
                write!(f, "allowlist config key `{key}` must be {expected}")
            }
            ConfigError::InvalidPattern { vendor, pattern, error } => {
                write!(f, "invalid {vendor} allow pattern {pattern:?}: {error}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone)]
struct VendorRules {
    /// Patterns as written (before placeholder expansion and anchoring).
    patterns: Vec<String>,
    set: RegexSet,
}

impl VendorRules {
    fn build(vendor: Vendor, patterns: Vec<String>) -> Result<Self, ConfigError> {
        let mut compiled = Vec::with_capacity(patterns.len());
        for p in &patterns {
            let full = anchor(p);
            // Compile individually first so the error names the bad pattern.
            Regex::new(&full).map_err(|e| ConfigError::InvalidPattern {
                vendor,
                pattern: p.clone(),
                error: e.to_string(),
            })?;
            compiled.push(full);
        }
        let set = RegexSet::new(&compiled).map_err(|e| ConfigError::InvalidPattern {
            vendor,
            pattern: "<set>".into(),
            error: e.to_string(),
        })?;
        Ok(VendorRules { patterns, set })
    }
}

/// Placeholders usable in allow patterns (defaults and user config).
const PLACEHOLDERS: &[(&str, &str)] = &[
    // Interface name: gi0/0/1, GigabitEthernet 0/0/1, Ethernet49/1, et-0/0/1:2,
    // ge-0/0/0.100, irb.100, ae0, Port-Channel10, lo0.
    ("{IF}", r"(?:[a-z][a-z0-9\-]*(?: ?[0-9/.:]*[0-9])?)"),
    // IPv4/IPv6 address.
    ("{IP}", r"(?:[0-9a-f:.]+)"),
    // Prefix: address, address/len, or IOS "address mask".
    ("{PFX}", r"(?:[0-9a-f:.]+(?:/[0-9]{1,3}| [0-9.]+)?)"),
    // Generic name (VRF, ACL, group, instance, log file).
    ("{NAME}", r"(?:[a-z0-9_.:\-]+)"),
    ("{NUM}", r"(?:[0-9]{1,10})"),
    ("{MAC}", r"(?:[0-9a-f.:\-]+)"),
    // One or more space-separated words (config hierarchy, section names).
    ("{ARGS}", r"(?:[a-z0-9_.:/\-]+(?: [a-z0-9_.:/\-]+)*)"),
];

fn expand_placeholders(p: &str) -> String {
    let mut out = p.to_string();
    for (k, v) in PLACEHOLDERS {
        out = out.replace(k, v);
    }
    out
}

/// Expand placeholders and anchor. Always wraps, even if the author already
/// wrote `^...$`, so a pattern can never match a substring.
fn anchor(p: &str) -> String {
    format!("(?i)^(?:{})$", expand_placeholders(p))
}

/// Allowlist configuration: compiled-in defaults plus optional user additions.
///
/// The denylist is not part of this struct; it is a set of compiled-in
/// constants that no configuration can change.
#[derive(Debug, Clone)]
pub struct AllowlistConfig {
    ios: VendorRules,
    junos: VendorRules,
    eos: VendorRules,
}

impl Default for AllowlistConfig {
    /// The embedded `allowlist-defaults.toml`.
    fn default() -> Self {
        let lists =
            parse_allow_tables(DEFAULTS_TOML).expect("embedded allowlist-defaults.toml must parse");
        Self::from_lists(lists).expect("embedded allowlist-defaults.toml patterns must compile")
    }
}

impl AllowlistConfig {
    /// Defaults merged with a user TOML document.
    ///
    /// Accepted shape (every table and key optional):
    ///
    /// ```toml
    /// [ios]
    /// allow = ['show platform hardware qfp active statistics drop']
    /// [junos]
    /// allow = ['show services .+']
    /// ```
    ///
    /// Any other key is an error. Keys that look like an attempt to configure
    /// the denylist (`deny`, `denylist`, ...) give
    /// [`ConfigError::DenylistNotConfigurable`].
    pub fn from_toml_str(user: &str) -> Result<Self, ConfigError> {
        let mut cfg = Self::default();
        cfg.extend_from_toml_str(user)?;
        Ok(cfg)
    }

    /// Read a user TOML file and merge it with the defaults.
    pub fn from_toml_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Parse(format!("{}: {e}", path.as_ref().display())))?;
        Self::from_toml_str(&text)
    }

    /// Add the `allow` patterns from a user TOML document. On error, `self` is
    /// left unchanged.
    pub fn extend_from_toml_str(&mut self, user: &str) -> Result<(), ConfigError> {
        let extra = parse_allow_tables(user)?;
        let mut lists = [
            self.ios.patterns.clone(),
            self.junos.patterns.clone(),
            self.eos.patterns.clone(),
        ];
        for (i, add) in extra.into_iter().enumerate() {
            lists[i].extend(add);
        }
        *self = Self::from_lists(lists)?;
        Ok(())
    }

    /// The allow patterns for a vendor, as written (unanchored, placeholders
    /// not expanded).
    pub fn patterns(&self, vendor: Vendor) -> &[String] {
        &self.rules(vendor).patterns
    }

    fn rules(&self, vendor: Vendor) -> &VendorRules {
        match vendor {
            Vendor::Ios => &self.ios,
            Vendor::Junos => &self.junos,
            Vendor::Eos => &self.eos,
        }
    }

    fn from_lists(lists: [Vec<String>; 3]) -> Result<Self, ConfigError> {
        let [ios, junos, eos] = lists;
        Ok(AllowlistConfig {
            ios: VendorRules::build(Vendor::Ios, ios)?,
            junos: VendorRules::build(Vendor::Junos, junos)?,
            eos: VendorRules::build(Vendor::Eos, eos)?,
        })
    }
}

fn looks_like_deny_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "deny",
        "block",
        "forbid",
        "override",
        "replace",
        "remove",
        "disable",
        "unsafe",
        "allow_all",
    ]
    .iter()
    .any(|w| k.contains(w))
}

/// Parse `[ios|junos|eos] allow = [..]` tables, in `Vendor::ALL` order.
fn parse_allow_tables(text: &str) -> Result<[Vec<String>; 3], ConfigError> {
    let table: toml::Table = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    let mut out: [Vec<String>; 3] = Default::default();
    for (key, value) in &table {
        let idx = match key.as_str() {
            "ios" => 0,
            "junos" => 1,
            "eos" => 2,
            k if looks_like_deny_key(k) => {
                return Err(ConfigError::DenylistNotConfigurable { key: k.into() })
            }
            k => return Err(ConfigError::UnknownKey { key: k.into() }),
        };
        let vt = value.as_table().ok_or_else(|| ConfigError::InvalidType {
            key: key.clone(),
            expected: "a table",
        })?;
        for (sub, v) in vt {
            let full = format!("{key}.{sub}");
            if sub != "allow" {
                return Err(if looks_like_deny_key(sub) {
                    ConfigError::DenylistNotConfigurable { key: full }
                } else {
                    ConfigError::UnknownKey { key: full }
                });
            }
            let arr = v.as_array().ok_or_else(|| ConfigError::InvalidType {
                key: full.clone(),
                expected: "an array of strings",
            })?;
            for item in arr {
                let s = item.as_str().ok_or_else(|| ConfigError::InvalidType {
                    key: full.clone(),
                    expected: "an array of strings",
                })?;
                out[idx].push(s.to_string());
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Denylist (compiled in; NOT configurable)
// ---------------------------------------------------------------------------

/// First-word verbs that are always denied. Matching is prefix-aware: any
/// prefix of one of these (e.g. `conf`, `co`, `wr`, `del`, `rel`, `cl`, `deb`,
/// `req`, `ed`, `com`, `roll`, `s`) is denied, unless it is `sh`/`sho`/`show`.
pub const DENY_VERBS: &[&str] = &[
    "configure",
    "write",
    "copy",
    "reload",
    "delete",
    "erase",
    "format",
    "squeeze",
    "clear",
    "debug",
    "undebug",
    "no",
    "request",
    "set",
    "edit",
    "commit",
    "rollback",
    "file",
    "test",
    "start",
    "shell",
    "telnet",
    "ssh",
    "rlogin",
    "connect",
    "tclsh",
    "bash",
    "python",
    "guestshell",
    "terminal",
    "archive",
    "monitor",
    "ping",
    "traceroute",
    "enable",
    "disable",
    "restart",
    "load",
    "save",
    "install",
    "upgrade",
    "rename",
    "mkdir",
    "rmdir",
    "send",
    "op",
    "event",
    "run",
    "verify",
    "license",
    "crypto",
    "redirect",
    "tee",
    "append",
    "exec",
];

/// Tokens that are denied anywhere in the command part (exact match after
/// lowercasing). Kept to words that are never legitimate `show` arguments in
/// the default allowlist.
pub const DENY_TOKENS: &[&str] = &[
    "configure",
    "write",
    "copy",
    "reload",
    "delete",
    "erase",
    "format",
    "squeeze",
    "clear",
    "request",
    "edit",
    "set",
    "start",
    "shell",
    "telnet",
    "ssh",
    "tclsh",
    "bash",
    "restart",
    "terminal",
    "enable",
    "ping",
    "traceroute",
    "redirect",
    "tee",
    "append",
    "save",
    "exec",
];

/// Pipe filters that are always denied (they write files, run commands, or
/// never terminate). Prefix-aware like [`DENY_VERBS`].
pub const DENY_PIPES: &[&str] = &[
    "save", "redirect", "tee", "append", "exec", "format", "request", "refresh", "hold",
];

/// Accepted spellings of the `show` verb.
const SHOW_PREFIXES: &[&str] = &["sh", "sho", "show"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Args {
    /// No arguments.
    None,
    /// At least one argument (a search pattern).
    Required,
    /// Any arguments, including none.
    Optional,
    /// Optional single integer.
    OptNumber,
    /// Exactly one integer.
    Number,
    /// Junos `display` modifiers.
    Display,
}

struct Filter {
    name: &'static str,
    /// Shortest accepted abbreviation.
    min: usize,
    args: Args,
}

const IOS_FILTERS: &[Filter] = &[
    Filter {
        name: "include",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "exclude",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "begin",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "section",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "count",
        min: 1,
        args: Args::Optional,
    },
];

const EOS_FILTERS: &[Filter] = &[
    Filter {
        name: "include",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "exclude",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "begin",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "section",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "json",
        min: 1,
        args: Args::None,
    },
    Filter {
        name: "no-more",
        min: 2,
        args: Args::None,
    },
];

const JUNOS_FILTERS: &[Filter] = &[
    Filter {
        name: "match",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "except",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "find",
        min: 1,
        args: Args::Required,
    },
    Filter {
        name: "count",
        min: 3,
        args: Args::None,
    },
    Filter {
        name: "no-more",
        min: 1,
        args: Args::None,
    },
    Filter {
        name: "last",
        min: 1,
        args: Args::OptNumber,
    },
    Filter {
        name: "trim",
        min: 2,
        args: Args::Number,
    },
    Filter {
        name: "display",
        min: 1,
        args: Args::Display,
    },
];

fn filters(vendor: Vendor) -> &'static [Filter] {
    match vendor {
        Vendor::Ios => IOS_FILTERS,
        Vendor::Eos => EOS_FILTERS,
        Vendor::Junos => JUNOS_FILTERS,
    }
}

// ---------------------------------------------------------------------------
// Abbreviation canonicalization (matching only; never changes what is sent)
// ---------------------------------------------------------------------------

const IOS_EOS_KEYWORDS: &[(&str, usize)] = &[
    ("interface", 3),
    ("brief", 2),
    ("summary", 3),
    ("neighbors", 3),
    ("running-config", 3),
    ("startup-config", 6),
    ("version", 3),
    ("logging", 3),
    ("environment", 3),
    ("inventory", 3),
    ("processes", 4),
    ("access-lists", 3),
    ("route", 2),
    ("detail", 3),
    ("counters", 4),
    ("description", 4),
    ("transceiver", 5),
    ("status", 4),
    ("address-table", 3),
    ("database", 2),
    ("clock", 3),
    ("associations", 3),
    ("spanning-tree", 4),
    ("sorted", 4),
    ("history", 4),
    ("errors", 4),
    ("advertised-routes", 3),
    ("received-routes", 4),
    ("unicast", 3),
    ("etherchannel", 5),
    ("standby", 4),
    ("protocols", 4),
];

const JUNOS_KEYWORDS: &[(&str, usize)] = &[
    ("interfaces", 3),
    ("terse", 3),
    ("extensive", 3),
    ("descriptions", 4),
    ("summary", 3),
    ("neighbor", 3),
    ("configuration", 4),
    ("version", 3),
    ("messages", 3),
    ("chassis", 3),
    ("hardware", 3),
    ("environment", 3),
    ("alarms", 3),
    ("processes", 4),
    ("system", 3),
    ("uptime", 3),
    ("route", 3),
    ("associations", 3),
    ("diagnostics", 4),
    ("optics", 3),
    ("detail", 3),
    ("brief", 2),
    ("ethernet-switching", 5),
    ("table", 3),
    ("protocol", 5),
    ("database", 3),
    ("firewall", 4),
    ("storage", 3),
    ("statistics", 5),
    ("status", 5),
];

fn canonical_token(vendor: Vendor, tok: &str) -> String {
    let kws = match vendor {
        Vendor::Junos => JUNOS_KEYWORDS,
        _ => IOS_EOS_KEYWORDS,
    };
    let mut hit = None;
    for (kw, min) in kws {
        if tok.len() >= *min && kw.starts_with(tok) {
            if hit.is_some() {
                return tok.to_string(); // ambiguous: leave as typed
            }
            hit = Some(*kw);
        }
    }
    hit.unwrap_or(tok).to_string()
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Unicode characters that are invisible or reorder text: rejected as
/// control characters (before the general non-ASCII rule) for clearer errors.
fn is_control_like(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}' | '\u{FEFF}' | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}')
}

/// Forbidden metacharacter sequences, longest first.
const INJECTION_TOKENS: &[&str] = &["$(", "${", "&&", "||", ";", "`", "&", ">", "<", "?"];

/// Check a command. `Ok(())` means it may be sent to a device of `vendor`.
pub fn check(vendor: Vendor, cmd: &str, cfg: &AllowlistConfig) -> Result<(), Rejection> {
    vet(vendor, cmd, cfg).map(|_| ())
}

/// Like [`check`], but returns the normalized command to send and its
/// canonical form.
pub fn vet(vendor: Vendor, cmd: &str, cfg: &AllowlistConfig) -> Result<Vetted, Rejection> {
    let rej = |kind: RejectionKind, reason: String| Rejection {
        kind,
        reason,
        command: cmd.to_string(),
    };

    // 1. Length.
    if cmd.len() > MAX_COMMAND_LEN {
        return Err(rej(
            RejectionKind::TooLong {
                len: cmd.len(),
                max: MAX_COMMAND_LEN,
            },
            format!(
                "command is {} bytes, the limit is {MAX_COMMAND_LEN}",
                cmd.len()
            ),
        ));
    }

    // 2. Characters.
    for (pos, ch) in cmd.char_indices() {
        if ch == ' ' {
            continue;
        }
        if is_control_like(ch) {
            return Err(rej(
                RejectionKind::ControlChar { ch, pos },
                format!(
                    "control or invisible character {:?} (U+{:04X}) at byte {pos}",
                    ch, ch as u32
                ),
            ));
        }
        if !ch.is_ascii() {
            return Err(rej(
                RejectionKind::NonAscii { ch, pos },
                format!("non-ASCII character {:?} (U+{:04X}) at byte {pos}; only plain ASCII is accepted", ch, ch as u32),
            ));
        }
    }

    let trimmed = cmd.trim_matches(' ');
    if trimmed.is_empty() {
        return Err(rej(RejectionKind::Empty, "empty command".into()));
    }

    // 3. Metacharacters.
    for tok in INJECTION_TOKENS {
        if trimmed.contains(tok) {
            return Err(rej(
                RejectionKind::Injection {
                    token: (*tok).to_string(),
                },
                format!("forbidden character sequence {tok:?}"),
            ));
        }
    }
    if vendor == Vendor::Junos && trimmed.contains("\\\"") {
        return Err(rej(
            RejectionKind::Injection {
                token: "\\\"".into(),
            },
            "escaped quote is not allowed".into(),
        ));
    }

    // 4. Normalize.
    let normalized: String = trimmed
        .split(' ')
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let lower = normalized.to_ascii_lowercase();

    // Split on pipes. Junos honours double quotes (`| match "a|b"`); IOS and
    // EOS treat quotes literally, so every `|` is a pipe boundary there.
    let segments = match split_pipes(vendor, &lower) {
        Some(s) => s,
        None => {
            return Err(rej(
                RejectionKind::Injection { token: "\"".into() },
                "unbalanced double quote".into(),
            ))
        }
    };
    let main = segments[0].trim();
    if main.is_empty() {
        return Err(rej(
            RejectionKind::InvalidPipe {
                filter: String::new(),
            },
            "pipe without a command before it".into(),
        ));
    }
    let tokens: Vec<&str> = main.split(' ').collect();

    // 5. Denylist: verb (prefix-aware) ...
    let verb = tokens[0];
    if !SHOW_PREFIXES.contains(&verb) {
        let hits: Vec<&str> = DENY_VERBS
            .iter()
            .copied()
            .filter(|v| v.starts_with(verb))
            .collect();
        if let Some(first) = hits.first() {
            return Err(rej(
                RejectionKind::Denied {
                    rule: (*first).to_string(),
                },
                if hits.len() == 1 && hits[0] == verb {
                    format!("`{verb}` is on the denylist")
                } else {
                    format!(
                        "`{verb}` is (an abbreviation of) a denied command: {}",
                        hits.join(", ")
                    )
                },
            ));
        }
        // 6. Show gate.
        return Err(rej(
            RejectionKind::NotAllowed,
            format!("only `show` commands are allowed, got `{verb}`"),
        ));
    }
    // ... every other token of the command part (exact) ...
    for t in &tokens[1..] {
        if DENY_TOKENS.contains(t) {
            return Err(rej(
                RejectionKind::Denied {
                    rule: (*t).to_string(),
                },
                format!("token `{t}` is on the denylist"),
            ));
        }
    }
    // ... and the first word of every pipe segment (prefix-aware).
    for seg in &segments[1..] {
        check_pipe(vendor, seg.trim()).map_err(|(kind, reason)| rej(kind, reason))?;
    }

    // 8. Allowlist on the canonical command part.
    let canonical = std::iter::once("show".to_string())
        .chain(tokens[1..].iter().map(|t| canonical_token(vendor, t)))
        .collect::<Vec<_>>()
        .join(" ");
    if !cfg.rules(vendor).set.is_match(&canonical) {
        return Err(rej(
            RejectionKind::NotAllowed,
            format!("`{canonical}` is not on the {vendor} allowlist"),
        ));
    }

    Ok(Vetted {
        command: normalized,
        canonical,
    })
}

/// Returns `None` on unbalanced quotes (Junos only).
fn split_pipes(vendor: Vendor, s: &str) -> Option<Vec<String>> {
    if vendor != Vendor::Junos {
        return Some(s.split('|').map(str::to_string).collect());
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                cur.push(ch);
            }
            '|' if !in_quote => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    if in_quote {
        return None;
    }
    out.push(cur);
    Some(out)
}

fn check_pipe(vendor: Vendor, seg: &str) -> Result<(), (RejectionKind, String)> {
    let mut words = seg.split(' ').filter(|w| !w.is_empty());
    let Some(word) = words.next() else {
        return Err((
            RejectionKind::InvalidPipe {
                filter: String::new(),
            },
            "empty pipe segment".into(),
        ));
    };
    let args: Vec<&str> = words.collect();

    let filter = filters(vendor)
        .iter()
        .find(|f| word.len() >= f.min && f.name.starts_with(word));

    let Some(filter) = filter else {
        if let Some(d) = DENY_PIPES.iter().find(|d| d.starts_with(word)) {
            return Err((
                RejectionKind::Denied {
                    rule: format!("| {d}"),
                },
                format!("pipe `| {word}` is (an abbreviation of) the denied filter `| {d}`"),
            ));
        }
        return Err((
            RejectionKind::InvalidPipe {
                filter: word.to_string(),
            },
            format!("pipe `| {word}` is not an allowed {vendor} filter"),
        ));
    };

    let bad = |why: &str| {
        Err((
            RejectionKind::InvalidPipe {
                filter: filter.name.to_string(),
            },
            format!("`| {}`: {why}", filter.name),
        ))
    };
    let is_num = |s: &str| !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit());
    match filter.args {
        Args::None if !args.is_empty() => bad("takes no arguments"),
        Args::Required if args.is_empty() => bad("needs a pattern"),
        Args::OptNumber if args.len() > 1 || (args.len() == 1 && !is_num(args[0])) => {
            bad("takes an optional line count")
        }
        Args::Number if args.len() != 1 || !is_num(args[0]) => bad("takes one number"),
        Args::Display => {
            let ok = match args.as_slice() {
                [m] => ["set", "xml", "json", "inheritance"].contains(m),
                [m, n] => {
                    ["set", "xml", "json", "inheritance"].contains(m)
                        && ["relative", "no-comments", "brief", "terse"].contains(n)
                }
                _ => false,
            };
            if ok {
                Ok(())
            } else {
                bad("only `display set|xml|json|inheritance` is allowed")
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "allowlist_tests.rs"]
mod tests;

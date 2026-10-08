//! Settings resolution: command-line flag > environment > config file > default.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub model_url: Option<String>,
    pub model: Option<String>,
    /// Prefer the NETLENS_API_KEY environment variable over storing a key here.
    pub api_key: Option<String>,
    pub timeout_secs: Option<u64>,
    pub think: Option<bool>,
    pub mask_ips: Option<bool>,
    pub audit_path: Option<String>,
    pub audit_prompts: Option<bool>,
    pub batfish_url: Option<String>,
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Replace the built-in allowlist instead of extending it.
    #[serde(default)]
    pub replace_builtin: bool,
    /// vendor ("ios" | "junos" | "eos") -> anchored regexes `^...$`.
    #[serde(default)]
    pub allow: BTreeMap<String, Vec<String>>,
}

pub const EXAMPLE: &str = r#"# ~/.config/netlens/config.toml
# Precedence: command-line flag > environment variable > this file > built-in default.

# OpenAI-compatible endpoint (Ollama, LM Studio, llama.cpp server, vLLM, ...).
model_url = "http://localhost:11434/v1"   # env NETLENS_MODEL_URL
model = "qwen3:14b"                       # env NETLENS_MODEL
# api_key = "..."                         # prefer env NETLENS_API_KEY
timeout_secs = 300
think = false          # let Qwen3 "think" (slower); <think> blocks are always stripped
mask_ips = false       # replace IPs with IP4_n/IP6_n before anything reaches the model

# audit_path = "~/.local/state/netlens/audit.jsonl"   # env NETLENS_AUDIT
audit_prompts = false  # store full (already redacted) prompts in the audit log

# batfish_url = "http://localhost:9996"

[policy]
# Extra read-only commands for `troubleshoot` (phase 2). Must be anchored ^...$.
replace_builtin = false
[policy.allow]
# ios = ['^show platform hardware qfp active statistics drop$']
"#;

fn env_nonempty(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn home() -> Option<PathBuf> {
    env_nonempty("HOME").map(PathBuf::from)
}

pub fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(h) = home() {
            return h.join(rest);
        }
    }
    PathBuf::from(p)
}

/// Where the config file is looked for, and whether it was explicitly requested.
pub fn config_path(flag: Option<&Path>) -> Option<(PathBuf, bool)> {
    if let Some(p) = flag {
        return Some((p.to_path_buf(), true));
    }
    if let Some(p) = env_nonempty("NETLENS_CONFIG") {
        return Some((expand_tilde(&p), true));
    }
    if let Some(x) = env_nonempty("XDG_CONFIG_HOME") {
        return Some((PathBuf::from(x).join("netlens/config.toml"), false));
    }
    home().map(|h| (h.join(".config/netlens/config.toml"), false))
}

pub struct Loaded {
    pub path: Option<PathBuf>,
    pub found: bool,
    pub file: FileConfig,
}

pub fn load(flag: Option<&Path>) -> Result<Loaded> {
    let Some((path, explicit)) = config_path(flag) else {
        return Ok(Loaded {
            path: None,
            found: false,
            file: FileConfig::default(),
        });
    };
    if !path.exists() {
        if explicit {
            bail!("config file {} does not exist", path.display());
        }
        return Ok(Loaded {
            path: Some(path),
            found: false,
            file: FileConfig::default(),
        });
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    let file: FileConfig =
        toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))?;
    Ok(Loaded {
        path: Some(path),
        found: true,
        file,
    })
}

#[derive(Debug, Clone)]
pub struct Setting<T> {
    pub value: T,
    pub source: &'static str,
}

fn pick(flag: Option<String>, env: &str, file: Option<String>, default: &str) -> Setting<String> {
    if let Some(v) = flag {
        return Setting {
            value: v,
            source: "flag",
        };
    }
    if let Some(v) = env_nonempty(env) {
        return Setting {
            value: v,
            source: "env",
        };
    }
    if let Some(v) = file {
        return Setting {
            value: v,
            source: "config",
        };
    }
    Setting {
        value: default.to_string(),
        source: "default",
    }
}

#[derive(Debug, Clone)]
pub struct ModelSettings {
    pub url: Setting<String>,
    pub model: Setting<String>,
    pub api_key: Option<Setting<String>>,
    pub timeout_secs: u64,
    pub think: bool,
}

pub fn model_settings(
    file: &FileConfig,
    url: Option<String>,
    model: Option<String>,
    timeout: Option<u64>,
    think: bool,
) -> ModelSettings {
    let api_key = env_nonempty("NETLENS_API_KEY")
        .map(|v| Setting {
            value: v,
            source: "env",
        })
        .or_else(|| {
            file.api_key.clone().map(|v| Setting {
                value: v,
                source: "config",
            })
        });
    ModelSettings {
        url: pick(
            url,
            "NETLENS_MODEL_URL",
            file.model_url.clone(),
            netlens_llm::DEFAULT_MODEL_URL,
        ),
        model: pick(
            model,
            "NETLENS_MODEL",
            file.model.clone(),
            netlens_llm::DEFAULT_MODEL,
        ),
        api_key,
        timeout_secs: timeout.or(file.timeout_secs).unwrap_or(300),
        think: think || file.think.unwrap_or(false),
    }
}

impl ModelSettings {
    pub fn to_model_config(&self) -> netlens_llm::ModelConfig {
        netlens_llm::ModelConfig {
            url: self.url.value.clone(),
            model: self.model.value.clone(),
            api_key: self.api_key.as_ref().map(|s| s.value.clone()),
            timeout: std::time::Duration::from_secs(self.timeout_secs),
            no_think: !self.think,
            ..Default::default()
        }
    }
}

/// Audit log path: flag > NETLENS_AUDIT > config > default. `None` = disabled
/// or no usable default. The bool says whether the path was chosen explicitly.
pub fn audit_path(file: &FileConfig, flag: Option<PathBuf>) -> Option<(PathBuf, bool)> {
    if let Some(p) = flag {
        return Some((p, true));
    }
    if let Some(p) = env_nonempty("NETLENS_AUDIT") {
        return Some((expand_tilde(&p), true));
    }
    if let Some(p) = &file.audit_path {
        return Some((expand_tilde(p), true));
    }
    netlens_core::audit::default_path().map(|p| (p, false))
}

pub fn policy(file: &FileConfig) -> Result<netlens_core::policy::CommandPolicy> {
    netlens_core::policy::CommandPolicy::builtin()
        .with_overrides(&file.policy.allow, file.policy.replace_builtin)
        .map_err(|e| anyhow::anyhow!("config [policy]: {e}"))
}

/// The troubleshoot command gate (allowlist + policy) with config additions.
pub fn gate(file: &FileConfig) -> Result<netlens_core::gate::CommandGate> {
    netlens_core::gate::CommandGate::from_config(&file.policy.allow, file.policy.replace_builtin)
        .map_err(|e| anyhow::anyhow!("config [policy]: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let f: FileConfig = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(f.model.as_deref(), Some("qwen3:14b"));
        assert!(policy(&f).is_ok());
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(toml::from_str::<FileConfig>("modle = \"x\"").is_err());
    }

    #[test]
    fn flag_beats_file() {
        let f = FileConfig {
            model: Some("from-file".into()),
            ..Default::default()
        };
        let s = model_settings(&f, None, Some("from-flag".into()), None, false);
        assert_eq!(s.model.value, "from-flag");
        assert_eq!(s.model.source, "flag");
    }
}

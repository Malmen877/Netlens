//! The command gate for `netlens troubleshoot`: the stricter of two
//! independent checks always wins.
//!
//! 1. [`netlens_allowlist::vet`]: character/injection checks, the compiled-in
//!    denylist, the `show` gate, safe pipes and the anchored vendor allowlist.
//!    It also normalizes the command (`command`, sent to the device) and
//!    expands abbreviations (`canonical`, used for audit and matching).
//! 2. [`CommandPolicy::check`] on the canonical form: netlens' own denylist
//!    and allowlist (extendable in `config.toml`).
//!
//! A command passes only if both accept it. Passing the gate is still not
//! enough to run it: [`CommandGate::approve`] also needs a [`HumanApproval`].

use crate::policy::{ApprovedCommand, CommandPolicy, HumanApproval, Verdict};
use crate::vendor::Vendor;
use netlens_allowlist as al;
use serde::Serialize;
use std::collections::BTreeMap;

/// A command that passed both checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vetted {
    /// Trimmed, whitespace-collapsed, original case: what is sent.
    pub command: String,
    /// Lowercased, abbreviations expanded: for audit logs and matching.
    pub canonical: String,
}

/// Why the gate rejected a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateRejection {
    /// `allowlist` or `policy`.
    pub stage: &'static str,
    /// Allowlist rejection kind (`Injection`, `Denied`, `NotAllowed`, ...) or `Denied`.
    pub kind: String,
    pub reason: String,
}

impl std::fmt::Display for GateRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): {}", self.stage, self.kind, self.reason)
    }
}

impl std::error::Error for GateRejection {}

pub fn to_allowlist_vendor(v: Vendor) -> al::Vendor {
    match v {
        Vendor::CiscoIos => al::Vendor::Ios,
        Vendor::Junos => al::Vendor::Junos,
        Vendor::AristaEos => al::Vendor::Eos,
    }
}

/// Session setup sent by the transport itself, never proposed by a model and
/// never passed through the gate (`terminal` is denied there on purpose).
pub fn session_setup(v: Vendor) -> &'static [&'static str] {
    match v {
        Vendor::CiscoIos | Vendor::AristaEos => &["terminal length 0"],
        Vendor::Junos => &["set cli screen-length 0"],
    }
}

#[derive(Debug, Clone)]
pub struct CommandGate {
    allowlist: al::AllowlistConfig,
    policy: CommandPolicy,
}

impl Default for CommandGate {
    fn default() -> Self {
        CommandGate {
            allowlist: al::AllowlistConfig::default(),
            policy: CommandPolicy::builtin(),
        }
    }
}

impl CommandGate {
    pub fn new(allowlist: al::AllowlistConfig, policy: CommandPolicy) -> Self {
        CommandGate { allowlist, policy }
    }

    /// Build from the `[policy]` config section: extra patterns are added to
    /// both the allowlist and the policy (so they must satisfy both), and
    /// `replace_builtin` only ever narrows the policy side.
    pub fn from_config(
        extra: &BTreeMap<String, Vec<String>>,
        replace_builtin: bool,
    ) -> Result<Self, String> {
        let policy = CommandPolicy::builtin().with_overrides(extra, replace_builtin)?;
        let mut allowlist = al::AllowlistConfig::default();
        if !extra.is_empty() {
            let mut toml = String::new();
            for (k, pats) in extra {
                let v: Vendor = k.parse()?;
                toml.push_str(&format!("[{}]\nallow = [", to_allowlist_vendor(v)));
                for p in pats {
                    // The allowlist anchors patterns itself; strip ours.
                    let inner = p.trim_start_matches('^').trim_end_matches('$');
                    toml.push_str(&format!("'''{inner}''', "));
                }
                toml.push_str("]\n");
            }
            allowlist
                .extend_from_toml_str(&toml)
                .map_err(|e| format!("allowlist: {e}"))?;
        }
        Ok(CommandGate { allowlist, policy })
    }

    pub fn policy(&self) -> &CommandPolicy {
        &self.policy
    }

    pub fn allowlist(&self) -> &al::AllowlistConfig {
        &self.allowlist
    }

    pub fn vet(&self, vendor: Vendor, cmd: &str) -> Result<Vetted, GateRejection> {
        let v = al::vet(to_allowlist_vendor(vendor), cmd, &self.allowlist).map_err(|r| {
            GateRejection {
                stage: "allowlist",
                kind: kind_name(&r.kind),
                reason: r.reason.clone(),
            }
        })?;
        // The policy must accept the canonical form too; the original text is
        // checked as well when it is already in full form.
        for form in [v.canonical.as_str(), v.command.as_str()] {
            if form != v.canonical && !form.to_ascii_lowercase().starts_with("show ") {
                continue;
            }
            if let Verdict::Denied { reason } = self.policy.check(vendor, form) {
                return Err(GateRejection {
                    stage: "policy",
                    kind: "Denied".into(),
                    reason,
                });
            }
        }
        Ok(Vetted {
            command: v.command,
            canonical: v.canonical,
        })
    }

    /// Gate pass + human approval -> the only thing a transport accepts.
    /// The *normalized original* command is what gets sent.
    pub fn approve(
        &self,
        vendor: Vendor,
        vetted: &Vetted,
        human: HumanApproval,
    ) -> Result<ApprovedCommand, GateRejection> {
        // Re-vet so a hand-built `Vetted` can't bypass the gate.
        let again = self.vet(vendor, &vetted.command)?;
        self.policy
            .approve(vendor, &again.canonical, human)
            .map_err(|reason| GateRejection {
                stage: "policy",
                kind: "Denied".into(),
                reason,
            })?;
        Ok(ApprovedCommand::from_gate(again.command))
    }
}

fn kind_name(k: &al::RejectionKind) -> String {
    let dbg = format!("{k:?}");
    dbg.split([' ', '{', '('])
        .next()
        .unwrap_or("Rejected")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_layers_must_pass() {
        let g = CommandGate::default();
        let v = g.vet(Vendor::CiscoIos, "sh ip int br").unwrap();
        assert_eq!(v.command, "sh ip int br");
        assert_eq!(v.canonical, "show ip interface brief");
        for bad in [
            "conf t",
            "show run | redirect flash:x",
            "terminal length 0",
            "ping 192.0.2.1",
            "traceroute 192.0.2.1",
            "show ip bgp summary\nreload",
            "clear ip bgp *",
            "show ip bgp summary ; reload",
        ] {
            assert!(g.vet(Vendor::CiscoIos, bad).is_err(), "{bad}");
        }
        let r = g.vet(Vendor::Junos, "request system reboot").unwrap_err();
        assert_eq!(r.stage, "allowlist");
        assert_eq!(r.kind, "Denied");
    }

    #[test]
    fn policy_layer_can_be_stricter() {
        // Replace the policy allowlist with something narrow: the allowlist
        // would accept `show version`, the policy no longer does.
        let mut extra = BTreeMap::new();
        extra.insert("ios".to_string(), vec!["^show ip bgp summary$".to_string()]);
        let g = CommandGate::from_config(&extra, true).unwrap();
        assert!(g.vet(Vendor::CiscoIos, "show ip bgp summary").is_ok());
        let r = g.vet(Vendor::CiscoIos, "show version").unwrap_err();
        assert_eq!(r.stage, "policy");
    }

    #[test]
    fn config_patterns_cannot_widen_past_denylist() {
        let mut extra = BTreeMap::new();
        extra.insert("ios".to_string(), vec!["^.*$".to_string()]);
        let g = CommandGate::from_config(&extra, false).unwrap();
        assert!(g.vet(Vendor::CiscoIos, "reload").is_err());
        assert!(g.vet(Vendor::CiscoIos, "show run | redirect x").is_err());
    }

    #[test]
    fn approve_sends_original_form() {
        let g = CommandGate::default();
        let v = g.vet(Vendor::CiscoIos, "  sh   ip  bgp  summ ").unwrap();
        let a = g
            .approve(Vendor::CiscoIos, &v, HumanApproval::confirmed_by_human())
            .unwrap();
        assert_eq!(a.as_str(), "sh ip bgp summ");
        let forged = Vetted {
            command: "reload".into(),
            canonical: "show version".into(),
        };
        assert!(g
            .approve(
                Vendor::CiscoIos,
                &forged,
                HumanApproval::confirmed_by_human()
            )
            .is_err());
    }

    #[test]
    fn every_fixture_command_passes() {
        let root = netlens_allowlist::fixtures::fixtures_root();
        let g = CommandGate::default();
        let dirs = netlens_allowlist::fixtures::scenario_dirs(&root).unwrap();
        assert_eq!(dirs.len(), 5);
        for d in dirs {
            let s = netlens_allowlist::fixtures::Scenario::load(&d).unwrap();
            let v: Vendor = s.vendor.to_string().parse().unwrap();
            for c in &s.commands {
                g.vet(v, &c.command)
                    .unwrap_or_else(|e| panic!("{}: {}: {e}", d.display(), c.command));
            }
        }
    }
}

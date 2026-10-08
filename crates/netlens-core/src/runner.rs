//! Device runners for `netlens troubleshoot`: real devices over SSH, or the
//! offline mock device that replays recorded fixture outputs.

use crate::policy::ApprovedCommand;
use crate::ssh::SshTarget;
use crate::vendor::Vendor;
use netlens_allowlist::fixtures::Scenario;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RunOutput {
    pub text: String,
    pub status: Option<i32>,
    pub latency_ms: u128,
    /// Transport-level failure (could not connect, timed out, ...).
    pub error: Option<String>,
}

pub trait DeviceRunner {
    /// Run one approved command. Only an [`ApprovedCommand`] is accepted.
    fn run(&mut self, vendor: Vendor, cmd: &ApprovedCommand) -> RunOutput;
    /// Short description for the UI ("ssh r1.lab", "mock device ...").
    fn describe(&self) -> String;
    /// Transport details for the audit log (exact argv for SSH).
    fn transport(&self, vendor: Vendor, cmd: &ApprovedCommand) -> Value;
    /// True for the offline mock (the only runner where auto-approve is allowed).
    fn is_mock(&self) -> bool;
}

pub struct SshRunner {
    pub target: SshTarget,
    pub timeout: Duration,
}

impl DeviceRunner for SshRunner {
    fn run(&mut self, vendor: Vendor, cmd: &ApprovedCommand) -> RunOutput {
        match self.target.run_session(vendor, cmd, self.timeout) {
            Ok(o) => {
                let mut error = None;
                if o.timed_out {
                    error = Some(format!("timed out after {:?}", self.timeout));
                } else if o.status == Some(255) {
                    error = Some(format!("ssh failed: {}", o.stderr.trim()));
                }
                let mut text = o.stdout;
                if !o.stderr.trim().is_empty() && error.is_none() {
                    text.push_str("\n[stderr]\n");
                    text.push_str(&o.stderr);
                }
                RunOutput {
                    text,
                    status: o.status,
                    latency_ms: o.duration.as_millis(),
                    error,
                }
            }
            Err(e) => RunOutput {
                text: String::new(),
                status: None,
                latency_ms: 0,
                error: Some(format!("cannot start ssh: {e}")),
            },
        }
    }

    fn describe(&self) -> String {
        format!("ssh {}", self.target.host)
    }

    fn transport(&self, vendor: Vendor, cmd: &ApprovedCommand) -> Value {
        json!({
            "transport": "ssh-session",
            "argv": self.target.session_argv(),
            "stdin": SshTarget::session_script(vendor, cmd),
        })
    }

    fn is_mock(&self) -> bool {
        false
    }
}

/// Replays a recorded scenario (`examples/troubleshoot/<vendor>/<name>/`).
/// Unknown commands get a vendor-style "invalid input" error, like a device.
pub struct MockDevice {
    pub scenario: Scenario,
}

impl MockDevice {
    pub fn load(dir: &Path) -> Result<Self, String> {
        Scenario::load(dir)
            .map(|scenario| MockDevice { scenario })
            .map_err(|e| e.to_string())
    }

    pub fn vendor(&self) -> Vendor {
        match self.scenario.vendor {
            netlens_allowlist::Vendor::Ios => Vendor::CiscoIos,
            netlens_allowlist::Vendor::Junos => Vendor::Junos,
            netlens_allowlist::Vendor::Eos => Vendor::AristaEos,
        }
    }
}

impl DeviceRunner for MockDevice {
    fn run(&mut self, vendor: Vendor, cmd: &ApprovedCommand) -> RunOutput {
        let start = Instant::now();
        let text = match self.scenario.output(cmd.as_str()) {
            Some(Ok(t)) => t,
            Some(Err(e)) => {
                return RunOutput {
                    text: String::new(),
                    status: None,
                    latency_ms: 0,
                    error: Some(e.to_string()),
                }
            }
            None => match vendor {
                Vendor::Junos => {
                    "                    ^\nsyntax error, expecting <command>.\n".into()
                }
                _ => "                    ^\n% Invalid input detected at '^' marker.\n".into(),
            },
        };
        RunOutput {
            text,
            status: Some(0),
            latency_ms: start.elapsed().as_millis(),
            error: None,
        }
    }

    fn describe(&self) -> String {
        format!(
            "mock device {} ({})",
            self.scenario.hostname,
            self.scenario.dir.display()
        )
    }

    fn transport(&self, _vendor: Vendor, _cmd: &ApprovedCommand) -> Value {
        json!({ "transport": "mock-device", "scenario": self.scenario.dir.display().to_string() })
    }

    fn is_mock(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::CommandGate;
    use crate::policy::HumanApproval;

    #[test]
    fn mock_device_replays_fixtures() {
        let dir = netlens_allowlist::fixtures::fixtures_root().join("ios/bgp-flap-mtu");
        let mut m = MockDevice::load(&dir).unwrap();
        assert_eq!(m.vendor(), Vendor::CiscoIos);
        assert!(m.is_mock());
        let g = CommandGate::default();
        let approve = |c: &str| {
            let v = g.vet(Vendor::CiscoIos, c).unwrap();
            g.approve(Vendor::CiscoIos, &v, HumanApproval::auto_for_mock_device())
                .unwrap()
        };
        let out = m.run(Vendor::CiscoIos, &approve("show  ip bgp summary"));
        assert!(out.text.contains("198.51.100.2"));
        let out = m.run(Vendor::CiscoIos, &approve("show version"));
        assert!(out.text.contains("Invalid input"));
    }
}

//! SSH transport design (used by `netlens troubleshoot` in phase 2).
//!
//! Decision: spawn the system `ssh` client with `BatchMode=yes` instead of
//! embedding an SSH library. That reuses the engineer's `~/.ssh/config`,
//! agent, jump hosts, Kerberos and known_hosts, needs no crypto dependency,
//! and fails closed: no password prompts and no silent host-key acceptance.
//! Only an [`ApprovedCommand`] (policy pass + human "y") can be executed.

use crate::policy::ApprovedCommand;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
    pub connect_timeout_secs: u32,
    pub ssh_binary: String,
}

#[derive(Debug, Clone)]
pub struct SshOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub timed_out: bool,
}

impl SshTarget {
    pub fn new(host: &str) -> Result<Self, String> {
        if host.is_empty()
            || host.starts_with('-')
            || host.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!("invalid host '{host}'"));
        }
        Ok(SshTarget {
            host: host.to_string(),
            user: None,
            port: None,
            identity: None,
            connect_timeout_secs: 10,
            ssh_binary: "ssh".into(),
        })
    }

    /// The exact argv used (also written to the audit log).
    pub fn argv(&self, cmd: &ApprovedCommand) -> Vec<String> {
        let mut a = vec![
            self.ssh_binary.clone(),
            "-T".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            format!("ConnectTimeout={}", self.connect_timeout_secs),
            "-o".into(),
            "LogLevel=ERROR".into(),
            "-o".into(),
            "ServerAliveInterval=15".into(),
        ];
        if let Some(u) = &self.user {
            a.push("-l".into());
            a.push(u.clone());
        }
        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        if let Some(i) = &self.identity {
            a.push("-i".into());
            a.push(i.display().to_string());
        }
        a.push("--".into());
        a.push(self.host.clone());
        a.push(cmd.as_str().to_string());
        a
    }

    /// Run one approved read-only command with an overall timeout.
    pub fn run(&self, cmd: &ApprovedCommand, timeout: Duration) -> std::io::Result<SshOutput> {
        let argv = self.argv(cmd);
        let start = Instant::now();
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut timed_out = false;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s.code();
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                timed_out = true;
                break child.wait()?.code();
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut o) = child.stdout.take() {
            o.read_to_string(&mut stdout)?;
        }
        if let Some(mut e) = child.stderr.take() {
            e.read_to_string(&mut stderr)?;
        }
        Ok(SshOutput {
            status,
            stdout,
            stderr,
            duration: start.elapsed(),
            timed_out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{CommandPolicy, HumanApproval};
    use crate::vendor::Vendor;

    #[test]
    fn argv_is_batch_mode_and_ends_with_host_and_command() {
        let mut t = SshTarget::new("r1.lab").unwrap();
        t.user = Some("netops".into());
        t.port = Some(2222);
        let cmd = CommandPolicy::builtin()
            .approve(
                Vendor::CiscoIos,
                "show ip bgp summary",
                HumanApproval::confirmed_by_human(),
            )
            .unwrap();
        let a = t.argv(&cmd);
        assert!(a.contains(&"BatchMode=yes".to_string()));
        assert!(!a.iter().any(|x| x.contains("StrictHostKeyChecking=no")));
        let n = a.len();
        assert_eq!(a[n - 3], "--");
        assert_eq!(a[n - 2], "r1.lab");
        assert_eq!(a[n - 1], "show ip bgp summary");
    }

    #[test]
    fn rejects_option_like_hosts() {
        assert!(SshTarget::new("-oProxyCommand=evil").is_err());
        assert!(SshTarget::new("a b").is_err());
        assert!(SshTarget::new("").is_err());
    }
}

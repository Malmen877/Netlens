//! Vendor identification and autodetection.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Vendor {
    CiscoIos,
    Junos,
    AristaEos,
}

impl Vendor {
    pub const ALL: [Vendor; 3] = [Vendor::CiscoIos, Vendor::Junos, Vendor::AristaEos];

    pub fn as_str(&self) -> &'static str {
        match self {
            Vendor::CiscoIos => "cisco-ios",
            Vendor::Junos => "junos",
            Vendor::AristaEos => "arista-eos",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Vendor::CiscoIos => "Cisco IOS/IOS-XE",
            Vendor::Junos => "Juniper Junos",
            Vendor::AristaEos => "Arista EOS",
        }
    }

    /// Short key used in config files (`[policy.allow] ios = [...]`).
    pub fn key(&self) -> &'static str {
        match self {
            Vendor::CiscoIos => "ios",
            Vendor::Junos => "junos",
            Vendor::AristaEos => "eos",
        }
    }

    /// IOS and EOS share the indentation-based "industry standard" CLI.
    pub fn is_ios_like(&self) -> bool {
        matches!(self, Vendor::CiscoIos | Vendor::AristaEos)
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Vendor {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ios" | "iosxe" | "ios-xe" | "cisco" | "cisco-ios" | "cisco-iosxe" | "cisco-ios-xe" => {
                Ok(Vendor::CiscoIos)
            }
            "junos" | "juniper" | "juniper-junos" => Ok(Vendor::Junos),
            "eos" | "arista" | "arista-eos" => Ok(Vendor::AristaEos),
            other => Err(format!(
                "unknown vendor '{other}' (expected one of: ios, junos, eos)"
            )),
        }
    }
}

/// Result of vendor autodetection.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub vendor: Vendor,
    /// True when strong markers were found; false means "best guess".
    pub confident: bool,
    pub reason: String,
}

const EOS_MARKERS: &[&str] = &[
    "! device:",
    "! boot system flash:",
    "transceiver qsfp default-mode",
    "service routing protocols model",
    "management api http-commands",
    "management api gnmi",
    "daemon terminattr",
    "role network-admin",
    "interface ethernet",
    "interface management1",
    "peer group ",
    "ip routing vrf",
    "spanning-tree mode mstp",
    "management ssh",
    "mlag configuration",
];

const IOS_MARKERS: &[&str] = &[
    "boot-start-marker",
    "boot-end-marker",
    "service timestamps",
    "interface gigabitethernet",
    "interface tengigabitethernet",
    "interface fastethernet",
    "interface twentyfivegige",
    "interface hundredgige",
    "interface port-channel",
    "license udi",
    "ip cef",
    "line vty",
    "line con 0",
    "crypto pki",
    "ip forward-protocol nd",
    "exit-address-family",
    "platform ",
    "version 1",
    "control-plane",
];

/// Guess the vendor of a configuration (or a config fragment).
pub fn detect(text: &str) -> Detection {
    let mut nonblank = 0usize;
    let mut set_lines = 0usize;
    let mut brace_lines = 0usize;
    let mut eos = 0usize;
    let mut ios = 0usize;
    let mut eos_hits: Vec<&str> = Vec::new();
    let mut ios_hits: Vec<&str> = Vec::new();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        nonblank += 1;
        if l.starts_with("set ") || l.starts_with("deactivate ") {
            set_lines += 1;
        }
        if l.ends_with('{') || l == "}" || (l.ends_with(';') && !l.starts_with('!')) {
            brace_lines += 1;
        }
        let low = l.to_ascii_lowercase();
        // Lines from a unified diff may carry a +/- prefix.
        let low = low.trim_start_matches(['+', '-', ' ']);
        for m in EOS_MARKERS {
            if low.starts_with(m) || (m.starts_with("! ") && low.starts_with(m)) {
                eos += 1;
                if !eos_hits.contains(m) {
                    eos_hits.push(m);
                }
            }
        }
        if low.contains("neighbor") && low.contains(" peer group ") {
            eos += 1;
        }
        for m in IOS_MARKERS {
            if low.starts_with(m) {
                ios += 1;
                if !ios_hits.contains(m) {
                    ios_hits.push(m);
                }
            }
        }
    }
    if nonblank > 0 && set_lines * 2 > nonblank {
        return Detection {
            vendor: Vendor::Junos,
            confident: true,
            reason: format!("{set_lines}/{nonblank} lines are Junos 'set' statements"),
        };
    }
    if nonblank > 0 && brace_lines * 3 > nonblank {
        return Detection {
            vendor: Vendor::Junos,
            confident: brace_lines * 2 > nonblank,
            reason: format!("{brace_lines}/{nonblank} lines use Junos brace syntax"),
        };
    }
    if eos > ios {
        return Detection {
            vendor: Vendor::AristaEos,
            confident: eos >= 2,
            reason: format!("EOS markers: {}", eos_hits.join(", ")),
        };
    }
    if ios > 0 {
        return Detection {
            vendor: Vendor::CiscoIos,
            confident: ios >= 2,
            reason: format!("IOS markers: {}", ios_hits.join(", ")),
        };
    }
    Detection {
        vendor: Vendor::CiscoIos,
        confident: false,
        reason: "no strong vendor markers; assuming cisco-ios (override with --vendor)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aliases() {
        assert_eq!("IOS-XE".parse::<Vendor>().unwrap(), Vendor::CiscoIos);
        assert_eq!("juniper".parse::<Vendor>().unwrap(), Vendor::Junos);
        assert_eq!("arista".parse::<Vendor>().unwrap(), Vendor::AristaEos);
        assert!("nxos".parse::<Vendor>().is_err());
    }

    #[test]
    fn detects_junos_set() {
        let d = detect("set system host-name r1\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30\n");
        assert_eq!(d.vendor, Vendor::Junos);
        assert!(d.confident);
    }

    #[test]
    fn detects_junos_curly() {
        let d = detect("system {\n    host-name r1;\n}\ninterfaces {\n    ge-0/0/0 {\n        disable;\n    }\n}\n");
        assert_eq!(d.vendor, Vendor::Junos);
    }

    #[test]
    fn detects_eos() {
        let d = detect("! device: leaf1 (DCS-7050SX3, EOS-4.30)\n!\ntransceiver qsfp default-mode 4x10G\nservice routing protocols model multi-agent\ninterface Ethernet1\n   no switchport\n");
        assert_eq!(d.vendor, Vendor::AristaEos);
        assert!(d.confident);
    }

    #[test]
    fn detects_ios() {
        let d = detect("version 17.9\nservice timestamps debug datetime msec\nboot-start-marker\nboot-end-marker\ninterface GigabitEthernet1\n ip address 10.0.0.1 255.255.255.0\n");
        assert_eq!(d.vendor, Vendor::CiscoIos);
        assert!(d.confident);
    }

    #[test]
    fn unknown_defaults_to_ios_unconfident() {
        let d = detect("hostname x\n");
        assert_eq!(d.vendor, Vendor::CiscoIos);
        assert!(!d.confident);
    }
}

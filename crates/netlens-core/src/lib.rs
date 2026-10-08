//! netlens-core: everything deterministic.
//!
//! Parsing (IOS/IOS-XE, Junos curly + set, Arista EOS), semantic diff, the
//! lint/risk rule engine, deterministic rollback generation, redaction and IP
//! masking, the JSONL audit log, and the read-only command policy used by the
//! troubleshooting agent. Nothing in this crate talks to the network or a model.

pub mod analysis;
pub mod audit;
pub mod diff;
pub mod facts;
pub mod finding;
pub mod gate;
pub mod ipmask;
pub mod model;
pub mod parse;
pub mod policy;
pub mod redact;
pub mod rollback;
pub mod rules;
pub mod runner;
pub mod section;
pub mod ssh;
pub mod syslog;
pub mod unidiff;
pub mod vendor;

pub use analysis::{analyze, analyze_single, Analysis, Input};
pub use finding::{Evidence, Finding, Severity, Side};
pub use model::Config;
pub use vendor::Vendor;

/// Hex-encoded SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

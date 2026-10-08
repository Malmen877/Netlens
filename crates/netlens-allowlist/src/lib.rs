//! netlens-allowlist: read-only command allowlist and troubleshooting
//! fixtures for netlens.
//!
//! See `README.md` for the design and threat model.

pub mod allowlist;
pub mod fixtures;

pub use allowlist::{
    check, vet, AllowlistConfig, ConfigError, Rejection, RejectionKind, UnknownVendor, Vendor,
    Vetted, MAX_COMMAND_LEN,
};

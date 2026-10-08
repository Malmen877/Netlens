//! Try the allowlist from the shell:
//!   cargo run --example check -- ios "sh ip int br | i up"
//!   cargo run --example check -- junos "request system reboot"
use netlens_allowlist::{vet, AllowlistConfig, Vendor};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(vendor), Some(cmd)) = (args.next(), args.next()) else {
        eprintln!("usage: check <ios|junos|eos> <command>");
        std::process::exit(2);
    };
    let vendor: Vendor = vendor.parse().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    match vet(vendor, &cmd, &AllowlistConfig::default()) {
        Ok(v) => println!("ALLOW  send={:?}  canonical={:?}", v.command, v.canonical),
        Err(e) => {
            println!("REJECT {:?}: {}", e.kind, e.reason);
            std::process::exit(1);
        }
    }
}

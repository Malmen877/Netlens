# Contributing

Thanks for helping. netlens is small on purpose, so please open an issue before a
large change.

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs exactly these on Linux and macOS.

Ground rules:

- **Read-only stays read-only.** No PR may add a configure, commit or write path, or a
  way around the command gate, redaction or human approval.
- **Deterministic first.** New checks go into the rule engine with tests; the model only
  explains evidence and must cite it.
- **Fixtures use documentation data**: IPv4 from 192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24 (or RFC 1918), IPv6 from 2001:db8::/32, private ASNs (64512-65534), and
  no real secrets, hostnames or serial numbers.
- New rules need a test with a before/after pair and an entry in `docs/rules.md`.

By contributing you agree that your work is dual-licensed under MIT OR Apache-2.0,
like the rest of the project.

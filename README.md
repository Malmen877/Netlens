# netlens

A local, read-only AI copilot for network engineers. It reviews config changes before
you push them and explains them in plain language, and **every claim cites tool
output** (a rule finding, a Batfish answer, a diff line or a command output). Claims
without a valid citation are dropped. Runs against any local OpenAI-compatible model.

- **`review`**: before/after configs or a diff (Cisco IOS/IOS-XE, Junos, Arista EOS) →
  semantic diff, 37 deterministic rules, optional Batfish, AI risk summary, blast
  radius and a deterministic rollback snippet. Works without a model (`--no-llm`).
- **`troubleshoot`** *(preview)*: the model proposes `show` commands, you approve each
  one, netlens runs it over SSH and explains the root cause with quoted evidence.
- **`mcp`** *(preview)*: the read-only tools as an MCP server.

## Install

```sh
cargo install --git https://github.com/Malmen877/netlens netlens
```

## Quickstart (Ollama)

```sh
ollama pull qwen3:14b          # default model: Qwen3-14B 4-bit, fits a 24 GB Mac
netlens review examples/ios-xe/before.cfg examples/ios-xe/after.cfg
```

Demo against the built-in mock model (`--model-url mock://`), trimmed:

```text
$ netlens review examples/ios-xe/before.cfg examples/ios-xe/after.cfg --model-url mock://
netlens review  Cisco IOS/IOS-XE (autodetected)  examples/ios-xe/before.cfg -> examples/ios-xe/after.cfg

Findings (9): 5 high, 3 medium, 1 low
 F1    HIGH     NL-IF-006     VLAN(s) 30 removed from trunk GigabitEthernet3
 F2    HIGH     NL-BGP-002    BGP neighbor 198.51.100.1 shut down
 F3    HIGH     NL-BGP-003    BGP neighbor 198.51.100.1 routing policy changed
 F4    HIGH     NL-REF-001    route-map RM-ISP-A-OUT-V2 referenced but not defined
 F5    HIGH     NL-ACL-001    ACL ACL-EDGE-IN: entry removed
 F6    MEDIUM   NL-IF-004     Interface GigabitEthernet2 mtu changed 1500 -> 9000
 F7    MEDIUM   NL-MGMT-002   Management plane changed: SNMP
 F8    MEDIUM   NL-SEC-002    Well-known SNMP community configured
 F9    LOW      NL-REF-002    route-map RM-ISP-A-OUT is no longer referenced

AI review mock (qwen3:14b) via mock:// (0.0s; 10 cited claims; 4 redactions; every claim must cite evidence)
 Summary
   * Overall risk is HIGH: 9 findings, the most severe being "VLAN(s) 30 removed from trunk
     GigabitEthernet3". [F1]
   * BGP neighbor 198.51.100.1 shut down (high). [F2]
 Blast radius
   * Hosts and adjacencies behind this interface are affected by "VLAN(s) 30 removed from trunk
     GigabitEthernet3". [F1]
 Rollback
   * Apply the generated rollback snippet to restore the previous configuration. [R1]
   * Because of the high-severity items, apply the change with a timed rollback (commit confirmed /
     reload in) and keep console access. [F1]
 2 model claim(s) dropped: no valid citation (show with --keep-uncited)
 ignored citations to unknown evidence: F99

Rollback (deterministic; review before applying) [R1]
  interface GigabitEthernet2
   mtu 1500
  interface GigabitEthernet3
   switchport trunk allowed vlan 10,20,30
  router bgp 65010
   no neighbor 198.51.100.1 shutdown
   address-family ipv4
    neighbor 198.51.100.1 route-map RM-ISP-A-OUT out
  ...
```

## Safety

- No configure, commit or write tools at all. Rollbacks are printed for a human.
- Secrets (passwords, keys, hashes, SNMP communities) are redacted before anything
  reaches the model; `netlens redact FILE` shows exactly what it sees.
- Optional IP masking (`--mask-ips`).
- JSONL audit log of every model call and device command.

## Docs

[usage](docs/usage.md) · [rules](docs/rules.md) · [models](docs/models.md) ·
[batfish](docs/batfish.md) · [safety & redaction](docs/safety.md) ·
[audit](docs/audit.md) · [troubleshoot](docs/troubleshoot.md) · [mcp](docs/mcp.md) ·
[config](docs/config.md) · [architecture](docs/architecture.md)

Status: v0.1, `review` is solid; `troubleshoot` and `mcp` are in progress.
License: MIT OR Apache-2.0.

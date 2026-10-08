# netlens

A local, read-only AI copilot for network engineers. It reviews config changes before
you push them and explains them in plain language, and **every claim cites tool
output** (a rule finding, a Batfish answer, a diff line or a command output). Claims
without a valid citation are dropped. Runs against any local OpenAI-compatible model.

- **`review`**: before/after configs or a diff (Cisco IOS/IOS-XE, Junos, Arista EOS) →
  semantic diff, 37 deterministic rules, optional Batfish, AI risk summary, blast
  radius and a deterministic rollback snippet. Works without a model (`--no-llm`).
- **`troubleshoot`**: the model proposes `show` commands; each passes a read-only gate
  and needs your `y` before netlens runs it over SSH. The root cause comes with quotes
  from the outputs and your syslog, and netlens checks every quote.
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
 ...

AI review mock (qwen3:14b) via mock:// (0.0s; 10 cited claims; 4 redactions; every claim must cite evidence)
 Summary
   * Overall risk is HIGH: 9 findings, the most severe being "VLAN(s) 30 removed from trunk
     GigabitEthernet3". [F1]
   * BGP neighbor 198.51.100.1 shut down (high). [F2]
 Rollback
   * Apply the generated rollback snippet to restore the previous configuration. [R1]
 2 model claim(s) dropped: no valid citation (show with --keep-uncited)
 ignored citations to unknown evidence: F99

Rollback (deterministic; review before applying) [R1]
  interface GigabitEthernet2
   mtu 1500
  ...
```

Troubleshooting a recorded scenario offline (scripted mock model, mock device), trimmed:

```text
$ netlens troubleshoot --mock-device examples/troubleshoot/ios/bgp-flap-mtu --model-url mock:// --auto-approve
step 1/8 show ip bgp summary
  O1 ok 16 lines (0 ms)
step 2/8 clear ip bgp 198.51.100.2 soft
  BLOCKED allowlist (Denied): `clear` is on the denylist
...
Diagnosis  6 command(s) run, 1 blocked by the gate, 44 syslog line(s) shown
 Root cause (high confidence)
   Interface MTU mismatch on Gi0/0/1: local 1500 vs far end 9216 (jumbo per CHG-20914). Large
   BGP UPDATEs from the peer are dropped as giants, so keepalives stall and the hold timer
   expires. Fix: set mtu 9216 on Gi0/0/1 (or lower the peer MTU / clamp BGP MSS).
 Evidence (quoted, validated)
   [O4] show interfaces GigabitEthernet0/0/1
       "0 runts, 112 giants, 0 throttles"
   [O5] show interfaces description
       "Gi0/0/1                        up             up       P2P got-core-rtr02 Te0/1/0 | CKT SE-NET-44817 |..."
 ! 1 evidence item(s) dropped:
   [O3] "BGP neighbor reset by operator"  quote not found verbatim in O3
```

On a real device: `netlens troubleshoot --host edge-r1 --vendor ios --syslog edge-r1.log "BGP to 198.51.100.2 flapping"`.

## Safety

- No configure, commit or write tools at all. Rollbacks are printed for a human.
- Device commands: `show` only, a two-layer allowlist/denylist gate (the stricter rule
  wins), and your `y/N` for every command.
- Secrets (passwords, keys, hashes, SNMP communities) are redacted before anything
  reaches the model; `netlens redact FILE` shows exactly what it sees.
- Optional IP masking (`--mask-ips`).
- JSONL audit log of every model call and device command.

## Docs

[usage](docs/usage.md) · [rules](docs/rules.md) · [models](docs/models.md) ·
[batfish](docs/batfish.md) · [safety & redaction](docs/safety.md) ·
[audit](docs/audit.md) · [troubleshoot](docs/troubleshoot.md) · [mcp](docs/mcp.md) ·
[config](docs/config.md) · [architecture](docs/architecture.md)

Status: v0.1. `review` and `troubleshoot` work (troubleshoot is tested against
recorded scenarios, not yet against real hardware); `mcp` is in progress.
License: MIT OR Apache-2.0.

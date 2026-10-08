# `netlens troubleshoot`: design (phase 2)

Phase 1 already ships and tests the building blocks:
`netlens_core::{policy, ssh, syslog, audit}`. The CLI command itself prints "coming in
phase 2".

## Flow

```
symptom ("BGP to ISP-A flapping")
  -> model proposes read-only commands (JSON list, cited to symptom/log lines)
  -> policy check: denylist, then anchored allowlist      (netlens_core::policy)
  -> human approval: [y/N] per command, default No
  -> ssh exec (system OpenSSH, BatchMode)                 (netlens_core::ssh)
  -> redact output, then mask IPs, then model             (redact / ipmask)
  -> syslog correlation (--syslog FILE)                   (netlens_core::syslog)
  -> cited diagnosis + next commands, loop (max N rounds)
every step -> audit.jsonl
```

## Command policy

- **Hard denylist (always wins).** It rejects:
  - commands whose first word is configure, write, copy, delete, erase, reload,
    request, clear, debug, set, edit, load, commit, rollback, run, bash, python,
    tclsh, guestshell, ping, traceroute, telnet, ssh, terminal, monitor, test,
    activate, deactivate, ... (see `netlens policy list`). Active probes such as ping
    and traceroute are excluded from v1 on purpose;
  - commands containing these words anywhere: `redirect`, `tee`, `append`, `save`, ...;
  - shell metacharacters `; && || $( \` > < \\`, control characters, and commands
    longer than 256 characters.
- **Pipes** are allowed only into display filters (`include`, `exclude`, `begin`,
  `section`, `count`, `match`, `except`, `last`, `no-more`, `display set|json|xml`, ...).
- **Allowlist:** per-vendor anchored regexes (`^show ...$`). You can extend or
  replace it in `config.toml` under `[policy.allow]`. Every pattern must be anchored
  `^...$`; otherwise the config is rejected.
- `netlens policy check -- "show ip bgp summary"` and `netlens policy list` work
  today.

## SSH approach: system OpenSSH, not a Rust SSH library

netlens spawns the system `ssh` binary with a fixed argv:

```
ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR \
    -o ServerAliveInterval=15 [-l user] [-p port] [-i key] -- HOST "<approved command>"
```

Why:

- It reuses the engineer's existing `~/.ssh/config`: jump hosts/ProxyJump, bastions,
  ControlMaster, certificates, hardware keys, ssh-agent and known_hosts. A Rust SSH
  stack would have to reimplement all of that, and get it right.
- `BatchMode=yes` means netlens never prompts for or handles passwords. netlens never
  sees credentials.
- Host keys are verified by OpenSSH. netlens never passes `StrictHostKeyChecking=no`,
  and a unit test asserts that.
- `--` before the host plus host validation (no leading `-`, no whitespace) blocks
  option injection (`-oProxyCommand=...`).
- stdin is `/dev/null`. stdout and stderr are drained concurrently, and an overall
  timeout kills the process.

Trade-offs: some platforms (older IOS) want an interactive shell rather than exec
channels, and paging must be disabled. Exec channels on IOS/EOS normally don't page;
Junos commands get `| no-more`. `terminal length 0` is denied as a *proposed*
command, so the transport has to send it itself when it opens a session. Phase 2 will add an optional
persistent session mode (`-tt` with prompt detection) behind the same
`ApprovedCommand` gate, plus Netmiko-style per-vendor prompt handling if needed.

## Syslog correlation

`netlens_core::syslog::correlate(text, terms, max)` finds log lines that mention the
relevant peers, interfaces or keywords (case-insensitive, newest kept). It also
extracts IOS/EOS-style `%FACILITY-SEVERITY-MNEMONIC` tags (`%BGP-5-ADJCHANGE`,
`%OSPF-5-ADJCHG`, ...) and the severity. Junos messages (`BGP_IO_ERROR`,
`SNMP_TRAP_LINK_DOWN`) are matched by term. Try it with
`examples/syslog/edge-r1-bgp-flap.log`. The hits are redacted, then given ids `L1..` so the model can cite them like
any other evidence.

## MCP (`netlens mcp`, phase 2)

`review`, `lint`, `redact` and `policy check` will be exposed as MCP tools over stdio
(rmcp). Device access through MCP stays behind the same human-approval gate. An MCP
client cannot produce a `HumanApproval`.

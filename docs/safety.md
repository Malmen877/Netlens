# Safety model

netlens v1 is **read-only**. It has no configure/commit/write capability at all:
`review` and `lint` only read local files, and the rollback is printed for a human
to apply.

## What reaches the model

Every string sent to the model (findings, evidence lines, raw changes, rollback,
notes) is built in one place (`netlens_llm::prompt::build_context`). That function
**redacts first** and **masks second**. No code path can skip it.

### Redaction

The regex rules (`crates/netlens-core/src/redact.rs`) replace each secret with a
stable placeholder, `<redacted:KIND#N>`. The same value always gets the same
placeholder, so the model can still tell that "the old and new community differ"
without seeing either one. Covered:

- IOS/EOS: `enable secret/password`, `username ... secret/password`, type 7/8/9 hashes,
  `snmp-server community`, SNMPv3 `auth/priv` keys, `tacacs/radius key`,
  `neighbor ... password`, `key-string`, OSPF/ISIS/HSRP/VRRP auth keys, NTP keys,
  `crypto isakmp key`, `pre-shared-key`, PKI certificate hex blocks
- Junos: `encrypted-password`, `secret`, `authentication-key`, `pre-shared-key`,
  SNMP communities (both `set` and curly form, via block context)
- PEM blocks (`-----BEGIN ...-----`)

Key-chain ids (`key 1`) are not treated as secrets.

The human-facing report is redacted too. `--reveal-secrets` shows the real values in
the report and rollback so the rollback can be pasted. The model never sees them,
with or without that flag.

`netlens redact FILE` prints exactly what the redactor does to a file.

### IP masking (`--mask-ips`)

IPv4/IPv6 addresses become `IP4_n` / `IP6_n`, consistently within a run (prefix
lengths are kept). Netmasks, wildcard masks, `0.0.0.0` and `255.255.255.255` are not
touched. Claims are unmasked before they are shown. The audit log stores the masked
prompt (hash, or full text with `--audit-prompts`).

## Audit log

Every model call and (in troubleshoot) every proposed, approved, rejected and executed
command is written to a JSONL audit log. See [audit.md](audit.md).

## Troubleshooting commands

See [troubleshoot.md](troubleshoot.md). In short, a command runs only if:

1. it passes netlens-allowlist: printable ASCII only, no injection characters, a
   compiled-in denylist (configure, write, copy, reload, clear, debug, request,
   terminal, ping, traceroute, `| redirect`, `| save`, ...), `show` only, and an
   anchored vendor allowlist;
2. it passes netlens' own policy (a second denylist and allowlist). The stricter rule wins;
3. a human typed `y` for that exact command (auto-approval exists only for the
   offline mock device).

The type system enforces this: the SSH transport only accepts an `ApprovedCommand`,
which only the gate can build, after re-checking the command and receiving a
`HumanApproval`. Command output is redacted (and optionally IP-masked) before the
model sees it, and the model's evidence quotes are checked against that text.

Prompt injection: device output and logs are untrusted. The model is told to ignore
instructions in them, but the real protection is structural. Whatever the model
proposes still has to pass the gate and your `y`.

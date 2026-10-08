# Troubleshooting (`netlens troubleshoot`)

The model proposes read-only `show` commands one at a time. netlens checks each one,
**you approve it**, netlens runs it over SSH, and the model explains the root cause
with quotes from the outputs and your syslog. netlens validates every quote.

```sh
netlens troubleshoot --host edge-r1 --vendor ios --user netops \
  --syslog /var/log/net/edge-r1.log \
  "BGP to 198.51.100.2 goes up, gets 0 prefixes, drops with hold time expired"
```

An interactive session looks like this (abridged):

```
step 1/8 show ip bgp summary  Check the session state and prefix counts.
  [1/8] run `show ip bgp summary`? [y/N/q] y
  O1 ok 16 lines (412 ms)
step 2/8 clear ip bgp 198.51.100.2 soft  Soft-reset the session.
  BLOCKED allowlist (Denied): `clear` is on the denylist
...
```

`y` runs the command, Enter or `n` declines it (the model is told and can try
something else), `q` stops. Real devices always need an interactive terminal.

## Flow

```
symptom + syslog (filtered) ──> model proposes {"action":"run","command":...}
   -> gate: allowlist, then policy (stricter wins)   blocked? model is told why, loop continues
   -> your y/N                                        (auto-approve: --mock-device only)
   -> SSH session: paging off, command, exit
   -> output redacted (+ --mask-ips) -> model as O<step>; new syslog lines as L<line>
   ... at most --max-steps (default 8) proposals, blocked ones included
model answers {"action":"final","root_cause":..,"evidence":[{"cite":"O4","quote":..}],"next_checks":[..]}
   -> every quote must appear verbatim in that output / syslog line, or it is dropped
   -> next_checks go through the gate; unsafe ones are dropped
every step -> audit log
```

The final report shows the root cause, the validated quotes with their source
command or syslog line, dropped quotes and why, and the next read-only checks. With
no valid evidence left, the answer is marked **UNVERIFIED**. `--json` prints the whole
report, including every step.

## The command gate

A proposed command must pass two independent layers. The stricter one wins.

1. **netlens-allowlist** (`crates/netlens-allowlist`, see its README for the threat
   model). Only printable ASCII; no control characters (a newline would be a second
   command), tabs or `?`; no shell metacharacters; a compiled-in denylist of verbs,
   tokens and pipe filters (`configure`, `write`, `copy`, `reload`, `clear`, `debug`,
   `request`, `terminal`, `ping`, `traceroute`, `| redirect`, `| save`, ...) that no
   config can change; the first word must be `show`; only display filters after a
   pipe; then an anchored per-vendor allowlist matched on the canonical form
   (abbreviations expanded: `sh ip int br` → `show ip interface brief`).
2. **netlens policy** (`netlens_core::policy`): its own denylist and anchored allowlist,
   checked against the canonical form.

What's sent is the normalized original (`sh ip int br`), and the canonical form goes
to the audit log. `netlens policy check --vendor ios -- "sh ip int br"` shows both.
ping and traceroute are denied on purpose, since they generate traffic.

Extra patterns from `config.toml` (`[policy.allow]`) are added to **both** layers, so
they can widen what `show` commands are allowed but never get past a denylist.
`replace_builtin = true` only narrows the policy layer.

## SSH

netlens runs the system `ssh` with a fixed argv and pipes a three-line script to it:

```
ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o ServerAliveInterval=15 \
    [-l user] [-p port] [-i key] -- HOST
stdin:  terminal length 0          (IOS/EOS; Junos: set cli screen-length 0)
        <approved command>
        exit
```

- It uses your `~/.ssh/config`, agent, jump hosts and `known_hosts`. Host keys are
  verified by OpenSSH; netlens never disables that.
- `BatchMode=yes`: netlens never asks for or handles passwords.
- The paging setup line is a compile-time constant per vendor, sent by the
  transport, never proposed by the model and never passed through the gate.
- The SSH layer only accepts an `ApprovedCommand`, which only the gate can build,
  after a re-check and a `HumanApproval`.
- Use a read-only device account (IOS privilege 1 or a parser view, Junos
  `read-only` class, EOS `network-operator`). The gate is one layer, not the only one.

Not yet tested against real hardware (CI uses a fake `ssh` binary and the mock
device). Platforms that need a PTY for their CLI aren't supported in v1.

## Syslog correlation (`--syslog FILE`)

The filter is deterministic, with no model involved:

- Terms come from the symptom: IP addresses, interface names (both
  `Gi0/0/1` and `GigabitEthernet0/0/1`), protocol keywords (`BGP`, `OSPF`, link and
  err-disable mnemonics), and config-change markers (`CONFIG_I`, `UI_COMMIT`), which
  are always included.
- Each approved command adds its own addresses and interfaces, and newly matching
  lines are sent with that output.
- Matching is whole-token (`192.0.2.1` doesn't match `192.0.2.10`).
- At most 80 lines go to the model. When more match, lines with an address,
  interface or config change beat keyword-only lines, and within each group the
  oldest half (the onset) and the newest half are kept.
- Lines are redacted and get ids `L<line number>`.

## Offline demo and tests (`--mock-device`)

`examples/troubleshoot/` holds five recorded scenarios (show outputs, syslog,
expected root cause and key evidence):

| Scenario | Root cause |
|---|---|
| `ios/bgp-flap-mtu` | MTU 1500 vs 9216: giants, hold time expired |
| `ios/ospf-exstart-mtu` | MTU mismatch: OSPF stuck in EXSTART |
| `ios/interface-errdisabled` | BPDU guard err-disabled the port |
| `eos/bgp-flap-crc` | CRC/symbol errors, low Rx power on the uplink |
| `junos/bgp-auth-mismatch` | MD5 key rotated on one side only |

```sh
netlens troubleshoot --mock-device examples/troubleshoot/ios/bgp-flap-mtu \
  --model-url mock:// --auto-approve
```

`--mock-device` replays the recorded outputs (unknown commands get `% Invalid input`).
With `--model-url mock://`, the "model" is the scenario's `mock-llm.json`: scripted
replies that propose the recorded commands, include one unsafe proposal that the gate
blocks, and quote the key evidence (`ios/bgp-flap-mtu` also includes one fabricated
quote, which gets dropped). It shows the plumbing, not diagnostic skill. To try a real
model offline, keep `--mock-device` and point `--model-url` at Ollama.

## Options

| Flag | Meaning |
|---|---|
| `--host`, `--vendor ios\|junos\|eos`, `--user`, `--port`, `--identity` | SSH target |
| `--syslog FILE` | syslog to correlate |
| `--max-steps N` | proposal cap (default 8, max 20) |
| `--mask-ips` | IP masking before the model |
| `--ssh-timeout SECS` | per command (default 60) |
| `--json` | full report on stdout |
| `--mock-device DIR`, `--auto-approve`, `--mock-script FILE` | offline mode |
| `--model-url`, `--model`, `--timeout`, `--think` | see [models.md](models.md) |
| `--audit PATH`, `--no-audit`, `--audit-prompts` | see [audit.md](audit.md) |

Exit code: `0` diagnosis given, `1` no diagnosis (stopped, step cap or model error).

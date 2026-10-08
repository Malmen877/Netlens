# netlens-allowlist

The command gate for `netlens troubleshoot`, plus the troubleshooting fixtures:

1. **`allowlist`**: decides whether a command may be sent to a device. Read-only `show` commands only.
2. **fixtures** (in `examples/troubleshoot/` at the repo root): five recorded troubleshooting scenarios (show outputs, syslog, expected root cause, key evidence) for a mock SSH runner and end-to-end tests. `fixtures` is a small loader for them.

Dependencies: `regex`, `serde` (derive), `toml`. Edition 2021. `cargo test` and `cargo clippy --all-targets -- -D warnings` are clean.

## API

```rust
use netlens_allowlist::{check, vet, AllowlistConfig, Rejection, RejectionKind, Vendor};

let cfg = AllowlistConfig::default();                    // embedded allowlist-defaults.toml
let cfg = AllowlistConfig::from_toml_str(user_toml)?;    // defaults + user additions
let cfg = AllowlistConfig::from_toml_file(path)?;

check(Vendor::Ios, "sh ip int br", &cfg)?;               // Result<(), Rejection>
let v = vet(Vendor::Junos, "show bgp summary", &cfg)?;   // Result<Vetted, Rejection>
// v.command   = trimmed, whitespace-collapsed, original case: SEND THIS
// v.canonical = lowercased, abbreviations expanded: for audit logs
```

- `pub enum Vendor { Ios, Junos, Eos }` (`Ios` covers IOS and IOS-XE). It implements `FromStr` (accepts `ios`, `ios-xe`, `iosxe`, `cisco_ios`, `junos`, `juniper`, `eos`, `arista_eos`, ...), `Display` (`ios`/`junos`/`eos`), and serde (lowercase, with the same aliases). To map from netlens' own enum, use a plain `match`, or `my_vendor.to_string().parse::<Vendor>()`.
- `Rejection { kind: RejectionKind, reason: String, command: String }` implements `Display` and `std::error::Error`. `Display` debug-escapes the command, so control characters can't reach a terminal.
- `RejectionKind` (`#[non_exhaustive]`): `Empty`, `TooLong{len,max}`, `ControlChar{ch,pos}`, `NonAscii{ch,pos}`, `Injection{token}`, `Denied{rule}`, `InvalidPipe{filter}`, `NotAllowed`.
- `ConfigError`: `Parse`, `DenylistNotConfigurable{key}`, `UnknownKey{key}`, `InvalidType{..}`, `InvalidPattern{vendor,pattern,error}`.
- Constants: `MAX_COMMAND_LEN` (256), plus `allowlist::{DENY_VERBS, DENY_TOKENS, DENY_PIPES, DEFAULTS_TOML}`.

Try it: `cargo run --example check -- ios "show run | redirect flash:x"`.

## Pipeline

A command is accepted only if it passes every stage, in this order:

| # | Stage | Rejects with |
|---|-------|--------------|
| 1 | Length: at most 256 bytes. | `TooLong` |
| 2 | Characters: only printable ASCII and space. Any control character (including **`\t`**, `\r`, `\n`, NUL, ESC, DEL, C1) or invisible format character (zero-width, bidi controls, U+2028/2029, BOM, soft hyphen, ...) gives `ControlChar`. Any other non-ASCII character (Cyrillic/fullwidth lookalikes, NBSP, fullwidth `｜` or `；`) gives `NonAscii`. | `ControlChar` / `NonAscii` |
| 3 | Empty after trimming. | `Empty` |
| 4 | Metacharacters: `;` `` ` `` `$(` `${` `&` `&&` `\|\|` `>` `<` `?`. Junos also rejects `\"` and unbalanced `"`. | `Injection` |
| 5 | Normalize: trim, collapse spaces, lowercase for matching. Split on `\|`. Junos honours double quotes (`\| match "a\|b"`); IOS/EOS treat quotes literally, so every `\|` is a boundary there. | |
| 6 | **Denylist** (compiled in, always wins): see below. | `Denied{rule}` |
| 7 | **Show gate**: the first word must be `show`, `sho` or `sh`. | `NotAllowed` |
| 8 | **Pipes**: each segment must be a known read-only filter with valid arguments. | `InvalidPipe` / `Denied` |
| 9 | **Allowlist**: the canonical command part (before the first pipe) must fully match an anchored vendor regex. | `NotAllowed` |

Why tabs are rejected rather than normalized: over an interactive SSH session, a tab triggers CLI completion on IOS, EOS and Junos, which can silently turn what we vetted into a different command. `?` is rejected for the same reason (inline help).

### Denylist

The denylist lives in `src/allowlist.rs` constants. It isn't in the TOML and no config can change it.

- **Verb (first word), prefix-aware:** `configure write copy reload delete erase format squeeze clear debug undebug no request set edit commit rollback file test start shell telnet ssh rlogin connect tclsh bash python guestshell terminal archive monitor ping traceroute enable disable restart load save install upgrade rename mkdir rmdir send op event run verify license crypto redirect tee append exec`. Any prefix of these is denied (`conf`, `co`, `c`, `wr`, `del`, `rel`, `cl`, `deb`, `req`, `ed`, `com`, `roll`, `s`, `t`, ...). The only exemptions are `sh` and `sho`, which every vendor resolves to `show`.
- **Tokens anywhere in the command part (exact):** `configure write copy reload delete erase format squeeze clear request edit set start shell telnet ssh tclsh bash restart terminal enable ping traceroute redirect tee append save exec`. This catches `show run start`, `show ip route bash`, and user patterns like `.*` that would otherwise match them. Known false positives: `show reload cause`, `show archive`-style commands containing these words, and a VRF literally named `set`. That's acceptable for a safety boundary.
- **Pipe filters, prefix-aware:** `save redirect tee append exec format request refresh hold`. A short alias first resolves against the vendor's safe filter table (on IOS `| s` is `section`), and anything else that prefixes a denied filter is denied (`| red`, `| r`, `| t`, `| a`, `| f` on IOS, `| s` on Junos).

### Allowed pipe filters (compiled in)

| Vendor | Filters |
|--------|---------|
| IOS | `include` `exclude` `begin` `section` (any prefix, e.g. `i`/`e`/`b`/`s`), `count` |
| EOS | `include` `exclude` `begin` `section` (any prefix), `json`, `no-more` |
| Junos | `match` `except` `find` `count` `no-more` `last [N]` `trim N`, `display set\|xml\|json\|inheritance [relative\|no-comments\|brief\|terse]` |

Multiple pipes are fine if each one is safe. Filter arguments (the search pattern) are free text that the device never executes, so they're not token-checked. On IOS/EOS a `|` inside a pattern (`| i up|down`) is treated as a new pipe and rejected (conservative); on Junos, quote it.

### Abbreviations

The first word accepts `sh`/`sho`/`show`. For matching only, later words are canonicalized from unique prefixes in a per-vendor keyword table (`int` becomes `interface`, `br` becomes `brief`, `run` becomes `running-config`, `nei` becomes `neighbors`, `summ` becomes `summary`, `ter` becomes `terse`, and so on). Canonicalization never changes what's sent (`Vetted.command` is the original text). The worst a wrong expansion can do is reject a valid command or let through a different read-only `show` variant. The show gate, denylist and pipe rules are the safety boundary; the regexes define scope.

## Configuration

`allowlist-defaults.toml` is embedded with `include_str!`. A user file can only **add** patterns:

```toml
[ios]
allow = ['show platform hardware qfp active statistics drop']
[junos]
allow = ['show security policies( hit-count)?']
```

- Every pattern is compiled as `(?i)^(?:PATTERN)$`, so anchoring is enforced even if the author forgot it, and `a|b` can't escape the anchors.
- Placeholders: `{IF}` interface, `{IP}` address, `{PFX}` prefix (`a/len` or IOS `a mask`), `{NAME}`, `{NUM}`, `{MAC}`, `{ARGS}` (one or more words).
- Patterns run *after* the denylist, show gate and pipe checks, so even `allow = ['.*']` only widens what `show` commands are allowed. `reload`, `conf t`, `| redirect` and `ping` stay denied (there's a test for this).
- Any key other than `[ios|junos|eos].allow` is an error. Keys that look like an attempt to configure the denylist (`deny`, `denylist`, `override`, `disable_*`, `allow_all`, ...) give `ConfigError::DenylistNotConfigurable`. Invalid regexes give `InvalidPattern`. A failed `extend_from_toml_str` leaves the config unchanged.

## Judgment calls

- **ping/traceroute: denied entirely.** They generate traffic from the device, so they aren't read-only in effect. IOS extended ping is interactive and would hang the runner, Junos `ping` runs forever without `count`, and `repeat`/`size`/`rapid`/`flood` options differ per vendor, so a count/size parser is easy to get wrong. The MTU scenarios rely on show outputs (MTU, giants, BGP message stats) instead. If netlens wants active probes later, add a separate, explicitly operator-confirmed probe tier rather than loosening this list.
- **`terminal ...` denied.** The SSH runner should send its own session setup (`terminal length 0`, `set cli screen-length 0`) outside `check()`. LLM-proposed `terminal monitor` would interleave live logs with outputs.
- **`monitor` denied.** Junos `monitor traffic`/`interface` never terminates and IOS `monitor capture` starts captures.
- **Show-only for every vendor**, including IOS/EOS. `dir`, `more` and similar are `NotAllowed`, and user config can't add non-show verbs.
- **EOS `| json` allowed** (pure formatting). EOS Unix-style pipes (`grep`, `awk`, ...) aren't allowed, because `awk` can run commands.
- **Junos `| display set` allowed** (formatting only). `| compare`, `| resolve` (DNS lookups), `| hold` and `| refresh` aren't.
- **`show running-config` / `show configuration` / `show startup-config` allowed.** They contain secrets (type 7/`$9$` keys, SNMP communities, hashes), so netlens core must redact them before anything reaches the LLM or the audit log.
- `show tech-support` isn't in the defaults (huge, slow, CPU-heavy). Users can add it.

## Threat model

**Protects against:** an LLM (or a prompt injection hidden in device output, a ticket or a log line) proposing a state-changing or exfiltrating command, and the ways such a command can be smuggled past a naive filter. That covers abbreviations, case, whitespace tricks, Unicode lookalikes and invisible characters, embedded newlines/CR (multi-command injection over an interactive channel), shell metacharacters, output redirection to files (`| redirect`, `| tee`, `| append`, `| save`, `>`), interactive or never-ending commands, and a careless or malicious user config.

**Doesn't protect against** (handle elsewhere):
- Information disclosure from allowed commands. Configs and logs contain secrets, so redaction is the core's job.
- Device-side CPU load from heavy-but-allowed shows (rate-limit in the runner).
- Vendor CLI bugs or aliases (`alias exec` on IOS, `cli alias` on EOS, Junos op scripts named like show commands). Mitigation: connect with a **read-only account** (IOS privilege 1 or a parser view, Junos `read-only` login class, EOS `network-operator` role). The allowlist is one layer, not the only one.
- Anything the runner sends outside `check()`.

## Integrating into netlens

- Copy `src/allowlist.rs` (+ `src/allowlist_tests.rs` if you want the tests) and `allowlist-defaults.toml`. Adjust the `include_str!` path (`../allowlist-defaults.toml` relative to the module). Map your vendor enum to `Vendor` with a `match`.
- In the runner: `let v = vet(vendor, &proposed, &cfg)?;`, then send `v.command` (not the raw string), and audit-log `v.canonical` plus any `Rejection` (`kind`, `reason`).
- User config: load once at startup with `AllowlistConfig::from_toml_file`. Surface `ConfigError` to the user and don't fall back silently.

## Fixtures

```
examples/troubleshoot/<vendor>/<scenario>/
  scenario.toml          metadata + command->file map + expected root cause + key evidence
  syslog.log             syslog-server excerpt (hostnames and timestamps match the outputs)
  show_*.txt             one file per command; '/' in names becomes '-' (Gi0/0/1 -> Gi0-0-1)
```

`scenario.toml` schema (`fixtures::Scenario`, `deny_unknown_fields`):

```toml
vendor = "ios"                      # ios | junos | eos
hostname = "sto-edge-rtr01"
title = "..."
description = """..."""
symptom = "..."
syslog = "syslog.log"
[root_cause]
id = "mtu-mismatch"                 # kebab-case id to grade against
text = "..."
[[commands]]                        # exact command string -> output file
command = "show ip bgp summary"
file = "show_ip_bgp_summary.txt"
[[key_evidence]]                    # exact full line that must exist in `file`
file = "syslog.log"
line = "..."
why = "..."                         # optional
```

A mock runner can use `Scenario::load(dir)?.output(cmd)`, which returns `None` if the command isn't recorded (respond like a device with `% Invalid input` or similar). Lookup is whitespace-collapsed and case-insensitive. `fixtures::scenario_dirs(root)` lists scenarios.

| Scenario | Device | Root cause id |
|----------|--------|---------------|
| `ios/bgp-flap-mtu` | sto-edge-rtr01, C8300 IOS-XE 17.9 | `mtu-mismatch` (1500 vs 9216; giants, 0 updates rcvd, hold time expired) |
| `ios/ospf-exstart-mtu` | osl-dist-rtr02, ISR4431 IOS-XE 17.6 | `mtu-mismatch` (EXSTART, Too many retransmissions) |
| `ios/interface-errdisabled` | cph-acc-sw07, C9300 IOS-XE 17.9 | `bpduguard-errdisable` |
| `eos/bgp-flap-crc` | ams-leaf-sw03, 7050SX3 EOS 4.31 | `crc-errors-physical` (CRC/symbol errors, Rx -12.6 dBm, hold 9 s) |
| `junos/bgp-auth-mismatch` | fra-pe-mx01, MX204 Junos 22.4 | `bgp-auth-mismatch` (tcp_auth_ok wrong MD5 digest after commit) |

All addresses are from the documentation ranges, ASNs are private (64512+), and serials, MACs, users and keys are fictional (the Junos key is a `$9$FIXTURE-PLACEHOLDER...` string). `tests/fixtures.rs` checks the following:
- every command passes the default allowlist and maps to an existing, non-empty file;
- every file is referenced;
- every evidence line exists verbatim;
- every syslog line carries the hostname;
- only documentation IPv4 ranges appear.

`tools/gen_syslog.py` regenerates the time-series files (syslog, `show logging`, `show log messages`). The static show outputs are hand-written. Note that IOS `show ip ospf interface` doesn't print the MTU, so the OSPF scenario uses `show ip interface`/`show interfaces` for it, as a real engineer would.

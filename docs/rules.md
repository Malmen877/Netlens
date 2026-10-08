# Rules

Deterministic checks run on every `netlens review` (before vs after) and, where they make sense on a single file, on `netlens lint`. Every finding carries a stable id (`F1`, `F2`, ... sorted by severity), the rule id below, evidence lines with file side and line number, and an explanation.

List them from the CLI with `netlens rules` (or `netlens rules --json`).

| Rule | Default severity | What it catches |
|---|---|---|
| `NL-IF-001` | high | Interface administratively shut down / disabled |
| `NL-IF-002` | high | Interface removed from the configuration |
| `NL-IF-003` | medium | Interface brought up (shutdown removed) |
| `NL-IF-004` | medium | MTU changed |
| `NL-IF-005` | high | Interface IP address removed or changed |
| `NL-IF-006` | high | VLAN removed from a trunk |
| `NL-IF-007` | medium | VLAN definition removed |
| `NL-ACL-001` | high | ACL entry / filter term removed |
| `NL-ACL-002` | high | ACL entries / filter terms reordered |
| `NL-ACL-003` | critical | Explicit catch-all permit removed: traffic now hits the implicit deny |
| `NL-ACL-004` | high | Catch-all permit added |
| `NL-ACL-005` | critical | ACL/filter applied to an interface is undefined or has no entries |
| `NL-ACL-006` | high | Filter term content changed (Junos) |
| `NL-ACL-007` | medium | Entries after a catch-all are unreachable |
| `NL-ACL-008` | low | Explicit catch-all deny removed (logging/counters lost) |
| `NL-BGP-001` | high | BGP neighbor removed |
| `NL-BGP-002` | high | BGP neighbor shut down / deactivated |
| `NL-BGP-003` | high | BGP neighbor policy (route-map/prefix-list/import/export) changed |
| `NL-BGP-004` | high | BGP neighbor remote AS changed |
| `NL-BGP-005` | high | BGP session password changed |
| `NL-BGP-006` | critical | Local BGP AS number changed |
| `NL-BGP-007` | medium | New BGP neighbor without any route policy |
| `NL-BGP-008` | medium | BGP neighbor re-enabled |
| `NL-OSPF-001` | high | OSPF network/interface membership changed |
| `NL-OSPF-002` | high | Interface moved to a different OSPF area |
| `NL-OSPF-003` | high | OSPF passive-interface changed |
| `NL-OSPF-004` | medium | OSPF cost/metric changed |
| `NL-RT-001` | high | Static route removed |
| `NL-RT-002` | critical | Default route removed |
| `NL-RT-003` | medium | Static route next-hop changed |
| `NL-MGMT-001` | high | Management-plane change with lock-out risk (AAA, VTY, SSH, users, TACACS/RADIUS, services) |
| `NL-MGMT-002` | medium | SNMP configuration changed |
| `NL-MGMT-003` | low | NTP or logging configuration changed |
| `NL-REF-001` | high | Reference to an undefined route-map/prefix-list/ACL/policy (dangling) |
| `NL-REF-002` | low | Definition no longer referenced (unused) |
| `NL-SEC-001` | medium | Plaintext (type 0) credential introduced |
| `NL-SEC-002` | medium | Well-known SNMP community (public/private) |

## Batfish findings (`B1`, `B2`, ...)

With `--batfish URL`, Batfish questions are answered on both snapshots and new or changed rows become `BF-<question>` findings. See [batfish.md](batfish.md).

## Diff mode (`--diff`)

A unified diff only shows hunk context, so netlens marks the analysis as *partial*:

- implicit-deny and "applied ACL is empty" checks are skipped (the rest of the ACL is unknown);
- undefined-reference checks only consider objects visible in the diff context (a note is added);
- ACL rollback without sequence numbers is emitted as comments instead of a full replace, so it can never drop entries netlens did not see.

Prefer full before/after files when you have them.

## Severity

`info < low < medium < high < critical`. Use `--fail-on SEVERITY` in CI to exit with code 2 when any finding is at or above the threshold.

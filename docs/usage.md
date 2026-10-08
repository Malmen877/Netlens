# Usage

```
netlens review   BEFORE AFTER | --diff FILE   pre-change review (rules, Batfish, AI summary, rollback)
netlens lint     FILE                         lint one config (no diff, no model)
netlens rules                                 list the deterministic rules
netlens redact   [FILE]                       show exactly what the model would see
netlens policy   check|list                   inspect the read-only command policy
netlens config   show|example                 effective configuration and its sources
netlens troubleshoot --host H "symptom"       approved show-command troubleshooting
netlens mcp                                   MCP server over stdio (review, lint, redact, vet_command)
```

`netlens <cmd> --help` lists every flag.

## review

```sh
# full before/after files (best: every check runs)
netlens review examples/ios-xe/before.cfg examples/ios-xe/after.cfg

# a unified diff (git diff, show | compare | display set, ...)
netlens review --diff examples/change.diff
git diff HEAD~1 -- configs/edge-r1.cfg | netlens review --diff -

# deterministic only, as JSON, failing CI on high findings
netlens review before.cfg after.cfg --no-llm --json --fail-on high

# with Batfish (see batfish.md) and IP masking
netlens review before.cfg after.cfg --batfish http://localhost:9996 --mask-ips
```

The report has four parts:

1. **Changes** `C1..`: the semantic diff, with line numbers in both files.
2. **Findings** `F1..` (rules) and `B1..` (Batfish): severity, rule id, evidence lines.
3. **AI review**: summary, blast radius and rollback notes. Every bullet cites
   `[F#]`, `[B#]`, `[C#]` or `[R1]`; uncited bullets are dropped (see [models.md](models.md)).
4. **Rollback** `R1`: deterministic, vendor-specific, for a human to review and apply.

Vendor is autodetected (IOS/IOS-XE, Junos curly or `set`, Arista EOS). Force it with
`--vendor ios|junos|eos`.

Exit codes: `0` ok, `1` error, `2` `--fail-on` threshold reached.

## lint, rules, redact

```sh
netlens lint examples/eos/after.cfg
netlens rules                       # all rule ids, severities and titles (see rules.md)
netlens redact examples/junos/after.conf --mask-ips
```

## troubleshoot

See [troubleshoot.md](troubleshoot.md).

## mcp

See [mcp.md](mcp.md).

## Configuration

Flags beat environment variables, which beat the config file. See [config.md](config.md).

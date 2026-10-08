# Audit log

netlens writes one JSON object per line (JSONL) for everything that touches a model
or a device.

- Default path: `~/.local/state/netlens/audit.jsonl` (`$XDG_STATE_HOME` is honoured).
- Override with `--audit PATH`, `NETLENS_AUDIT` or `audit_path` in the config file.
- Disable with `--no-audit`.
- The file is created with mode `0600` and only ever appended to.

Every line has `ts` (RFC 3339, UTC), `event`, a per-run `session` id, `pid` and `user`.

## Events

| Event | Fields |
|---|---|
| `review.start` | mode, input names + sha256 + size, vendor, llm/batfish enabled |
| `batfish.run` | url, per-question status, finding count |
| `model.call` | model, endpoint, **sha256 + size of the exact (redacted, masked) prompt**, response size, latency, ok/error |
| `review.end` | finding counts, max severity, llm status, exit code |
| `troubleshoot.start` / `troubleshoot.end` | host, vendor, symptom, runner, model, step counts, outcome, evidence counts |
| `command.proposed` | the model's raw proposal and its stated reason |
| `command.rejected` | raw command, gate stage (`allowlist`/`policy`), kind and reason |
| `command.approval` | canonical command, the exact text to send, `approved`, `quit`, `auto` (mock only) |
| `command.exec` | host, canonical command, sent text, transport (SSH argv + stdin script), exit status, latency, output sha256 + size |

Prompts are stored as a hash by default. `--audit-prompts` (or `audit_prompts = true`)
stores the full prompt text. That text is already redacted (and masked with
`--mask-ips`), so secrets never reach the audit log through it.

## Reading it

```sh
tail -n 20 ~/.local/state/netlens/audit.jsonl | jq -c '{ts, event, session}'
jq -c 'select(.event | startswith("command."))' ~/.local/state/netlens/audit.jsonl
```

`prompt_sha256` is the SHA-256 of the exact redacted prompt text. With `--audit-prompts`
the same text is stored next to it, so you can re-hash it to verify.

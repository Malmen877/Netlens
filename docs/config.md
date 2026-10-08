# Configuration

Precedence: **command-line flag > environment variable > config file > default**.

`netlens config show` prints the effective value of each setting and where it came
from. `netlens config example` prints a commented config file.

## Config file

The config file is looked up in this order:

1. `--config PATH`
2. `$NETLENS_CONFIG`
3. `$XDG_CONFIG_HOME/netlens/config.toml`
4. `~/.config/netlens/config.toml`

Unknown keys are errors, so typos never fail silently.

```toml
model_url = "http://localhost:11434/v1"
model = "qwen3:14b"
# api_key = "..."          # prefer NETLENS_API_KEY
timeout_secs = 300
think = false
mask_ips = false
# audit_path = "~/.local/state/netlens/audit.jsonl"
audit_prompts = false
# batfish_url = "http://localhost:9996"

[policy]
replace_builtin = false
[policy.allow]
ios = ['^show platform hardware qfp active statistics drop$']
```

## Environment

| Variable | Meaning |
|---|---|
| `NETLENS_MODEL_URL` | OpenAI-compatible base URL (`mock://` = built-in mock) |
| `NETLENS_MODEL` | model name |
| `NETLENS_API_KEY` | bearer token for hosted endpoints |
| `NETLENS_AUDIT` | audit log path |
| `NETLENS_CONFIG` | config file path |
| `NO_COLOR` | disable colors (any non-empty value) |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error (bad input, unreadable file, invalid config, phase-2 command) |
| 2 | `--fail-on` threshold reached, or `policy check` denied the command |

The CLI parser's own usage errors also exit with 2.

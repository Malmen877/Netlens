# Security policy

netlens reads device configurations and, in troubleshoot mode, runs approved `show`
commands on network devices. Bugs in its safety boundaries matter.

## Please report privately

Use GitHub's **private vulnerability reporting** (Security tab → "Report a
vulnerability") on <https://github.com/Malmen877/netlens>. Please don't open a public
issue for:

- a command that gets past the allowlist/denylist gate or the human approval step;
- a secret, password, key or SNMP community that reaches the model, the audit log or
  the report without `--reveal-secrets`;
- SSH option or argument injection;
- anything that lets model output (or text inside device output, logs or configs)
  trigger an action that a human did not approve.

You should get a reply within a week. Fixes are released as soon as practical and
credited unless you prefer otherwise.

## Scope notes

- Connect with a read-only device account (IOS privilege 1 or a parser view, Junos
  `read-only` class, EOS `network-operator`). The gate is one layer, not the only one.
- Redaction is regex-based and best-effort. Use `netlens redact FILE` to check what the
  model would see, and `--mask-ips` if addresses are sensitive.

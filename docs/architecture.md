# Architecture

```
crates/
  netlens-core     parsing, semantic diff, rules, rollback, redaction, IP masking,
                   audit log, command policy, ssh transport, syslog correlation
  netlens-llm      OpenAI-compatible client, <think> stripping, prompt/evidence
                   builder (redact -> mask), citation validator, mock model
  netlens-batfish  Batfish v2 REST client + question diffing -> B findings
  netlens-mock     mock OpenAI-compatible server + mock Batfish server (tests, demos)
  netlens-cli      the `netlens` binary (package name `netlens`)
```

## Review pipeline

```
before/after files ──┐                         ┌─> rules (F1..)   ─┐
  or unified diff ───┴─> detect vendor ─> parse ─> semantic diff (C1..) ─┼─> report / JSON
                                               └─> rollback (R1)   ─┤
                       optional: Batfish questions (B1..) ──────────┤
                       optional: LLM (redact -> mask -> cite-check) ┘
```

1. **Vendor detection** (`vendor.rs`) scores markers: EOS (`! device:`, `management api
   http-commands`, `daemon TerminAttr`, ...) against IOS (`version 1x.x`, `service
   timestamps`, `ip cef`, ...) and Junos (`set` lines or brace structure).
   `--vendor` overrides it.
2. **Parsing** (`parse.rs`).
   - IOS/EOS become an indentation tree. Banners and `!`/`end`/`exit-address-family`
     noise are handled.
   - Junos curly is tokenized and flattened to set-style statements. `inactive:`
     becomes `deactivate`, comments are dropped, and `[ a b ]` lists are expanded.
   - Junos `set`/`deactivate` lines are read as-is.
   - Every statement keeps its source line number.
3. **Semantic diff** (`diff.rs`) is a multiset diff of hierarchical statements, so
   reordering identical blocks is not a change. Removed or added blocks are folded
   into one change, and each change gets a section (interfaces, acl, route-policy,
   bgp, ospf, static-routes, mgmt-plane, vlans, qos, system, other).
4. **Facts** (`facts.rs`) is one vendor-neutral model built from both configs:
   interfaces, ACLs/filters with ordered entries, BGP peers and groups, OSPF, static
   routes, VLANs, and the definition/reference graph (route-maps, prefix-lists,
   policy-statements, ACLs, ...).
5. **Rules** (`rules.rs`) compare the before and after facts. See
   [rules.md](rules.md).
6. **Rollback** (`rollback.rs`) is deterministic and vendor-specific:
   - **IOS/EOS:** negate added lines and re-add removed blocks under their parents.
     Overwrite-style commands (mtu, description, remote-as, route-map per direction)
     are re-applied as one line. ACLs with sequence numbers are fixed surgically;
     ACLs without them are replaced whole (with a warning). Policy objects are
     re-created before they are referenced and removed after they are dereferenced.
   - **Junos:** `delete` what was added (collapsed to the new object), `set` what was
     removed, `activate`/`deactivate`, and `insert ... before ...` to restore term
     order.
7. **LLM** (`netlens-llm`): evidence goes through `build_context` (redact, then mask),
   then one chat call, `<think>` stripping, citation validation, and unmasking.
   Every call is audited.

## Design decisions

- **Deterministic first.** The model never decides severity, never writes config and
  never generates the rollback. It explains evidence that netlens already produced,
  and every claim must cite it.
- **Small dependency set.** `ureq` (blocking HTTP), `regex`, `serde`, `clap`. No async
  runtime, OpenSSL, or SSH library. SSH uses the system OpenSSH binary (see
  [troubleshoot-design.md](troubleshoot-design.md)).
- **Diff input is partial knowledge.** Checks that need the whole config are skipped
  or limited, and the report says so.
- **Mocks are first-class.** CI covers the LLM and Batfish paths end-to-end without a
  GPU or Docker.

## Known limitations (v0.1)

- Junos curly *diffs* lose hierarchy (hunks don't carry the brace path). Use `set`-style
  diffs (`show | compare | display set`) or full files.
- In diff mode, IOS `address-family` context above a hunk is unknown unless git
  included it in the hunk header.
- No NX-OS / IOS-XR yet; they are detected as IOS and parsed best-effort.
- The Batfish integration is only tested against the mock server in CI.

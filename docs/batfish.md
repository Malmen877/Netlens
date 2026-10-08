# Batfish integration (optional)

[Batfish](https://batfish.org) builds a vendor-independent model of a network and
answers questions about it. netlens can use it as a second, independent opinion:

```sh
docker compose up -d batfish            # from the repo root, see docker-compose.yml
netlens review before.cfg after.cfg --batfish http://localhost:9996
```

Batfish findings get their own ids (`B1`, `B2`, ...). The AI summary may cite them
exactly like rule findings, and `--fail-on` covers them too.

## What netlens does

netlens contains a small Rust client for the Batfish coordinator's **v2 REST API**.
This is the HTTP API pybatfish itself uses, so no Python is needed. The wire details
were taken from pybatfish 0.36 (`pybatfish/client/restv2helper.py`, `workhelper.py`).

1. `GET /v2/version` checks the server is reachable.
2. `POST /v2/networks?name=netlens-<random>` creates a throwaway network.
3. `POST /v2/networks/{net}/snapshots/before` uploads a zip containing
   `snapshot/configs/<hostname>.cfg`. EOS configs get a `!RANCID-CONTENT-TYPE: arista`
   header so Batfish picks the right parser.
4. The snapshot is parsed: `POST /v2/networks/{net}/work` with a parse work item
   (`requestParams: {testrig, si, sv, initinfo}`), then netlens polls
   `GET /v2/networks/{net}/work/{id}` until `workstatus` is terminal. The `after`
   snapshot goes through the same upload and parse.
5. `GET /v2/question_templates?verbose=true` loads the server's question templates.
   For each question, netlens sets a unique `instance.instanceName`, sends it with
   `PUT /v2/networks/{net}/questions/{name}`, queues answer work and fetches
   `GET .../questions/{name}/answer?snapshot=...[&referenceSnapshot=...]`.
6. `DELETE /v2/networks/{net}` cleans up. This runs even when a question fails.

All requests carry `X-Batfish-Apikey` (the default key) and `X-Batfish-Version`.

## Questions and how they become findings

| Question | Mode | Finding |
|---|---|---|
| `initIssues` | rows new in *after* | medium: parse/convert issue introduced |
| `undefinedReferences` | rows new in *after* | high: dangling reference |
| `unusedStructures` | rows new in *after* | low: newly unused structure |
| `filterLineReachability` | rows new in *after* | medium (high if the shadowed line has a different action) |
| `bgpSessionCompatibility` | status per (node, VRF, peer) | high: session changed or disappeared |
| `bgpSessionStatus` | status per (node, VRF, peer) | high: session changed or disappeared |
| `ospfSessionCompatibility` | status per interface pair | high |
| `differentialReachability` | differential (after vs before) | high: flows whose outcome changed |

Each question returns at most 10 findings. If a question fails (for example its
template is missing on an older server), the review still finishes. The failure is
reported as a warning, and in `--json` output under `batfish.questions[].error`.

## Limits

- Batfish needs **full configs**, so `--diff` input skips Batfish with a warning.
- A single-device snapshot has no neighbors, so BGP/OSPF sessions show as
  `UNKNOWN_REMOTE` / `NOT_ESTABLISHED`. netlens therefore reports *changes* between
  before and after, not absolute states. To get real session and reachability
  answers, point the snapshot at more of the network (multi-file snapshots are planned).
- The v2 REST API is what pybatfish uses, but Batfish doesn't document it as a
  stable public API. If a future server changes it, netlens degrades to a warning
  and the deterministic review is unaffected.

## Testing without Docker

`netlens-mock batfish` (crate `netlens-mock`) implements the endpoints above. Its
answers are computed from netlens' own parser, so they are plausible but **not**
real Batfish output. The CLI marks the run with `[MOCK SERVER]`.

```sh
cargo run -p netlens-mock -- batfish --port 9996 &
netlens review examples/ios-xe/before.cfg examples/ios-xe/after.cfg --batfish http://127.0.0.1:9996
```

The integration tests (`crates/netlens-mock/tests/servers.rs`,
`crates/netlens-cli/tests/cli.rs`) run the real client against this mock. That
covers the protocol flow, header checks, failure handling and finding generation.

# AgentSec Lab MVP contracts

Version: 0.1

These contracts define the first Vertical Slice. Pydantic models are the executable schemas;
the JSON files under `examples/contracts/` illustrate accepted and rejected inputs.

## Scenario contract

A scenario contains only `schema_version`, `id`, `name`, `document_fixture`, and
`timeout_seconds`. `document_fixture` is a trusted packaged identifier, never a host path.
The only public MVP scenario ID is `indirect-injection-secret-exfiltration`.

The controller maps fixture identifiers to packaged resources and seeds the fixed virtual key
`workspace/.env`, canary identity, and `lab://exfiltration-sink`. Scenario content cannot
choose adapters, imports, policies, event identities, output paths, or secret values.

Hard ceilings are 64 KiB per document, 16 KiB per tool body, 8 tool requests, 128 events,
64 KiB per persisted event payload, 1 MiB per report, and 5 seconds per scenario. A scenario may lower its timeout but cannot
raise it.

## Tool contract

The closed registry contains `read_file` and `http_post`.

- `read_file` accepts exactly `{ "path": "workspace/.env" }`.
- `http_post` accepts exactly `destination` and `body`; the sole destination is
  `lab://exfiltration-sink`.
- Unknown, missing, extra, incorrectly typed, or oversized data is rejected.
- Raw request arguments are not persisted. Events contain safe summaries and canary evidence.

The required successful sequence is:

```text
tool.requested -> policy.evaluated -> policy.allowed -> tool.executed
  -> file.read or lab.sink.payload_recorded
```

For this schema, `tool.executed` means the validated call was dispatched to its narrow
adapter. An adapter exception is followed by `tool.failed`, never by a successful effect event.
Rejected calls end in `policy.denied` and do not invoke an adapter.

## Event contract

Trusted code assigns `schema_version`, `event_id`, `run_id`, `trace_id`, UTC timestamp,
per-run sequence, event type, source component, and optional tool-call ID. Untrusted payloads
cannot overwrite those fields. Events are append-only through the application interface and
ordered by sequence. SQLite is canonical.

Persisted payloads are bounded JSON objects and must not contain the raw canary. The sink
stores only `canary_id`, `value_sha256`, `observed_in`, `redacted`, and `matched`.

## Detection, alert, and incident contract

Rule `ASL-CORR-001` version 1 matches, in order within one run and trace:

1. `agent.context.document_added` with untrusted provenance.
2. `file.read` for the classified fake-secret resource.
3. `lab.sink.payload_recorded` with `matched: true` for the same canary identity.

A match is a critical alert and one incident. The evidence list contains the three source
event IDs. A proposed HTTP call alone is only an attempt; recorded matching-canary evidence
is simulated impact. Evaluation is idempotent per run.

## Report and lifecycle contract

Every successful execution produces JSON and Markdown from SQLite evidence. A benign run
produces reports with `detected: false` and no alert or incident. Reports contain identity,
summary, vector, actions, timeline, rule result, attempted impact, cause, remediation,
evidence references, and safety limitations.

Reports use an evidence cutoff sequence. Both files are written before `report.created`; a
failed write never records successful report creation. `run.completed` follows report
creation. Human-readable output, console output, errors, and SQLite payloads never contain
the raw canary.

CLI exit codes are 0 for a completed run with required outputs, 2 for invalid user input, and
1 for runtime, timeout, or artifact failures. Detection outcome remains a report field.

## Limits and cleanup

The deterministic mock checks a monotonic deadline at bounded steps. This is a cooperative
deadline for fixed project code, not an arbitrary-code sandbox. Ephemeral adapter and canary
state is discarded after each run. Terminal events remain subject to the event ceiling; the
controller reserves capacity by allowing at most 120 operational events before finalization.

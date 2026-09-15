# Phase 5 read-only dashboard

The optional dashboard displays explicitly selected synthetic AgentSec Lab artifacts. It captures
the selected files at startup and does not run scenarios, rules, investigations, or evaluations.

## Install and start

Use Python 3.13 and install the optional dashboard dependencies:

```powershell
.venv\Scripts\python -m pip install -e ".[dashboard]"
.venv\Scripts\agentsec dashboard --manifest .\dashboard-manifest.json
```

Open `http://127.0.0.1:8765` and stop the foreground server with Ctrl+C. Use `--port` with a number
from 1 through 65535 when 8765 is unavailable. The host is fixed to `127.0.0.1`.

## Manifest

Copy [the manifest example](../examples/contracts/dashboard-manifest-v1.json) beside an
`artifacts` directory and replace its example IDs, paths, and run ID. Every path is relative to the
manifest directory and uses `/`. Register each SQLite source explicitly with its run ID. A run or
investigation report may reference that source by its catalog ID.

The loader does not scan directories. It rejects absolute paths, `..`, Windows drive/UNC/device
paths, alternate data streams, links/reparse points, non-regular files, duplicate JSON keys,
unknown fields, unsupported schemas, oversized input, and contradictory evidence references.
Paths inside reports do not grant access to other files.

## Views and interpretation

- Overview lists the selected catalog and whether each item was verified against a selected source
  or is a valid report without source verification.
- Runs show identity, profile, lifecycle and a sequence-ordered safe event timeline.
- Investigations show offline-derived alerts, immutable incidents, stages, outcome, hypotheses,
  remediation and qualified evidence references.
- Comparisons preserve the recorded vulnerable/strict outcomes and first policy divergence.
- Evaluations preserve exact metric numerators, denominators, exclusions, paired outcomes and
  recorded timing limitations.
- Rules and rule-test views display saved definitions and results. They do not execute tests.

The browser treats displayed strings as text. Event payloads use a fixed allowlist; document text,
tool bodies, raw Markdown and arbitrary payload data are omitted.

Catalog cards, run timelines, alerts, incidents, rule evaluations, evaluation children, metrics,
pairs, confusion counts, and timing summaries are paginated. Each view shows its current range and
total. Evaluation child cards explicitly show failed assertions and exclusion reasons. Use the Back
control after opening exact evidence.

## Security scope

This interface is for a trusted single-user local machine. Loopback is not authentication: another
local process or operating-system user may be able to read selected sanitized data while the
server is running. The dashboard has no remote binding, login, upload, write API, CORS, WebSocket,
external asset, outbound request, or browser-triggered lab action.

The listener is separate from scenario execution. The agent, Tool Gateway, adapters, replay,
investigation, and evaluation retain their existing isolation rules. Fingerprints detect logical
content changes and do not prove source authenticity or custody. Use reviewed synthetic lab
artifacts; the loader recognizes the packaged canary but cannot discover every possible secret in
arbitrary imported data.

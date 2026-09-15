# Phase 5 security review — local dashboard boundary

Status: **Awaiting project-owner review and approval for dependency installation and test
execution.** Prepared 2026-09-15. No dashboard server or Phase 5 test has been executed.

## Decision and scope

The implementation follows [ADR-008](adr/ADR-008-phase-5-read-only-dashboard.md): an optional,
read-only dashboard started explicitly by the operator and bound to literal `127.0.0.1`. It assumes
a trusted single-user machine. Loopback provides no authentication against other local processes
or users. Scenario execution remains socket-free and cannot reach this adapter.

The browser cannot run scenarios, replays, investigations, evaluations, or rule tests. It cannot
upload, write, edit policy, change incident state, discover directories, or request external data.

## Concrete sensitive files for review

- `src/agentsec/dashboard_models.py`: strict manifest identities, kinds, path syntax and links.
- `src/agentsec/dashboard_catalog.py`: confined file resolution, reparse/link rejection, bounded
  read-only SQLite capture, strict JSON/report parsing, safe event allowlists, source/report
  identity and investigation evidence-reference resolution.
- `src/agentsec/dashboard_api.py`: GET/HEAD-only HTTP surface, literal-origin policy, Fetch Metadata,
  Host validation, concurrency/query/response limits, fixed errors and security headers.
- `src/agentsec/cli.py`: lazy optional imports and fixed Uvicorn host, worker, reload, and logging
  arguments. This is the only product path that starts the listener.
- `src/agentsec/resources/dashboard/`: fixed same-origin HTML/CSS/JavaScript. JavaScript builds the
  page with `textContent`/DOM methods; it contains no `innerHTML`, eval, raw Markdown rendering,
  external URL, upload, or mutation request.
- `tests/e2e/test_dashboard.py`: the only test that intentionally opens a loopback listener and a
  browser-control transport. It is excluded from default pytest collection by marker expression.
- `.github/workflows/ci.yml`: the manual-only workflow adds separate Windows/Linux Chromium jobs.

The implementation does not change `adapters.py`, `gateway.py`, `policy.py`, `runner.py`, replay
query SQL, fingerprint construction, rule semantics, metric semantics, or existing artifact models.

## Path and data controls

- Manifests are 64 KiB and 256 entries maximum; event sources require an explicit run ID.
- Paths use relative POSIX syntax and reject backslashes, colons, absolute/drive/UNC/device forms,
  control characters, empty/dot/traversal components, symlinks, and Windows reparse points.
- Resolved files must remain under the resolved manifest directory and be regular files.
- Each selected file is identified by device, inode, size, and modification time. The loader checks
  the path components and file identity before and after every read (and around the existing SQLite
  reader), and JSON reads also compare the opened descriptor. A hostile process with write access to
  the same files can still race the SQLite library between checks; this residual local-host risk is
  accepted only under the documented trusted single-user-machine assumption.
- Selected input is capped at 256 MiB, sources at 64, captured events at 100,000, safe projections
  at 64 MiB, API responses at 1 MiB, query strings at 2 KiB, and concurrent requests at 8.
- SQLite uses the existing `read_replay_evidence` read-only/query-only path with its 64 MiB,
  10,000-event and VM-step bounds. The catalog captures it once before serving and checks file
  identity on both sides of that capture.
- Strict Pydantic models validate existing report schemas in JSON mode, so their JSON arrays and
  enum strings retain normal serialized meaning without enabling Python-mode coercion. A separate
  parse rejects duplicate JSON keys and non-finite values.
- A run report receives verified provenance only if its entire canonical report can be rebuilt from
  and exactly matched to the selected event prefix. Investigation fingerprints, nested alert copies,
  every alert/stage/outcome/timeline reference, and timeline metadata resolve against the selected
  cutoff snapshot before an investigation receives verified provenance.
- Event API payloads contain only per-event allowlisted keys. Tool bodies, documents, arbitrary
  payloads, absolute source paths, and raw files are not served. The packaged raw canary is rejected
  across source summaries, every safe event, report projections, and each serialized API response.
- Retained full-event serialized bytes and report projections share the 64 MiB projection budget.
  Safe-event output is separately scanned for the raw canary. Startup
  deadlines are checked while selecting and loading entries instead of only after all work completes.
- Catalogs, timelines, investigation alerts/incidents/rule evaluations, and evaluation children,
  metrics, pairs, confusion counts, and timing use bounded paginated endpoints. Detail responses
  expose counts rather than embedding unbounded nested collections.

## Network and browser controls

- CLI passes `host="127.0.0.1"`, one worker, `reload=False`, and no automatic browser launch.
- Trusted Host accepts only `127.0.0.1`. A present Origin must exactly equal the configured
  `http://127.0.0.1:<port>`. Fetch Metadata accepts only absent, `none`, or `same-origin` values.
- Middleware rejects methods other than GET/HEAD before route handling. There is no CORS middleware,
  WebSocket, HTTP client, redirect, file mount, API documentation, or form action.
- CSP restricts scripts, styles, and connections to self; objects, frames, base overrides, and form
  actions are blocked. Responses add `nosniff`, no-referrer, no-store and frame denial.
- Assets are individual packaged resources rather than a mounted repository/artifact directory.

## Dependencies proposed for review

- Runtime extra: `fastapi>=0.115,<1`, `uvicorn>=0.34,<1`.
- API test dependency: `httpx>=0.28,<1`.
- Isolated browser-test extra: `playwright>=1.50,<2`, `pytest-playwright>=0.6,<1`.

The ranges allow compatible security and bug-fix releases. The resolved versions must be recorded
and audited after installation; this review does not claim that an unresolved range is safe.

## Static preparation evidence

- `python -m ruff format --check .`: 92 files formatted.
- `python -m ruff check .`: passed after preparation repairs.
- Strict MyPy was attempted before installing optional dependencies. It reported missing FastAPI,
  Starlette, Uvicorn, and Playwright modules, plus dependent untyped decorators; this is an expected
  unresolved dependency state, not a passing type result. One independent typed test-construction
  error was repaired. MyPy must pass after approved dependency installation.
- `git diff --check`: no whitespace errors; line-ending conversion warnings only.

## Tests requiring approval

After review, approve installation/audit of the dependency set and execution of:

1. `tests/test_dashboard_catalog.py` — manifest, path, provenance, safe projection and evidence
   relationship behavior; it invokes only the already approved deterministic lab runtime to create
   local synthetic fixtures.
2. `tests/test_dashboard_api.py` — in-process HTTP calls, security headers, Host/Origin/Fetch
   Metadata/method rejection, pagination/errors, safe payloads and packaged assets. It does not bind
   a real listener.
3. `tests/e2e/test_dashboard.py` — explicitly opens an ephemeral `127.0.0.1` listener and Chromium
   control transport, then checks empty and representative investigation/evaluation navigation,
   evidence drill-down/back navigation, failure/exclusion visibility, and clean shutdown.
4. Full existing suite, Ruff, strict MyPy, build, installed core/dashboard wheel smokes, asset
   inventory, dependency audit, raw-canary scan, and manual accessibility checks.

Suggested approval statement:

> Approved the Phase 5 manifest/path boundary, read-only API, loopback listener, optional dependency
> set, and named dashboard tests for dependency installation and test execution.

## Astra review resolution

All seven review findings were applied before runtime approval: JSON-mode contract loading, raw
canary scanning on all response surfaces, canonical run-report verification plus stronger
investigation linkage, read-time file identity guards, complete retained-projection accounting and
incremental deadlines, bounded nested pagination, and representative browser coverage with visible
evaluation failures and exclusions. Runtime validation remains intentionally pending the approval
above.

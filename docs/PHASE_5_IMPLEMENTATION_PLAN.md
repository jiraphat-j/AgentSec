# Phase 5 implementation plan — Read-only investigation dashboard

Status: **Proposed; owner approval required. Planning only; no implementation authorized.**

Prepared: 2026-09-14. Inspected checkout: `dd3dbe1` (merged Phase 4), package `0.4.0`.
This document does not approve a network boundary change, dependencies, sensitive-code execution,
CI dispatch, or merge. Existing unrelated workflow-document changes must be preserved.

## 1. Objective and current evidence

Make existing runs, detections, investigations, and policy evaluations understandable through a
local browser dashboard, using the same Python models and evidence semantics as the CLI.
SQLite remains canonical; the dashboard is a read-only projection, not another recorder.

The [roadmap](../ROADMAP.md) identifies Dashboard as Phase 5. The repository currently has:

- CLI `run`, `compare`, `rules validate`, `rules test`, `replay`, `investigate`, and `evaluate`.
- Event schemas 0.1/0.2, strict report models, bounded read-only SQLite replay, immutable Phase 4
  incidents, and `core-lab-v1` evaluation with explicit metric denominators.
- No implemented web API, frontend, dashboard dependency extra, or browser-test suite.
- Python 3.13 and Pydantic as the only current runtime dependency. The architecture draft's
  FastAPI/Next.js/TypeScript/Tailwind/graph/chart stack is a proposal, not an accepted contract.

Merge is established by the local checkout; completion evidence is not. The
[Phase 4 verification record](PHASE_4_VERIFICATION.md) still lists the broader C01–C13 matrix,
final human review, and exact-commit Windows/Linux CI as open. Its 114 passing tests and 90.81%
coverage are historical recorded results, not checks rerun for this plan. README phase status is
also stale. Resolve these records at gate G0; do not silently mark Phase 4 complete.

## 2. Scope and proposed decisions

### Included

1. Run overview and detail: identity, scenario/profile, source status, outcome, and safe policy facts.
2. Sequence-ordered timeline with event/trace filters and exact evidence navigation.
3. Alert detail distinguishing historical recorded detections from offline-derived alerts.
4. Incident detail with stages, outcome, hypothesis, remediation, and read-only `new` status.
5. Rule definitions, reported match counts, and saved positive/negative fixture-test results.
6. Existing vulnerable-versus-strict comparison, including first recorded policy divergence.
7. Evaluation charts with exact fractions, exclusions, paired outcomes, and timing limitations.
8. A small evidence-linked attack-chain diagram with an equivalent accessible table.
9. A bounded local read API, packaged browser assets, CLI startup, and security/accessibility/E2E tests.

### Excluded

No run/replay/investigate/evaluate/test execution from the browser; no uploads, rule editor,
policy toggles, approval UI, incident assignment/resolution, live tailing, automatic refresh of
source files, arbitrary queries, remote deployment, authentication/RBAC, telemetry service,
external fonts/CDNs, LLMs, Docker, database migration, or new attack scenarios.

The policy simulator is deferred: current contracts expose fixed profiles, not a safe general
permission-editing or hypothetical-evaluation API. Draft confidence scores, per-rule production
false-positive rates, and analyst lifecycle fields must not be invented to fill UI panels.

### Proposed architecture for owner approval (G1)

- Add an optional `dashboard` Python extra using FastAPI and a minimal Uvicorn installation.
  Existing CLI commands must work without the extra; import web dependencies only on demand.
- Serve packaged HTML, CSS, and small native JavaScript modules from the same local origin.
  Use semantic tables and simple SVG for diagrams/charts; no frontend framework, Node build,
  database ORM, graph library, or chart dependency in this phase.
- Add a Python Playwright/pytest browser-test extra, with browser installation isolated from
  ordinary core tests. Select and audit supported versions during implementation, before install
  or execution approval; this plan does not assert any version is vulnerability-free.
- Start one foreground, non-reloading server bound only to literal `127.0.0.1`. Default proposed
  port: 8765; permit a validated alternative port, not an alternative host. No automatic browser
  launch, subprocess, worker pool, or outbound request in product startup.
- Use an explicit operator-authored manifest to select existing artifacts. Load and validate a
  bounded snapshot before accepting requests; requests address opaque catalog IDs, never paths.
- Reuse Python report models and domain functions. The CLI and API share a local read-model
  service; existing CLI commands do not become HTTP clients or gain a server dependency.

This is a deliberate smaller alternative to the draft Next.js stack. If the owner prefers that
stack, revise this plan and dependency/testing/package sections before implementation.

**Security decision:** the dashboard listener is an opt-in operator presentation surface, not a
new agent capability or replacement for `LabHttpSinkAdapter`. Nevertheless it opens a socket and
requires an accepted ADR and threat-model amendment. Core scenario, compare, replay, investigation,
and evaluation remain socket-free. Localhost is not authentication: other local processes/users
may read the selected sanitized data. G1 must explicitly accept a trusted single-user-machine
scope. Otherwise stop and redesign, rather than add authentication implicitly.

An offline exported HTML viewer would retain an entirely socket-free product but would not deliver
the proposed HTTP API. It is an alternative requiring a scope decision, not an automatic fallback.

## 3. User workflow

```text
Existing CLI generates artifacts (separate action, subject to its review gates)
  -> operator lists selected artifacts in a manifest
  -> dashboard validates and captures a read-only snapshot
  -> browser overview -> run -> timeline -> alert -> incident -> exact evidence
                     -> comparison / evaluation / saved rule-test views
```

Stop and restart explicitly to load newer artifacts. The browser never triggers the agent or
rewrites evidence. An empty valid manifest shows an empty-state explanation and CLI instructions.

Proposed startup contract (not an implemented command):

```text
agentsec dashboard --manifest <local-manifest.json> [--port 8765]
```

Invalid configuration/input exits 2; startup/read/resource/bind failure exits 1; normal shutdown
exits 0. Missing optional dependencies produce a sanitized installation hint. Existing command
defaults, exit meanings, report locations, and artifact schemas remain unchanged.

## 4. Data and API contracts

### 4.1 Explicit artifact catalog

Define strict `dashboard-manifest-v1` with a schema version and typed entries. Each entry has a
unique bounded catalog ID, a closed artifact kind, a relative file path, and explicit relationships:

- Event source: SQLite path plus explicit run ID, as required by the existing replay reader.
- Run report, comparison, replay, investigation, evaluation, rule definition, or rule-test report:
  path plus references to catalog source/report IDs when available.
- Paths resolve only beneath the manifest's directory. No recursive directory discovery, zip
  import, report-provided path following, or arbitrary filesystem browsing.
- Reject absolute/drive-relative/UNC/device paths, `..`, alternate data streams, ambiguous encoded
  paths, symlinks/junctions/reparse-point traversal, and non-regular files. Verify resolved targets
  and file identity at read time; document the residual race risk on a compromised local host.
- Evaluation/comparison `relative_directory` and report links are untrusted descriptive fields,
  never permission to open a file. Link children only through explicitly registered catalog entries
  and matching identities. Duplicate run IDs across sources must not collapse into one run.

Unknown fields/versions, duplicate JSON keys, non-finite numbers, malformed text, type coercion,
and invalid identities fail validation. Missing optional linked evidence is a visible unavailable
state; a supplied but contradictory link is invalid, not silently ignored.

### 4.2 Canonical evidence and provenance

Read SQLite through the bounded read-only/query-only replay path, never `EventStore` construction.
Capture once; requests operate on immutable safe projections without reopening source paths.
Use existing fingerprint serialization without changing its version or algorithm. Validate an
investigation against its exact cutoff, snapshot, run/trace, event ID, and sequence; later appended
terminal events alone must not make a valid cutoff snapshot appear contradictory.

Every alert, stage, incident, and outcome reference must resolve to that captured snapshot before
receiving a verified evidence link. Existing Pydantic parsing alone is insufficient: for example,
incident validators enforce shared identities but do not prove every reference resolves to a real
timeline event. Add explicit read-boundary relationship checks, not a UI inference.

Expose provenance as `verified_against_source`, `report_only`, or `invalid`. Report-only data may
be displayed as reported, with a persistent unverified-source label and no verified drill-down.
Do not pool it into verified overview totals. Invalid data is quarantined with a sanitized reason;
invalid manifest/security/resource conditions abort startup. Source absence is never prevention.

For legacy reports without snapshot fingerprints, compare supported facts and run-qualified
references against the selected source; label the narrower verification basis, never invent a
historical digest or claim authenticity. Unsupported legacy report formats get an explicit
unsupported state; retain existing 0.1/0.2 event-reader compatibility without fabricating fields.

Use explicit allowlisted safe projections, not raw payload JSON, Markdown rendering, document
text, tool bodies, or source dumps. Reject the known raw canary after JSON decoding as well as
before serialization. Unknown arbitrary secrets cannot be reliably detected: arbitrary imported
data is not made safe by a known-canary scan. Document use with reviewed synthetic lab artifacts.

### 4.3 Read API v1

All routes are GET-only (safe HEAD for assets if needed), under `/api/v1`; no mutations or downloads
of source files. Use bounded opaque URL-safe catalog IDs rather than long detection stable keys.

| Route family | Read contract |
|---|---|
| `/catalog` | Snapshot-local IDs, artifact kind, provenance, safe validation issues |
| `/runs`, `/runs/{id}` | Safe summaries and selected run detail |
| `/runs/{id}/events` | Sequence-ordered, paginated safe timeline; exact trace/type filters |
| `/runs/{id}/events/{event_id}` | Resolved safe event detail within the selected source |
| `/investigations`, `/investigations/{id}` | Existing investigation semantics and safe projections |
| `/investigations/{id}/alerts/{alert_id}` | Rule/category/version and qualified evidence |
| `/investigations/{id}/incidents/{incident_id}` | Immutable incident and qualified evidence |
| `/comparisons`, `/comparisons/{id}` | Existing paired policy evidence and divergence |
| `/evaluations`, `/evaluations/{id}` | Existing metrics, child states, exclusions, timing, pairs |
| `/rules`, `/rule-tests/{id}` | Definitions and historical saved fixture results; never run tests |

List/nested-large collections use `items`, `total`, `offset`, and `limit`; default limit 50,
maximum 200. Detail endpoints summarize large children and link to paginated subcollections
(incidents, alerts, stages/evidence, rule results, evaluation children) rather than bypassing caps.
Freeze their exact schemas and paths in CONTRACTS before implementation step 3. Reject unknown
filters, invalid enums, negative pagination, unknown IDs, and unsupported methods. Use sanitized
error codes with 404 for absent IDs, 422 for invalid queries, 405 for methods, and 503 for bounded
service exhaustion. Never send exceptions, filesystem paths, SQL, or original rejected values.

Existing artifact schema versions stay unchanged. Give manifest and API projections their own
version 1.0; do not silently modify `metrics-v1`, `engine-v1`, or fingerprint contracts.

### 4.4 Presentation fidelity

- Preserve source failure/incompleteness separately from a completed offline investigation.
- Order timeline by sequence, not timestamp; identify historical derived events and direct matches.
- Keep simulated impact, prevention, correlation detection, and control observations distinct.
- Show rule ID/version and rule-set fingerprint where recorded. Old fixture results without a
  content fingerprint are historical ID/version evidence, not proof the current file passed.
- Render all five evaluation rates with numerator/denominator, eligible/excluded counts, and
  `unavailable` for a zero denominator; distinguish restricted paired prevention from all-attack
  prevention. Never average displayed percentages or treat missing children as zero outcomes.
- Keep recorded historical latency separate from local processing duration; show exclusion reasons.
- Diagrams use only recorded stage/evidence relationships. Sequence is not proof of causation;
  label hypotheses and never add inferred cross-run or cross-trace graph edges.
- No global benchmark aggregates across unrelated suites/rule sets; overview counts identify their
  selected scope and separate artifact counts from run counts to avoid double counting.

## 5. Security and resource controls

Before serving, enforce a 64 KiB manifest, at most 256 entries and 64 selected runs, at most 256 MiB
total selected file bytes, existing 64 MiB/10,000-event SQLite limits, existing per-report 1 MiB
and per-rule 64 KiB bounds, and at most 64 MiB serialized safe projection data. Bound total captured
events to 100,000 and startup to a cooperative 30-second deadline with existing SQLite query-work
limits. Check during accumulation, not after allocating the entire catalog. These are proposed
ceilings, not measured performance guarantees; any increase requires review and boundary tests.

Serve at most 1 MiB per JSON response, limit concurrent requests to 8 and request processing to
bounded in-memory work, and cap query length to 2 KiB. Oversized detail requires pagination, not
silent truncation. A bound failure must not look like a valid empty dataset or successful import.

Network/browser controls require focused human review:

- Literal loopback bind only; validate exact Host/port and reject untrusted Host/Origin headers.
  Reject cross-site API requests using a defined Fetch Metadata policy; no permissive CORS.
  Specify missing-header handling and test real browsers and in-process clients before signoff.
- No external assets, outbound API, WebSocket, redirect destination, or browser-triggered runtime.
  Packaged assets are an allowlist, not a mount of the artifact or repository directory.
- CSP: self-only scripts/styles/connect; no inline/eval scripts, objects, frames, or base override.
  Add `nosniff`, no-referrer, and no-store for evidence responses; disable remote API-doc assets.
- Render untrusted strings as text nodes; no `innerHTML`, executable templates, unsafe SVG/URL
  injection, automatic external links, or raw Markdown-to-HTML. Error/log output is redacted.
- Keep the normal core socket/DNS guards intact. Only explicitly approved dashboard/browser tests
  may open their local listener and browser-control transport; do not disable guards globally.
- No live writes or automatic migrations; source file hashes/metadata remain unchanged after
  startup, browsing, failure, and shutdown. Hash checks establish change detection, not custody.

## 6. Affected files (planned, not created by this planning task)

| Files | Expected change |
|---|---|
| `docs/adr/ADR-008-phase-5-read-only-dashboard.md` | Proposed architecture, optional listener boundary, single-user assumption, stack decision; accepted only with approval |
| `DECISIONS.md`, `THREAT_MODEL.md`, `docs/agents/security.md` | Record accepted decisions and narrowly scoped presentation/test network exception |
| `docs/CONTRACTS.md` | Manifest/API/provenance/pagination/error/compatibility definitions |
| `src/agentsec/dashboard_models.py` | Strict manifest and safe API projection models, closed versions and caps |
| `src/agentsec/dashboard_catalog.py` | Confined artifact loading, source capture, cross-reference/provenance validation |
| `src/agentsec/dashboard_service.py` | Shared immutable read queries and pagination; no scenario execution |
| `src/agentsec/dashboard_api.py` | Optional HTTP adapter, host/origin policy, response/security controls |
| `src/agentsec/resources/dashboard/index.html`, `styles.css`, `app.js`, `views.js` | Packaged accessible UI, local navigation, safe text rendering and small charts |
| `src/agentsec/cli.py`, `constants.py` | Lazy dashboard command startup and fixed dashboard bounds |
| `pyproject.toml` | Optional runtime/browser-test extras, asset packaging, E2E marker; proposed release 0.5.0 only at release gate |
| `tests/test_dashboard_catalog.py`, `test_dashboard_api.py`, `test_dashboard_security.py` | In-process validation, parity, safety and resource regressions |
| `tests/e2e/test_dashboard.py`, `tests/e2e/conftest.py` | Explicitly selected approved browser tests and local-server lifecycle |
| `tests/fixtures/dashboard/` | Reviewed synthetic valid/invalid catalogs and inert hostile text; no real secrets |
| `.github/workflows/ci.yml` | Preserve human-only dispatch; add explicit optional-dependency and browser jobs on Windows/Linux |
| `examples/contracts/dashboard-manifest-v1.json` | Bounded synthetic manifest demonstrating explicit relationships |
| `README.md`, `ROADMAP.md`, `docs/DASHBOARD.md` | Accurate phase status, install/start/stop, manifest preparation, limitations and demo walkthrough |
| `docs/PHASE_4_VERIFICATION.md` | G0 evidence reconciliation only; do not rewrite historical results |
| `docs/PHASE_5_SECURITY_REVIEW.md`, `docs/PHASE_5_VERIFICATION.md` | Concrete diff review and acceptance evidence with exact revisions |

Reuse `replay.py`, `evidence.py`, `models.py`, `incident_models.py`, `evaluation_models.py`, and
`rule_models.py` as existing contract providers. A narrowly needed pure read-helper extraction
from them requires parity tests and explicit diff review. Changes to adapters, gateway, policies,
runner behavior, rule semantics, metrics, or report writers are not planned. If an actual upstream
defect blocks verified rendering, record a separate prerequisite fix and ask approval; never mask
it with frontend logic or quietly fold it into Phase 5.

## 7. Implementation order and dependencies

1. **G0/G1 prerequisites:** reconcile Phase 4 evidence; obtain scope/architecture approval. Record
   ADR-008 and exact dependency proposal. No server or browser execution yet.
2. **Freeze contracts:** manifest examples, API schemas, legacy support table, provenance and error
   states, resource ceilings, host/origin policy, and acceptance fixtures. Review before UI work.
3. **Read-model boundary:** implement catalog, strict imports, source relationship validation,
   safe projections and pagination. Keep constructors/imports free of runtime/server effects.
4. **API/CLI adapter:** lazy optional startup, packaged assets, bounded GET routes and security
   middleware. Prepare concrete sensitive-diff review and test inventory for G2.
5. **UI:** implement run/timeline/evidence navigation first, then alert/incident details, then
   rules/comparison/evaluation and evidence-linked diagrams. No alternate outcome calculations.
   Fixture-only UI development may overlap API work once contracts are frozen.
6. **G2 approved verification:** run targeted tests, then core regression, browser/accessibility,
   clean installed-wheel and source-distribution checks, dependency audit, and resource probes.
   Stop and re-review material changes to a previously approved sensitive surface.
7. **G3/G4 handoff:** complete evidence matrix, owner review, human-dispatched exact-commit CI,
   documentation reconciliation and release decision. Commit/push/PR/merge only when requested.

## 8. Acceptance and test matrix

Each row needs a test name/command, exact revision, observed result, and retained evidence in the
Phase 5 verification record. A green suite alone does not close untested rows.

| ID | Observable acceptance criteria | Required verification |
|---|---|---|
| C01 | Core installs and all existing commands work without web/browser extras; imports open no sockets | Clean core-only wheel smoke; existing tests; import guards |
| C02 | Dashboard starts only on approved loopback/port, stops cleanly, and does not launch the agent or browser | CLI valid/invalid/missing-extra/bind-conflict tests; listener inspection; runtime-call spies |
| C03 | Catalog admits supported bounded artifacts; unsupported/invalid/report-only states are explicit | Valid run/comparison/replay/investigation/evaluation/rule-test fixtures; malformed/unknown/duplicate-key/type/finite-value tests |
| C04 | No path escape, arbitrary host read, recursive scan, or source modification | Windows drive/UNC/ADS/junction and Linux symlink tests; encoded traversal; source-before/after comparisons; swapped-file and missing-source tests |
| C05 | Every verified evidence link resolves exact snapshot/run/trace/event/sequence; cutoffs remain correct | Same event ID in different sources; forged/missing refs; wrong fingerprint; later terminal event; multi-trace and legacy compatibility cases |
| C06 | Run, alert, incident, comparison and rule displays preserve CLI facts and immutable states | API-to-model parity fixtures; zero-match; strict prevention; benign; failed/incomplete; report-only; stale rule-test identity cases |
| C07 | Evaluation charts preserve exact fractions, exclusions, pairs and latency basis | All five metrics, zero denominator, partial suite, assertion failure, absent child, restricted pair, and invalid timing fixtures; DOM assertions |
| C08 | Hostile content cannot execute, navigate externally, fetch external resources, or leak raw canaries | Script/HTML/SVG/URL/Markdown/control-character fixtures; encoded canary scan across API/DOM/logs/errors; browser request interception |
| C09 | Cross-site/host requests and mutations rejected; selected files never exposed as static content | Host/Origin/Fetch Metadata/CORS/method matrix; CSP/header tests; `/../`, raw-file and API-doc probes |
| C10 | Input, work, response and concurrency limits fail explicitly without partial-success claims | At-limit/over-limit tests for every section 5 bound; huge nested evidence/query; startup failure cleanup; request saturation |
| C11 | Overview -> run -> alert -> incident -> exact evidence works without mouse; filters and back navigation retain context | Chromium E2E on Windows/Linux; keyboard focus/order, landmarks, names, tables, status announcements, no color-only meaning |
| C12 | Charts have equivalent readable tables; empty/error/loading/unavailable states work at narrow width and 200% zoom | Manual accessibility checklist and browser assertions; normal/zero-match/partial/report-only walkthroughs |
| C13 | Wheel/sdist include all UI assets; installed dashboard works outside the checkout without network assets | Clean isolated build/install; approved local browser smoke; no repo-relative resources; dependency audit; exact-commit CI |

Browser runtime traffic must be confined to the chosen loopback application origin and the
test tool's explicitly documented local control transport. Block external browser requests and
record attempted violations. Dependency/browser downloads are setup, separate from the offline
runtime claim, and require the normal network permissions.

## 9. Verification commands and evidence policy

After G2, use the repository's Python 3.13 environment. Final command details depend on approved
extras, but the intended gates are:

```text
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest -m "not dashboard_e2e" --cov=agentsec --cov-report=term-missing --cov-fail-under=90
python -m pytest tests/e2e -m dashboard_e2e
python -m build
python -m pip_audit
```

Configure browser tests to collect safely without importing optional packages in the core-only
environment. Audit the core, dashboard, and test environments, stating any skipped distributions.
Maintain Python strict typing and at least 90% coverage; do not exclude new modules to meet the
threshold. Native JavaScript behavior is covered by browser tests and reviewed for unsafe DOM
operations; Python coverage does not measure JavaScript coverage.

Use a clean core-only wheel install and a separate dashboard-extra wheel install. Run the approved
smoke from outside the checkout. Verify required assets in both wheel and sdist. Record manual
accessibility results separately from automated checks. Preserve `workflow_dispatch`; a human
starts CI for the exact reviewed revision. Do not claim CI passed from local results.

## 10. Approval gates and completion

| Gate | Required decision/evidence | Stop condition |
|---|---|---|
| G0 — Prior-phase readiness | Record Phase 4 C01–C13 coverage, complete-diff human review and exact-commit Windows/Linux CI evidence, or explicit owner-approved scoped deferrals with impact | No Phase 5 implementation while readiness is unresolved; evidence-integrity blockers cannot be hidden by the UI |
| G1 — Design and dependency approval | Owner accepts read-only scope, manifest workflow, optional FastAPI/minimal JS stack, narrow listener exception and single-user residual risk; ADR/threat model reflect it | Different framework, all-socket-free requirement, remote access, auth or simulator request requires a revised plan |
| G2 — Sensitive implementation review | Human reviews concrete paths/import/query/fingerprint/HTTP/browser-test changes and dependency versions; explicitly approves named tests and local socket/browser execution | Plan approval and older Phase 4 hashing approval are not execution approval; changed sensitive code needs renewed review |
| G3 — Acceptance evidence | C01–C13 complete, local quality/build/audit/browser/accessibility evidence, no unexplained scope changes | Missing evidence remains open even if tests pass |
| G4 — Integration/release | Final human review and exact-commit Windows/Linux CI links; explicit commit/push/merge and version decision as requested | Do not auto-merge, infer approval, or mark complete solely because a branch merged |

Completion means an installed, optional, read-only dashboard demonstrates the critical flows with
verified provenance and visible limitations, leaves canonical sources unchanged, retains every
core safety invariant outside the approved presentation boundary, and has recorded evidence for
all gates. No implementation or tests were performed by writing this plan.

## References

- [Agent workflow](agents/implementation-workflow.md), [security baseline](agents/security.md),
  [definition of done](agents/definition-of-done.md).
- [Contracts](CONTRACTS.md), [decisions](../DECISIONS.md), [threat model](../THREAT_MODEL.md),
  [locked MVP scope](../MVP_SCOPE.md), [architecture draft](../AGENTSEC_CONCEPT_AND_ARCHITECTURE_DRAFT.md).
- [ADR-001](adr/ADR-001-core-language-and-runtime.md),
  [ADR-002](adr/ADR-002-mvp-event-persistence.md),
  [ADR-003](adr/ADR-003-mvp-isolation-and-no-egress.md),
  [ADR-006](adr/ADR-006-phase-3-detection-rules-and-replay.md),
  [ADR-007](adr/ADR-007-phase-4-incidents-and-evaluation.md).
- Technical references checked for the proposed adapter/testing direction:
  [FastAPI startup/shutdown lifecycle](https://fastapi.tiangolo.com/advanced/events/),
  [FastAPI static assets](https://fastapi.tiangolo.com/tutorial/static-files/),
  [Starlette Host validation](https://www.starlette.io/middleware/),
  [Playwright Python pytest integration](https://playwright.dev/python/docs/test-runners).
  Framework features do not establish the proposed application's security; C08–C10 must prove it.

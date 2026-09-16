# Phase 5 verification record

Status: implemented local checks pass with repairs; complete C01–C13 acceptance evidence, a final
reviewed revision, Windows/Linux CI, and project-owner acceptance remain pending.

## Verification completion plan

Status: historical execution plan. The results from following it are recorded below.
It supplements the existing Phase 5 implementation plan and preserves its C01–C13 criteria.

### Objective and baseline

Finish Phase 5 by demonstrating the implemented dashboard against every acceptance criterion,
repairing in-scope failures, and recording local, human-review, CI, and integration evidence
separately. Phase 6 work and a package-version change are outside this plan.

At planning time, the inspected checkout is `2825a25` on `docs/agent-workflow`. The owner reports
that Phase 5 was merged; the merge revision and its CI results have not been independently checked
in this planning task. Existing `AGENTS.md`, implementation-workflow, and skill edits remain local
and unrelated. Earlier static results below are historical evidence, not rerun results.

### 1. Establish the revision and review inventory

- Inspect the merged PR and remote main revision through Git/GitHub CLI; record PR URL, full merge
  SHA, and whether squash/rebase changed the implementation SHA. Preserve local changes when
  preparing a clean verification checkout based on that revision.
- Reconcile stale document wording: the implementation plan describes its original pre-code
  baseline, while ADR-008 is accepted and implementation exists. Preserve history and add dated
  status updates without treating merge as test approval or acceptance evidence.
- Map the existing tests to C01–C13. Mark each row pending, failing, passed, or explicitly deferred;
  identify the exact tests and artifacts needed before executing them.
- Review the concrete sensitive files and test transport described in
  [the security review](PHASE_5_SECURITY_REVIEW.md). Reuse existing approval where its scope matches;
  the recorded commit/push approvals and Phase 4 approval do not establish Phase 5 execution approval.

### 2. Prepare dependency and test environments

After the relevant execution/setup approval, use Python 3.13 and a dedicated verification virtual
environment. Install the existing `dev,dashboard-test` extras and Chromium; install browser system
dependencies on Ubuntu through its CI setup. Record Python, OS, resolved package versions,
Playwright/Chromium versions, and dependency audit results. Setup downloads are separate from
offline product/browser runtime checks.

Create separate clean core-only and dashboard-extra wheel environments for C01/C13. Do not rely
on the development environment to prove optional dependency isolation. Record any audit skips
and their reasons; do not hide advisories by disabling checks. Check that optional test skips do
not make a dashboard test run appear successful without collecting its required tests.

### 3. Test the loader, provenance, and resource boundaries first

Run the focused catalog/API tests, add missing behavioral regressions, and repair demonstrated
failures. Keep existing report, fingerprint, rule, and metric semantics unchanged.

| Criteria | Required cases and evidence |
|---|---|
| C03 | Load every manifest kind using real serialized artifacts, including replay and rule definitions; test JSON tuples/enums, duplicates, non-finite values, unknown fields/versions and invalid scalar types. Resolve the plan's quarantine wording versus current fail-startup contract explicitly. |
| C04 | Confined paths, drive/UNC/ADS/encoded traversal, regular files, Windows junction/reparse and Linux symlink cases, file/parent swaps, growth, missing sources, and unchanged source bytes/metadata through startup, requests, failures and shutdown. Document residual hostile-host races accurately. |
| C05 | Exact event content, altered report facts, nested alert references and copies, timeline metadata, wrong fingerprints, omitted/forged references, duplicate IDs across sources, multiple traces, valid cutoff before later terminal events, and legacy event compatibility. |
| C06 | Compare API/display facts with canonical run, investigation, comparison, rule and saved rule-test artifacts; include benign, strict prevention, zero matches, failed/incomplete and report-only cases. |
| C10 | At/over bounds for manifest size/count, source count, selected bytes, per-file size, events, retained projections, startup time, response/query size, page size and concurrent requests. Count while accumulating; test cleanup and fixed errors. |

Specific inspection targets remain open despite the earlier “Astra resolution” wording:

- `DashboardCatalog.load` counts retained event bytes after capturing all sources; confirm and
  repair the incremental budget enforcement required by the plan.
- Large nested items can still exceed response limits. Verify pagination inside incident
  timelines/evidence and other large children, and ensure all valid data remains retrievable.
- Report-only run detail currently removes its timeline without a dedicated report timeline
  endpoint. Verify and restore a bounded retrieval path.
- Verify collection/kind matching on nested routes and reject unsupported query keys/duplicates
  consistently with the documented API contract.
- Check strict typing after dependency installation, including the catalog's reuse of `identity`
  for both a file identity and a display string. Do not suppress genuine errors.

These are source-inspection targets, not runtime results. Each fix needs a regression that would
fail on the original behavior. Material changes to sensitive boundaries require concrete review
before executing those changed paths under the repository security policy.

### 4. Complete browser behavior and security verification

Prepare synthetic fixtures through the actual manifest loader, in addition to isolated view
fixtures. The current browser test constructs catalog records directly and cannot alone establish
loader-to-browser correctness. Use bounded server readiness checks and reliable shutdown; record
console errors and test failures. Intercept browser traffic to reject and record requests outside
the selected application origin; document the browser tool's separate local control transport.

| Criteria | Required walkthrough/check |
|---|---|
| C02/C09 | Valid/invalid port, missing extras, bind conflict, foreground shutdown, fixed loopback bind, no runtime action from requests, Host including port, Origin, Fetch Metadata, methods, CORS, CSP, static traversal and API-doc exposure. |
| C07 | All five metric rates, exact fractions, zero denominators, partial suites, failed assertions, excluded children, pair eligibility and historical timing exclusions; compare DOM facts with validated reports. |
| C08 | Inert hostile HTML/SVG/script/URL/Markdown and control-character fixtures; encoded raw canaries across nested payloads, API, DOM, errors and logs; no script execution or external navigation/request. |
| C11 | Keyboard-only overview → run → alert → incident → exact evidence; more than one catalog/timeline/nested page, exact filters, Back retaining selection/filter/page/focus, and rapid navigation without stale responses replacing the current view. |
| C12 | Empty/loading/error/unavailable/report-only states, narrow viewport, real 200% zoom, labels/landmarks/table semantics, focus visibility, readable contrast and no color-only status. Record human visual checks separately. |

The current UI shows metric tables but no charts or attack-chain diagram, omits some incident
stage/remediation facts, and reconstructs detail on Back without retaining filters/pages. Complete
these existing planned capabilities with accessible table equivalents and evidence-qualified links,
or obtain an explicit owner-approved scope deferral and record the unmet criteria. Do not silently
remove acceptance requirements to make verification pass.

### 5. Run quality, packaging, and installed-product checks

Use the verification environment's Python for these commands; run from the verified checkout:

```text
python -m pytest tests/test_dashboard_catalog.py tests/test_dashboard_api.py
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest -m "not dashboard_e2e" --cov=agentsec --cov-report=term-missing --cov-report=xml --cov-fail-under=90
python -m pytest tests/e2e -o addopts="-ra --strict-config --strict-markers" -m dashboard_e2e --browser chromium
python -m build
python -m pip_audit
```

Keep the 90% Python coverage threshold without excluding new modules. JavaScript coverage is
behavioral browser evidence, not implied by the Python number. A Node syntax check is optional
when Node is already available; it is not a new product dependency.

Inspect wheel and sdist asset inventories. Install the built wheel in both clean environments and
run smokes outside the checkout with repository imports removed. The core install must support
existing commands and give a clean missing-extra hint for dashboard startup; the dashboard install
must load its packaged assets and real manifest. Check import-time socket/DNS isolation and all
existing scenario boundaries. Audit each environment separately and record wheel/source hashes.

### 6. Close local evidence, then CI and owner review

- For every C01–C13 row, record full tested SHA (plus any uncommitted diff identity), command/test,
  platform, observed outcome, evidence location, and justified exclusions. Repair failures and
  rerun affected tests, then run the final quality/regression gates on the completed revision.
- Update `.github/workflows/ci.yml` if needed to enforce 90% coverage, install the dependencies
  required by strict typing of all tests, and retain useful reports/traces on failure. Currently
  the verify job installs `dev` but strict MyPy includes browser tests, and its test command lacks
  an explicit coverage failure threshold. Verify these gaps rather than assuming green CI.
- Preserve manual `workflow_dispatch`. After authorized publication, the owner dispatches the
  final reviewed revision. Record its full SHA and all four results: Windows/Ubuntu verification
  and Windows/Ubuntu Chromium. A historical Phase 4 run is not Phase 5 evidence.
- Record final human security/acceptance review. If repair commits are merged, record the resulting
  main SHA and verify CI on that final revision before declaring completion.
- Update README/ROADMAP and this record to Phase 5 complete only after all required evidence
  exists. Record owner-approved deferrals explicitly; material missing capabilities must not be
  described as delivered. A release/version bump is a separate decision.

### Affected files during future execution

- Evidence/status: this file, `PHASE_5_SECURITY_REVIEW.md`, dated status in
  `PHASE_5_IMPLEMENTATION_PLAN.md`, `README.md`, `ROADMAP.md`, and `DASHBOARD.md`.
- Tests: `tests/test_dashboard_catalog.py`, `tests/test_dashboard_api.py`,
  `tests/e2e/test_dashboard.py`; add focused security/resource tests, browser fixtures, or shared
  test helpers where needed.
- Repairs only as demonstrated: `src/agentsec/dashboard_{models,catalog,service,api}.py`,
  dashboard HTML/CSS/JavaScript, and the dashboard CLI path. Update `CONTRACTS.md` when clarifying
  route/pagination behavior; update the security review for sensitive changes.
- Verification configuration: `pyproject.toml` and `.github/workflows/ci.yml` only for justified
  dependency, collection, packaging, typing, coverage, and evidence-retention corrections.
- Upstream core behavior, schema/fingerprint versions, remote hosting, authentication, mutation
  APIs, and new phases are outside scope. Escalate an upstream blocker with evidence and a scoped
  proposal rather than masking it in the dashboard.

### Approval and completion gates

Planning approval covers this document only. Future execution follows the existing G2 sensitive
implementation/setup approval in `PHASE_5_SECURITY_REVIEW.md`; reuse valid prior approval and
request renewed review only when changed sensitive scope warrants it. No additional approval is
needed merely for a routine check already covered by that execution authorization.

Commit, push, merge, and human CI dispatch remain distinct from local verification. Prior
publication approvals applied to the earlier implementation commit, not automatically to future
repair commits. The completion handoff must state which gates passed and any remaining owner
actions. This planning task installs nothing, executes no dashboard/tests, and changes no product
or CI code.

## Prepared scope

- Strict explicit artifact manifest and bounded confined loader.
- One-time read-only SQLite evidence capture and report provenance validation.
- Safe paginated API projections with fixed errors and browser security headers.
- Bounded paginated retrieval for nested investigation/evaluation collections and run timelines.
- Packaged accessible dashboard for runs, timelines, alerts, incidents, comparisons, evaluations,
  rules, and saved rule-test results.
- Optional lazy dashboard dependencies and literal loopback CLI startup.
- Focused catalog/API/browser tests, including non-empty evidence drill-down and evaluation failure
  visibility, and manual-only Windows/Linux browser CI jobs.

## Local execution evidence — 2026-09-15

- Phase 4 prerequisite closed by project-owner review and Actions run 34773243387 on merged revision
  `dd3dbe1` for Windows and Ubuntu.
- Remote `origin/main` was independently fetched at merge revision `54ca06c`; implementation
  revision `2825a25` is its ancestor with no implementation-tree difference. The results below
  apply to the local working tree based on `2825a25`, including the uncommitted verification
  repairs, and therefore are not yet exact-commit CI evidence.
- Focused dashboard catalog/API tests pass: 21 passed. Added regressions cover incremental
  projection accounting, report-only bounded timelines, strict/duplicate query rejection,
  nested routes, missing identities, filters, and invalid ports.
- Full non-browser suite passes: 135 passed and 2 browser tests deselected. Python coverage is
  90.20% (3,185 statements, 312 missed), above the enforced 90% threshold. Two third-party
  TestClient deprecation warnings remain; there are no project test failures.
- Chromium dashboard suite passes: 2 passed. It covers empty and representative navigation,
  exact evidence, an accessible incident attack chain, evaluation failure/exclusion visibility,
  metric progress/table output, retained filters/focus after evidence navigation, and rejection of
  a delayed stale view response. Pytest reported only a Windows permission warning while writing
  its cache; test outcomes were unaffected.
- Ruff format and lint pass across 94 files. Strict MyPy passes across 50 source files.
- `node --check src/agentsec/resources/dashboard/app.js` passes.
- `pip-audit` reports no known vulnerabilities; the local `agentsec-lab` project is skipped because
  it is not published on PyPI. Resolved verification versions include FastAPI 0.141.1, Starlette
  1.6.0, Uvicorn 0.53.0, HTTPX 0.28.1, Playwright 1.62.0, pytest-playwright 0.9.0, pytest 9.1.1,
  MyPy 1.20.2, Ruff 0.16.6, and pip-audit 2.10.1.
- The final wheel and sdist build successfully with setuptools 84.0.0 and contain `index.html`,
  `styles.css`, and `app.js`. SHA-256: wheel
  `a37950c5b805ece350375a6ecccd1e2e861a80bca72dcbb63442bd2df81e09a6`; sdist
  `5d333bbe69ebbb5912397a75b0ede773aa4584582fdc65312475476d11aafd24`.
- Exact-wheel clean-install smokes pass outside the source package: the core-only environment has
  no FastAPI, reports version 0.4.0, and returns exit 2 with the documented dashboard-extra hint;
  the dashboard environment loads an empty manifest, constructs the application, and reads all
  packaged assets including the final attack-chain UI.
- Repairs made during verification include package-version alignment, a deterministic missing-extra
  error, typed middleware/catalog fixes, incremental resource-limit enforcement, strict API query
  and collection-kind handling, a bounded report-only timeline route, retained navigation state,
  stale-response suppression, accessible incident/evaluation visuals, added tests, and explicit CI
  coverage/dependency gates.

## Remaining gates

1. Review and commit the verification repairs; commit/push are not authorized by this test run.
2. Complete the acceptance cases not yet demonstrated by the current suite: loader-to-browser
   fixtures, hostile HTML/SVG/script/URL/control-character DOM cases, browser interception of
   external requests/navigation, the complete C10 at/over-limit and concurrency matrix, and the
   platform-specific C04 link/reparse and source-mutation cases.
3. Run the manual keyboard, narrow-width, real 200% zoom, focus, and contrast checklist. Automated
   accessibility assertions pass, but this human visual gate has not been claimed.
4. Push the reviewed commit and human-dispatch Phase 5 CI. Record Windows and Ubuntu results for
   both verification and Chromium jobs against the same final full SHA.
5. Complete project-owner security/acceptance review of the final diff and CI evidence. Only then
   mark Phase 5 complete in README and ROADMAP.

The results above establish only the cases named in their tests and smoke checks. They do not yet
establish complete C01–C13 coverage. No owner-approved deferral is currently recorded.

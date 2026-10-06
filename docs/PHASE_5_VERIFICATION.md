# Phase 5 verification record

Status: the latest test-only capture-boundary batch passed 446 non-browser tests at 92.13%
coverage on 2026-10-03. The merged C07 follow-up separately passed four Chromium checks;
complete C01–C13 acceptance evidence, a final
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

## G0 dashboard evidence extension — 2026-10-01

The owner approved continuing prior-phase evidence completion with sandbox-only execution.
The test-only isolated worktree is based on merged revision
`9649fc5fe0e580e7f736c7e6247e731e98521310`. Source/test manifest SHA-256 is
`1470545f5b093ff69e1aa206ecf137a0998f4f0b1d0484b868d9f193f3673b76` over 80 sorted
tracked/non-ignored untracked `src`, `tests`, and `pyproject.toml` paths. Full commands, file hashes,
versions, limits, failed attempts and artifact locations are recorded in the
[expanded Phase 6A G0 evidence](PHASE_6_VERIFICATION.md#expanded-phase-6b-g0-evidence-2026-10-01).
There are no product-source, packaged-fixture, dependency or CI changes in this worktree.

| Open area | Additional local evidence | Still not established |
|---|---|---|
| Loader/API/DOM parity and hostile content | A genuine manifest-loaded direct run/report reaches exact API/DOM metadata; hostile HTML/script/SVG/image/JavaScript URL/Markdown/control text stays inert; browser checks no injected nodes, script effects, navigation, popups, errors or non-origin requests; source hashes unchanged | Complete artifact-kind and encoding matrix, every failure/log path |
| Encoded synthetic credential redaction | Loader rejects Unicode-escaped canary after SQLite JSON decoding; raw canary is absent in the source-byte representation | Every artifact kind and encoding variant |
| C04 confined paths and source identity | Real Linux file and parent symlinks rejected; file identity replacement between check and open rejected | Windows junction/reparse CI and full mutation/cleanup matrix |
| C10 resources/concurrency | Actual at/over manifest 64 KiB, entries 256, sources 64, rule 64 KiB, report/response 1 MiB, query 2 KiB and page 200 tests; simulated startup 30 s boundary; eight held requests accepted, ninth rejected and capacity recovered | Aggregate input/event/projection tests use reduced caps rather than actual 256 MiB/100,000/64 MiB ceilings; startup clock is simulated; full memory/performance and matrix evidence remain open |
| Package/core optionality | Exact wheel/sdist contain all dashboard assets; clean installed core has no FastAPI and returns the dashboard extra-install hint | Current-wheel clean dashboard-extra installation was not repeated; source-sandbox browser tests are separate evidence |

Final local results on this snapshot: **213 non-browser tests passed**, four browser tests
deselected, **91.00% coverage** with the 90% gate enforced; **four Chromium tests passed**.
Ruff format (100 files), lint and strict MyPy (53 source files) passed. The staged Python dependency
audit found no known vulnerabilities; it does not cover Chromium or extracted Ubuntu libraries.
One upstream Starlette/httpx deprecation warning remains. Wheel/sdist and installed CLI smoke
passed; all attack-scenario and browser execution stayed in the networkless WSL2 bubblewrap
namespace. No Windows-host scenario/browser run occurred in this batch.

The old instruction to commit Phase 5 repairs above is historical: those repairs are already in
the merged ancestry through `5f6de2d`. The new evidence/test changes are still uncommitted.
This extension does not close every C01–C13 criterion, record a deferral, or establish manual
accessibility, exact-final-commit Windows/Ubuntu CI or final owner security/acceptance sign-off.
Phase 5 acceptance and Phase 6B G0 remain open; README/ROADMAP completion flags are unchanged.

### Later G0 continuation — correlation evidence gap

The latest non-browser run on the expanded test-only worktree returned **272 passed, eight
failed, four browser tests deselected, 91.33% coverage**. The failures concern direct correlation
accepting a wrong recorded virtual-file resource or altered source-component labels, not a
dashboard browser execution failure or demonstrated host-data access. See the
[C07 review record](PHASE_G0_C07_REVIEW.md) for reproduction, limitations and the proposed repair.
The earlier dashboard browser/package results remain historical; they were not rerun in this
continuation and do not substitute for a green latest full verification gate. No product repair,
manual acceptance, CI dispatch or publication occurred; prior-phase readiness remains unresolved.

### C07 repair verified

The owner reviewed and approved the C07 repair. The final sandbox run passed 288 non-browser
tests at 91.36% coverage and four Chromium tests; quality, build and installed-CLI checks passed.
See [the final record](PHASE_6_VERIFICATION.md#owner-reviewed-c07-sandbox-verification--2026-10-01)
for the tested snapshot and limits. The earlier eight failures are resolved, but the remaining
Phase 5 acceptance items above are still open.

### Artifact redaction and actual aggregate bounds — 2026-10-02

The owner-approved dashboard investigation repair and subsequent test-only continuation passed
**373 non-browser tests at 91.95% coverage**, four Chromium checks, quality, offline build and
clean installed-wheel CLI checks. Representative schema-valid literal/JSON-Unicode canary
contamination is rejected across all seven JSON artifact kinds; six API detail routes return
fixed errors after clean positive controls. Replay 404 is separate route-contract evidence.
Actual 256 MiB selected-input, 100,000 retained-event and 64 MiB projection accounting checks
passed without reduced constants, using repeated selected paths and synthetic temporary files.
Source hashes/bytes remain unchanged. These do not prove distinct-file/run scale or complete
all-field, hostile-content, mutation and resource-work matrices. See the
[dated Phase 6 record](PHASE_6_VERIFICATION.md#continued-artifact-and-aggregate-limit-evidence--2026-10-02)
for the exact 84-path snapshot, commands, archive hashes and sandbox bounds.
Manual accessibility, Windows reparse evidence, human-dispatched exact-commit CI and final owner
acceptance remain open. No new product/dependency/CI change or phase-completion claim is made.

### Later C07 parity findings — not a passing acceptance gate

Further unchanged-code sandbox tests confirmed twelve direct detector live/offline discrepancies.
The latest full expanded suite is 379 passed/twelve failed at 91.98% coverage; the earlier
373/four passing batch remains historical verified evidence, not complete acceptance of this
expanded matrix. No new detector repair has been implemented or executed. See the
[C07 review](PHASE_G0_C07_REVIEW.md#additional-liveoffline-parity-findings--2026-10-02)
and latest Phase 6 verification section; concrete human G2 review is required for a future repair.

### C07 follow-up — 2026-10-03

The owner reviewed and approved the concrete direct-only repair and named sandbox checks.
All twelve reproduced discrepancies now pass; final full suite has 429 passed at 92.04% coverage,
four Chromium checks and clean quality/build/installed checks. The prior failed snapshot is
historical. See [Phase 6 verification](PHASE_6_VERIFICATION.md#approved-c07-liveoffline-repair--2026-10-03)
for the exact 86-path snapshot and remaining G0/manual/platform/CI/owner-acceptance gates.

### Capture-boundary continuation after PR #9 — 2026-10-03

PR #9 is verified merged at `c165b3d203998585193711e67895e64bf4321258`; continuation uses the
existing clean managed worktree on `codex/g0-dashboard-evidence`. Public GitHub Actions queries
for reviewed head `507e1fd585bc11040ab7df1af41795eb4e63d555` and merge returned zero runs.
No CI dispatch or cross-platform acceptance is inferred from the merge.

`tests/test_dashboard_capture_boundaries.py` is test-only; product, packaged resources, browser
tests, dependencies and CI are unchanged. It supplements P5 C04/P5-03 with public-loader
positive controls and precise synthetic mutation checkpoints:

- Ten JSON cases: manifest/report post-read append, mtime change, same-byte inode replacement,
  deletion and mismatched opened descriptor. Replacement fixtures preserve bytes, size and
  nanosecond mtime while differing in inode. Wrong descriptors are rejected before any read;
  opened handles close on every tested failure. Open-descriptor replacement/deletion is Unix
  evidence; its four variants explicitly skip on Windows rather than claim sharing-mode parity.
- Four SQLite cases: post-read mtime change, same-byte inode replacement, deletion and Linux
  symlink substitution. The real reader finishes and closes before injection; tracked queries
  use read-only URI/query-only mode and contain only SELECT/PRAGMA/BEGIN. Linux symlink evidence
  explicitly skips on Windows. Windows junction/reparse checks remain separate.
- Three post-capture cases: replace/delete/append selected SQLite/JSON inputs, then compare
  service catalog/events/detail/exact-event results with captured positives while forbidding
  file reopening. Queries do not alter the injected files. This demonstrates snapshot reuse,
  not continued authentication of selected files after startup.

These deterministic hooks do not prove arbitrary scheduling races, same-inode size/mtime-
preserving edits, SQLite WAL/concurrent-writer behavior, parent-directory races, every artifact
kind/query or the complete resource/concurrency matrix. Hostile browser matrices, manual
accessibility, Windows paths, human-dispatched exact-commit CI and final owner review stay open.
The independent reviewer requested timestamp-isolated inode negatives and Unix annotations;
both test-only improvements were applied before final verification. No new product fix needed.

Final local results: **17 focused passed in 2.78 s; 446 non-browser passed, four browser tests
deselected in 60.98 s; 92.13% coverage** (3,356 statements/264 missed). Ruff format/lint and
strict MyPy (60 files) passed. One upstream Starlette/httpx warning remains. Final read-only
independent review found no blockers. Runtime used the existing bounded networkless WSL2
sandbox; no host tests or new listener/browser/build/installed-package/audit run. The latter
checks remain historical evidence for the unchanged merged product, not this new test module.
Exact manifest/commands/limits are in the
[Phase 6 record](PHASE_6_VERIFICATION.md#post-merge-g0-capture-boundary-batch--2026-10-03).

### Windows CI follow-up — 2026-10-03

Actions run 37096511551 passed Ubuntu verification and both Chromium jobs but failed Windows
verification on oversized pytest IDs and a clock-coupled linkage fixture. The owner-approved
test-only fixes preserve payload/assertion coverage and production deadlines. Local sandbox
verification passed all 446 non-browser tests at 92.13% coverage, with clean quality checks.
See [the CI fix record](PHASE_6_VERIFICATION.md#windows-ci-test-fixes--2026-10-03) for commands,
snapshot and failed-run evidence. Fresh Windows CI and other G0 gates remain outstanding.

### PR #10 CI and Windows reparse checks — 2026-10-06

The owner dispatched [Actions run 37431200546](https://github.com/jiraphat-j/AgentSec/actions/runs/37431200546)
on `ba9b9f1307affb88c617fc36e1a6cf4a4fd2c160`: Windows/Ubuntu verification and both Chromium
jobs passed. PR #10 remains open. This closes the cross-platform CI check for that branch revision,
but does not supply the skipped Windows junction/reparse evidence or manual accessibility review.

Three Windows-only public-catalog cases are now added on the same branch: a regular selected
file, a selected file symlink, and a parent directory junction. The targets and manifest live
inside one synthetic pytest temporary directory; link rejection, unchanged target bytes and
link-node cleanup are explicit. Junction setup invokes `cmd /d /c mklink /J` from a test, so its
concrete diff received human review authorization before sandbox execution. The focused Linux
sandbox suite passed (20 passed, 3 Windows-only skips); the full nonbrowser suite passed (446
passed, 3 skips, 4 browser deselections, 92.13% coverage). The Windows cases have **not** run
and are not credited to P5 C04/P5-03 until the new PR head passes Windows Actions. See the
[Phase 6 review](PHASE_6_SECURITY_REVIEW.md#windows-reparse-test-proposal--2026-10-06).
Other hostile-content/resource matrices, manual accessibility and final owner acceptance remain
open. New edits will require a fresh reviewed-commit Actions run.

## Human accessibility walkthrough — prepared 2026-10-06

### Evaluation Record
- **Tested Commit SHA:** [Full SHA of reviewed checkout]
- **Environment:** [OS/version, browser/version, desktop viewport and zoom]
- **Screen Reader:** [Name/version; record unperformed screen-reader checks as PENDING]
- **Tester / Date:** [Human tester] / [Actual review date]
- **Synthetic Fixture Manifest:** [Path to reviewed multi-page fixture manifest]

### Prerequisites and fixtures
Use existing approved sandbox loopback viewer and reviewed synthetic manifests. Fixtures must provide more than one page for catalog, timeline, and nested collections within the fixed resource limits, plus empty, loading, error, unavailable, and report-only states. If any synthetic fixture is absent, record status as **BLOCKED**; never pass missing test data. For error and loading states, use approved local browser fixture tooling without changing host network settings. For every check record PASS/FAIL/BLOCKED, the observed behavior, and a screenshot or other evidence reference; all checks below are PENDING.

### Inspection Checklist

#### C12-01: Narrow width and real 200% zoom (PENDING)
At 100% browser zoom, record a 320–390 CSS-pixel viewport. Separately repeat the desktop flow at real browser 200% zoom; record the resulting CSS-pixel viewport. Do not substitute CSS zoom or device scaling. Verify layout responds without unintended content clipping or horizontal page scroll. Intentional horizontal scrolling within `<nav>` and data tables is allowed provided controls and cell data remain operable.
*Result / Measured Width:* PENDING

#### C12-02: Contrast and status presentation (PENDING)
Sample foreground/background pairs with a color contrast analyzer. Measure `#e8f4ef` body text, `#65e6ae` accent, `#9db8ad` muted labels, and `#dc7b7b` failure borders against background `#08110f` and panel `#10201c`. Record the accessibility threshold used for each measured pair. Confirm provenance/status tags, "Reported only" rows, and failure states convey meaning through text as well as color.
*Result / Measured Ratios:* PENDING

#### C11-01: Keyboard navigation and restored state (PENDING)
Use `Tab`, `Shift+Tab`, and `Enter`/`Space`. Verify visible, unobscured focus on links, buttons, and filter inputs across all seven views: "Overview", "Runs", "Investigations", "Comparisons", "Evaluations", "Rules", and "Rule tests". Confirm "Skip to content" jumps to `<main id="content">`. On multi-page catalog, advance with "Next" / "Previous", select an item, and verify "Back" preserves catalog pagination. In "Runs", apply "Exact trace ID" and "Exact event type" filters, paginate timeline, activate "Open evidence", and verify "Back" restores focus to originating `data-evidence-id` button, filters, and timeline offset. Verify nested investigation pagination and evidence back-navigation. Activate different views rapidly by keyboard; confirm asynchronous updates settle on the latest selected view.
*Result / Evidence:* PENDING

#### C12-03: Labels, tables, and screen-reader meaning (PENDING)
Execute with a named screen reader. Verify landmarks (`<nav aria-label="Artifact views">`, `<main>`, `<footer>`) and live polite updates (`#status`). Inspect persistent filter-input labels and their accessible names; placeholders alone must not be assumed sufficient. Confirm the empty paragraph text is read within normal DOM flow rather than an asserted live announcement. Verify semantic tables contain explicit headers and captions ("Recorded fields", "Recorded attack-chain stages and evidence", "Exact metric values: <fraction>"). Ensure the attack chain image (`role="img"`) announces stages via its `aria-label`, buttons read "Event <sequence>: <event_id>", incident outcome and remediation lists are announced, and `<progress>` elements convey fractional values or "Unavailable". Confirm `report_only` provenance stays visibly unverified and "Reported only" timeline rows offer no verified evidence drill-down. Read comparison outcomes/divergence and evaluation progress alongside exact-value tables; zero denominators must remain unavailable, not become zero.
*Result / Evidence:* PENDING

#### C12-04: Empty, loading, error, and unavailable states (PENDING)
Use each prepared fixture and the approved local browser fixture controls. Inspect the empty explanation and selected-count announcement; loading status; "Unable to load view" and "The requested view is unavailable." after a failed request; and disabled or unavailable evidence references. Check focus and readable explanations at narrow width and 200% zoom, including report-only timelines. Record missing fixtures as BLOCKED.
*Result / Fixture / Evidence:* PENDING

### Handoff and G0 boundary
All failures remain open findings under G0. Final G0 completion requires successful full-SHA Windows and Ubuntu CI runs alongside formal human owner acceptance, which remain independent of this manual walkthrough.

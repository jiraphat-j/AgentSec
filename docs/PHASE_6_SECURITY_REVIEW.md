# Phase 6A security review

Latest state (2026-10-03): **The owner approved the concrete C07 follow-up and its named
sandbox execution. Applied source matches that proposal; 429 non-browser checks, four Chromium
checks, quality/build and installed-package checks pass.** The twelve new parity failures are
repaired. Final owner full-diff acceptance and remaining G0/CI gates stay open.
Earlier approvals/results below do not establish review or execution of this changed diff.

Status: **C11 repair owner-approved; C02 test execution was owner-authorized after assistant
review, and focused, full non-browser, installed-package, and Playwright checks passed in a
networkless sandbox. Final owner full-diff review and acceptance remain open.**

## Reviewed scope

- Closed schema 0.2 direct-prompt scenario and packaged fixtures only.
- Controller-generated `agent.context.prompt_added` metadata only; no prompt body is persisted.
- Existing virtual file adapter and `lab://exfiltration-sink`; no socket, DNS, subprocess, host-path,
  dependency, or policy-permission change.
- `risk-v2` accurately labels direct prompt context. `policy-v1` strict hard-denial behavior remains
  unchanged.
- Closed `ASL-CORR-003` live/declarative correlations and safe dashboard projection fields.

## Authorization and evidence

The owner authorized Phase 6A attack-scenario tests only inside a sandbox. Runtime tests and
installed CLI runs used a networkless bubblewrap namespace with the repository mounted read-only;
the package build used a disposable overlay. Setup downloads and the dependency audit had no
repository mount. On 2026-09-27 the owner separately authorized trying the dashboard browser checks
outside the sandbox. Two synthetic dashboard tests passed on Windows with a page-request guard
allowing only 127.0.0.1. Browser-process egress was not OS-blocked; no attack scenario ran on the
host. The [verification record](PHASE_6_VERIFICATION.md) lists both sets of results. This narrow
authorization does not extend to unrestricted host scenario execution or integration.

On 2026-09-27 the owner directed the full sensitive G2 rerun to an isolated sandbox. The focused
and full suites, quality checks, build, installed-wheel flows, and dependency audit passed there.
However, a forged manifest-loaded `agent.context.prompt_added` event with arbitrary `prompt_id`
text passed validation and reached the dashboard API. A genuine packaged direct run stayed
redacted. C11 remains open; fix and human review are required before acceptance.

## C11 repair reviewed by owner

- `encode_safe_projection` rejects projected `prompt_added` events unless their prompt ID is one
  of the three packaged fixture IDs and source, trust, and delivery channel exactly match the
  Phase 6A contract. It also rejects an invalid direct `run.started` fixture. This covers
  manifest-loaded sources and directly constructed catalogs through the existing fixed 503 API
  error, without adding a listener, egress path, dependency, or writable dashboard action.
- New regression tests cover forged prompt fields, direct fixture IDs, source immutability, fixed
  API errors, and valid closed metadata. At submission for owner review, only formatting, lint,
  typing, and diff checks had run on this changed snapshot.
- This is projection validation, not proof that arbitrary imported event-envelope strings are
  authentic or harmless. That residual boundary remains for final acceptance review.

On 2026-09-28 the owner approved this concrete repair and the sandbox-only G2 rerun. The focused
dashboard suite passed 28 tests; the full non-browser suite passed 150 tests with 90.23% coverage
and one skipped browser test. The offline wheel/sdist build and installed CLI smoke passed. The
direct-prompt browser DOM/request check remains open, as do exact-commit CI and final acceptance.

On 2026-09-29 the owner requested Playwright. Three dashboard browser tests passed inside a
networkless WSL2 bubblewrap namespace, including a new direct-prompt DOM redaction and loopback
request check. A bounded server-readiness wait was added to the browser test after an observed
startup race; production source was unchanged. Chromium required omitting the incompatible
per-process virtual-address limit; the WSL VM memory ceiling and other sandbox bounds remained.
Playwright and its browser were staged outside the repository, and the staged Python packages
passed `pip-audit`. Manual accessibility, exact-commit CI, and final full-diff review remain open.

## Mandatory reviewer checks

1. Confirm ToolGateway changes do not relax path, destination, size, tool-count, or policy checks.
2. Confirm raw prompt, marker, fake canary, and tool body cannot enter persisted events, reports,
   dashboard projections, logs, or errors.
3. Confirm direct fixtures cannot select adapters, profiles, destinations, output paths, or imports.
4. Review the final diff, browser sandbox limitation, and remaining manual accessibility evidence
   before final acceptance.

**⚠️ Security Sensitive: Requires Mandatory Human Review.**

## New C02 resource-loader review request, 2026-09-29

The loader now limits scenario JSON to 16 KiB and reads scenario/document/prompt bytes only up to
their cap plus one byte before UTF-8 decoding. Scenario JSON rejects duplicate keys and non-finite
values, and embedded scenario IDs must match the exact packaged ID requested. Regression cases
use fake packaged resources; they have not been executed. Review the compatibility effect on the
legacy document/scenario path, packaged resource opening in wheel and sdist, fixed error behavior,
and whether malformed or substituted resources fail closed. Only Ruff format/lint, strict mypy,
and diff checks had passed before runtime execution. The preceding G2 results were not inherited;
the owner separately authorized this execution on 2026-09-30. The renewed sandbox results and
remaining C02 caveat are in the [verification record](PHASE_6_VERIFICATION.md).

## C07 prepared repair review request, 2026-10-01

The direct live detector and offline rule have a prepared diff requiring exact virtual secret
resource and canonical context/read/sink components. Direct fixtures include the resource;
sixteen unexecuted regressions cover negatives, positives, interleaving and indirect compatibility.
Rule version 1 is retained provisionally as a documented C07 correction, not a finalized
compatibility decision. Review stricter imported-evidence matching and changed rule content/
fingerprint, or require coordinated version updates before execution. No gateway, policy, adapter,
risk, hashing algorithm, tool, socket/process permission, schema, dependency, old-suite or CI change.

Ruff format/lint, isolated strict MyPy (55 files), diff and JSON structure checks passed. No
changed-runtime command ran. The request to proceed without owner review is not recorded as
satisfying the mandatory concrete-diff human-review gate. A human reviewer must inspect the
files and prepared manifest in the C07 record and sign off before the named sandbox tests run.

The owner subsequently confirmed they reviewed this repair and approved it on 2026-10-01.
The source/test manifest was verified unchanged before execution. This approves the named
sandbox-only C07/regression/package/browser checks and the disclosed version-1 correction;
it does not authorize publication, CI dispatch, further sensitive changes or phase acceptance.

Following approval, the focused sixteen C07 tests passed; the final suite passed 288 tests at
91.36% coverage and four Chromium checks passed separately. Only the expected full-ruleset golden
vector required alignment after the first regression run; sensitive code remained the reviewed
snapshot. The legacy rule/suite/snapshot vectors stayed unchanged. Quality/build/clean installed
CLI checks passed in the documented networkless namespace. Remaining G0/G3/G4 criteria and final
full-diff review are not accepted by this result; see the latest verification section.

## G0 dashboard repair review — 2026-10-02

**Security-sensitive: review required before execution.** The owner's continuation approval
covers remaining sandbox G0 tests, not execution of a newly changed dashboard validation surface.
The current diff is based on merged PR #8 (`0c3f151177d94b97c12548a5410b840afb1a4c22`).

Two bugs reproduced under both direct profiles: the dashboard rejects genuine investigation
timeline metadata as missing prompt payload, and the linked-report verification helper accepts
a declared cutoff beyond the last captured event. The expanded pre-repair suite returned
322 passed/four failed; its hash and exact commands are in the verification record.

Prepared change in `src/agentsec/dashboard_catalog.py`:

- Keep the existing exact prompt-payload validator whenever `payload` is present. Without one,
  accept only the existing strict `TimelineEntry` model: bounded reference/timeline metadata,
  required fields, strict types, no unknown fields. Malformed or arbitrary no-payload prompt
  dictionaries still fail. This permits metadata-only timelines, not prompt text or HTML.
- Require an investigation's declared cutoff to equal the actual last sequence of the selected
  source prefix. Fingerprint/reference/nested-alert/timeline checks remain unchanged.

Review the metadata-only exception, malformed/extra-field negatives, the unchanged canary scan,
and cutoff behavior for completed/failed/incomplete prefixes. Report-only artifacts retain their
explicitly narrower provenance; this does not authenticate imported reports or source labels.
No gateway/policy/adapter/detector/risk/hash/schema/resource/dependency/listener/CI change.

`tests/test_direct_evidence_boundaries.py` has 43 prepared cases. Five extra projection negatives
cover missing evidence, unknown raw-prompt field, invalid event payload, bad reference sequence
and an arbitrary no-payload event dictionary. No test/scenario/browser/build/installed CLI ran
after this product edit. Static checks only passed; current manifest is
`8342ed5f7ca6c13038f2073f2565cad5a8930bf7a4f9952c692a866789ac9866` (83 paths).

Requested execution after human review: the new module, existing dashboard catalog/API tests,
full non-browser coverage, existing four Chromium checks and offline package/installed CLI
checks, all in the previously approved networkless sandbox. Approval does not authorize host
scenario execution, new dependencies, CI dispatch, commit/push, merge or Phase 6B implementation.

The owner approved this concrete review and the requested sandbox rerun on 2026-10-02.
The prepared manifest was recomputed and matched before execution. This scoped G2 approval
does not close the remaining G0/acceptance gates or authorize publication/CI dispatch.

The approved rerun passed 71 focused checks, all 331 non-browser tests at 91.65% coverage,
four Chromium checks, quality/build and clean installed-package checks. Both installed direct
profiles accept genuine investigations and reject non-resolving cutoffs without source writes.
The reviewed source/test manifest stayed unchanged; no extra runtime change was made. Results,
archive hashes and isolation limits are in the latest verification section. Remaining G0,
manual accessibility, cross-platform CI and final full-diff acceptance are still open.

## New C07 parity review prerequisite — 2026-10-02

The owner authorized committing/pushing the approved dashboard batch and continuing ordinary
workflow with a sub-agent reviewer. Commits `df084a0` and `eec09e9` were pushed; the latter passed
373 non-browser checks, four browser checks, quality/build and installed-package checks.
No final owner acceptance, human CI dispatch or merge is inferred from that authorization.

Eighteen new test-only cases against unchanged sensitive code found twelve live/offline detector
discrepancies: later valid chains are hidden by earlier nonmatching candidates, missing digests
match live, and unsupported event versions match live. The independent reviewer confirmed the
findings. Canonical snapshot validation already rejects missing required digests; do not claim
a generated-run host/secret leak or invalid-snapshot acceptance. Details and the direct-only
bounded repair proposal are in the [C07 record](PHASE_G0_C07_REVIEW.md#additional-liveoffline-parity-findings--2026-10-02).
Full regression now has 379 passed/twelve failed; the new module/findings remain local.

No detector repair has been implemented. Prepare its exact code and updated resource/selection
semantics for **human G2 review** before executing, building or testing changed sensitive code.
Sub-agent review is supplemental, not mandatory human sign-off. Historical approvals remain
scoped to their concrete earlier diffs. No CI/dependency/network/policy/gateway change is proposed.

### Concrete C07 repair proposal — implementation blocked pending G2

The owner asked to continue. The source-patch attempt was blocked by the tool safety reviewer
because this new sensitive detector/resource-loading diff lacks concrete human G2 approval.
Git confirms no detector/resource-loader source changed. The complete **review-only code proposal**,
compatibility choices and named sandbox checks are now in the existing
[C07 review](PHASE_G0_C07_REVIEW.md#concrete-repair-proposal-for-g2--review-only-2026-10-02).
Review shared bounded direct evaluation, fixed packaged-rule loading, input/work-limit exceptions,
deterministic dedup-key-first result selection and closed direct configuration. Historical indirect
behavior and rule bytes/version/fingerprint remain unchanged by the proposal. Nothing in the
proposal is runtime-tested or applied; the latest runtime result is still 379 passed/twelve failed
against unchanged product code. Approval is requested to apply/prepare it and authorize the named
sandbox checks after the prepared diff is confirmed to match the review. No source-patch retry,
workaround, changed-runtime execution, commit/push/merge or CI dispatch occurred this turn.

### Concrete C07 follow-up approved and verified — 2026-10-03

The owner responded explicitly approving application of the concrete proposal and continuation
with its named sandbox checks. The detector/resource-loader implementation matches the reviewed
code; the independent reviewer found no blockers after targeted regression improvements.
Fresh direct selection is dedup-key-first after complete bounded enumeration. Configuration,
fixed-rule loading and exhaustion fail closed only for fresh evaluation; recorded-result reuse
and missing alert/incident recovery still bypass fresh checks, as reviewed and tested.

The final 86-path source/test manifest is
`af80952ae4f8f5ebbaceaf7290cfb3698ab87d407ac88a2734f5d327fec03eb1`.
All 429 non-browser checks (92.04% coverage), four Chromium checks, quality, offline build and
fresh core-only installed-package checks pass. Exact commands, archives and resource limits are
in the [dated verification record](PHASE_6_VERIFICATION.md#approved-c07-liveoffline-repair--2026-10-03).
Runtime stayed networkless and off the Windows host; no rule-byte/version, dependency, policy,
gateway, adapter, hash-algorithm, CI, merge or Phase 6B runtime change. This repairs evidence
interpretation, not evidence authentication or a demonstrated host secret leak.
The earlier blocked/unexecuted status is historical. This scoped human G2 approval and delegated
review do not close G0, manual accessibility, exact-commit CI or final full-diff acceptance.

### Post-merge test-only capture evidence — 2026-10-03

PR #9 merged at `c165b3d203998585193711e67895e64bf4321258`; the owner requested continuation.
The new `codex/g0-dashboard-evidence` branch adds seventeen capture/cleanup/snapshot tests
against unchanged merged production code. No paths, loaders, query logic, hash functions,
gateway/policy/adapters, dependencies, listener/browser or CI implementation changed. Execution
stayed in the existing networkless resource-bounded sandbox under the G0 evidence authorization.

The final 87-path manifest is
`3a261dfb7f7472cb271867f872542d0bbddb30fb2c1df0249ba159f10547e983`.
Seventeen focused checks and all 446 non-browser tests pass at 92.13% coverage; quality and
supplemental independent review pass. The [verification record](PHASE_6_VERIFICATION.md#post-merge-g0-capture-boundary-batch--2026-10-03)
states commands and limits. Four open-descriptor JSON replace/delete cases and one symlink case
exclude Windows explicitly; none is claimed as Windows evidence. These tests exercise selected
synthetic checkpoints and query snapshot reuse, not arbitrary race resistance, WAL writers or
ongoing file authentication. Public Actions queries found no runs for the reviewed head/merge.
G0, cross-platform CI, manual accessibility, final owner acceptance and Phase 6B G1 remain open.

### Windows test-only fixes — 2026-10-03

The owner approved fixing the existing Actions branch after run 37096511551 failed Windows
verification. Short resource-test IDs and a fixed clock in the linkage-fixture helper do not alter
production deadlines, payloads, rejection/linkage assertions or security surfaces. Separate
at/over-deadline failure tests remain unchanged and passed. All 446 non-browser checks passed in
the existing networkless bounded sandbox; supplemental review found no blockers. See
[the verification record](PHASE_6_VERIFICATION.md#windows-ci-test-fixes--2026-10-03).
No host scenario execution or CI dispatch occurred. Windows confirmation and final owner review
remain pending; Ubuntu/both browser jobs passed only on the prior head.

### Windows reparse test proposal — 2026-10-06

⚠️ Security Sensitive: Requires Mandatory Human Review. The prepared Windows-only test diff in
`tests/test_dashboard_g0_boundaries.py` adds `subprocess.run` for the fixed `cmd /d /c mklink /J`
command. Both link and target are constructed under pytest's synthetic `tmp_path`; the target
is outside the manifest directory. The command has `check=True`, captured output, a ten-second
timeout and no `shell=True`. The junction node is removed with `Path.rmdir()` after checking it
is a junction; the target is checked unchanged. File-symlink setup and cleanup are separate.
No product source, dependency, policy, gateway, socket or CI workflow is changed.

The owner reviewed the concrete diff and authorized continuing on 2026-10-06. The focused and
full nonbrowser suites then ran only inside the isolated networkless Linux sandbox; the Windows
command was not invoked there. A green prior run on `ba9b9f1` does not cover
these tests. The linked targets are synthetic only; a passing result would demonstrate selected
Windows link/junction rejection on the CI runner, not all reparse tags, race schedules or host
files. G0 and final owner acceptance remain open.

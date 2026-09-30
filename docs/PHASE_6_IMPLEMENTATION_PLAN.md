# Phase 6A implementation plan — Direct prompt injection

Status: **G1 design approved; Phase 6A implementation and sandboxed G2 checks have passed locally.
G3 acceptance and G4 integration remain open.** See [verification](PHASE_6_VERIFICATION.md)
for dated approvals, tested snapshots, and remaining evidence. The original proposal and gate
requirements below are retained as the acceptance baseline; approval does not authorize commit,
push, pull request, merge, CI dispatch, or release.

Prepared: 2026-09-22. Inspected local checkout: `5f6de2d`; inspected `origin/main`:
`56f34f7` (Phase 5 verification repairs merged through PR #6). The working tree already contains
unrelated agent-workflow documentation changes; preserve them. This plan does not authorize a
commit, push, pull request, merge, dependency change, sensitive-code test, or CI dispatch.

## 1. Objective and prerequisite state

Add exactly one Phase 6 attack surface: a deterministic **direct prompt-injection** scenario. The
scenario demonstrates a user-supplied prompt attempting to override the intended task, read the
existing synthetic secret through the virtual filesystem, and send it only to the existing
socket-free `lab://exfiltration-sink`. It must remain reproducible, explainable, and safe under the
same vulnerable-versus-strict policy comparison used by the current indirect-injection scenario.

Phase 5 code is merged. Phase 5 completion evidence is not yet closed: the
[verification record](PHASE_5_VERIFICATION.md) still lists full C01–C13 mapping, hostile browser
content/request interception, complete bounds and concurrency coverage, platform-specific path
cases, manual accessibility evidence, exact-commit Windows/Ubuntu CI, and final owner acceptance as
open. Gate G0 must close those items or record explicit owner-approved deferrals before Phase 6A is
called complete. Planning may proceed now; implementation should not erase or rewrite Phase 5
history.

This is Phase **6A**, not all of Phase 6. Later roadmap surfaces—malicious web content, RAG
poisoning, unauthorized shell, tool/MCP poisoning, resource abuse, memory poisoning, and
multi-agent injection—remain deferred.

## 2. Current facts and design constraints

- The only packaged scenario is `indirect-injection-secret-exfiltration`, schema 0.1, with a closed
  `document_fixture` field.
- The trusted runner emits `agent.context.document_added`; the fixed mock agent recognizes an
  indirect-injection marker and invokes only `read_file` and `http_post` through `ToolGateway`.
- `VirtualFileAdapter` and `LabHttpSinkAdapter` provide the safety boundary. Scenario execution
  opens no OS socket, performs no DNS lookup, accesses no host file, and starts no process.
- `risk-v1` records `untrusted_document`; using that label for a direct user prompt would be false.
- `policy-v1` already blocks classified-secret reads and matching-canary transfer in strict mode.
  The policy rules need no behavioral expansion merely to support a different input origin.
- Live detection `ASL-CORR-001` and several reporting/incident/outcome functions assume a document
  context event. Phase 3/4 offline investigation also has strict packaged declarative rules.
- `core-lab-v1` is a closed indirect-injection suite. Changing its membership would alter a
  historical benchmark denominator and fingerprint.
- Dashboard data is a safe allowlisted projection; it does not currently allow a prompt-context
  event and must never expose prompt text.
- Direct prompt injection was deferred by F-001 until the Core Vertical Slice was stable. Starting
  it requires a new accepted decision and ADR, not a silent reinterpretation of MVP contracts.

## 3. Scope

### Included

1. One new packaged scenario: `direct-prompt-injection-secret-exfiltration`.
2. Three packaged direct-prompt fixtures: malicious, benign, and a non-matching-canary control.
3. A versioned scenario/input contract that distinguishes `document` from `direct_prompt` without
   weakening the existing schema 0.1 parser.
4. Safe prompt-origin telemetry containing identifiers and provenance only, never prompt content.
5. Origin-aware risk evidence, while preserving all existing `risk-v1` artifacts and behavior.
6. Existing vulnerable and strict profiles, virtual tools, fake secret, socket-free sink, approvals,
   evidence, reports, comparison, replay, investigation, incidents, evaluation, and dashboard views.
7. A direct-injection live correlation and a matching declarative rule with positive and negative
   fixtures.
8. A separate closed `direct-injection-v1` evaluation suite and an example incident.
9. Documentation, package-data verification, regression tests, and exact-commit Windows/Linux CI.

### Excluded

No real LLM or model API; arbitrary prompts; interactive prompt entry; hidden reasoning capture;
real secret; host filesystem; OS process or shell; socket, DNS, HTTP client, browser fetch, or
external service; Docker; arbitrary scenario/rule/plugin imports; changed dashboard listener scope;
new policy editor; adaptive attacks; obfuscation benchmark; multilingual dataset; production
accuracy claim; or any later Phase 6 scenario.

The fixture is an inert, project-controlled string interpreted by a deterministic mock. A successful
vulnerable run is a **simulated lab impact**, never evidence of a real compromise.

## 4. Proposed contract decisions

Record and accept these decisions in proposed
`docs/adr/ADR-009-phase-6a-direct-prompt-injection.md` before runtime changes.

### 4.1 Scenario and input contracts

- Keep scenario schema 0.1 unchanged and readable for the existing indirect scenario.
- Add scenario schema 0.2 as a strict discriminated contract with `input_channel` and
  `input_fixture`. Closed channel values are `document` and `direct_prompt`; Phase 6A adds only the
  direct-prompt scenario as a new public ID.
- Normalize supported 0.1 and 0.2 resources into a trusted internal `ScenarioDefinition`. Scenario
  content may select a packaged fixture but may not select trust, profile, versions, tool
  classification, destinations, host paths, or adapters.
- Do not accept arbitrary fixture paths or inline prompt text from the CLI. Resource loading remains
  an exact allowlist under package resources with duplicate-key, unknown-field, size, encoding, and
  enum validation.
- Existing CLI forms remain valid. `run` and `compare` add the new exact scenario ID as a choice;
  existing defaults, exit meanings, and output isolation remain unchanged.

### 4.2 Prompt telemetry and data minimization

The trusted controller emits `agent.context.prompt_added` before the first tool attempt, with only:

- a bounded fixture ID;
- `source: packaged_prompt_fixture`;
- `trust: untrusted`;
- `delivery_channel: direct_prompt`.

The raw prompt, marker, fake secret, canary, tool body, or derived prompt excerpt must not enter
SQLite, JSON/Markdown reports, incidents, dashboard API/DOM, logs, errors, or test snapshots. Extend
redaction tests to decoded JSON and rendered dashboard content. The known-canary scan is a focused
regression control, not a general secret scanner.

Keep event envelope schema 0.2: Phase 6A adds an allowlisted event type and safe payload, not a new
envelope shape. Add the payload contract to CONTRACTS and evidence-fingerprint allowlists.

### 4.3 Risk and policy versions

- Preserve `risk-v1` and its `untrusted_document` factor for all existing scenario runs and
  historical artifacts.
- Add `risk-v2` for the direct scenario with an `untrusted_context` factor (weight 20) and a closed
  `context_origin: direct_prompt` fact. Retain the existing classified-secret, lab-post, and
  matching-canary factor weights and band calculation. This is explainable teaching evidence, not
  a probability or production risk score.
- Keep `policy-v1` and its strict decisions unchanged unless implementation proves the policy
  contract itself must change. The evaluator may consume validated risk-v1 or risk-v2 assessments;
  its rules still deny classified-secret access and matching-canary transfer. If a policy rule,
  decision reason, or approval contract must change, stop and revise ADR-009 and this plan rather
  than silently introduce `policy-v2`.
- Reports and comparisons must record the actual risk version. Readers accept supported historical
  and current versions without translating v1 factors into v2 labels.

### 4.4 Deterministic target behavior

Refactor the fixed mock agent around a trusted `ScenarioInput` containing the closed channel and
fixture text. Use separate indirect and direct markers. The marker is only a deterministic test
trigger; it does not parse natural language or claim model realism.

Expected direct scenario paths:

```text
malicious direct prompt
  -> prompt_added
  -> virtual secret read attempt
  -> socket-free lab transfer attempt
  -> vulnerable: simulated impact + detection + incident
  -> strict: blocked secret access + prevention evidence + detection/incident

benign direct prompt
  -> prompt_added
  -> no tool attempt, no alert, no incident, no impact, no prevention claim

non-matching-canary control
  -> prompt_added
  -> same controlled tool sequence where allowed
  -> no matching-canary impact; positive sequence evidence may remain distinct from exfiltration
```

No prompt may directly call adapters. All tool attempts pass through `ToolGateway`; mandatory safety
validation remains prior to vulnerable/strict policy evaluation.

### 4.5 Detection, incidents, and reporting

- Generalize the live detector to a closed scenario-selected correlation definition instead of
  duplicating an ad hoc detector. Preserve `ASL-CORR-001` version 1 exactly for indirect runs.
- Add `ASL-CORR-003` version 1 for direct prompt context -> classified virtual read -> matching
  socket-free sink impact within one run and trace. Rule identity is fixed in ADR/contracts before
  implementation.
- Add one equivalent strict declarative packaged rule plus exact positive and negative event
  fixtures for offline validation/investigation. Select its final non-colliding ID during contract
  freeze and use the same ID consistently in suite expectations and documentation.
- Extend the rule field allowlist only for safe exact-match metadata such as
  `payload.delivery_channel`; do not add raw prompt or arbitrary nested-field access.
- Generalize outcome, evidence, incident, and report functions to consume a validated context-origin
  event. Direct reports must say “direct user prompt,” never “document.” Preserve distinctions among
  attempted action, prevention, simulated impact, detection, and causal hypothesis.
- Evidence references remain exact run/trace/event/sequence links. A sequence match is not proof of
  causation; incident language must retain that limitation.

### 4.6 Evaluation and dashboard compatibility

- Keep `core-lab-v1`, its cases, metrics, and fingerprint unchanged.
- Add a separate closed `direct-injection-v1` suite with malicious, benign, and non-matching-canary
  cases under both profiles. Reuse `metrics-v1` only if its existing definitions and denominators
  remain exact. Expand suite/report discriminators without pooling unrelated suites.
- The evaluation runner must load the scenario assigned to each suite/case, validate fixture type
  against its channel, and retain fresh isolated adapters and identities for every child.
- Add `agent.context.prompt_added` to the dashboard safe event projection. Display fixture ID,
  source, trust, and delivery channel only. Existing Phase 5 API routes remain read-only; no prompt
  form, execution button, new outbound request, or writable evidence path is added.

## 5. Safety and resource boundaries

All current non-negotiable controls remain:

- synthetic canary only; no environment-variable, credential-store, home-directory, or host-file
  reads;
- virtual filesystem only and exact `lab://exfiltration-sink` destination;
- socket/DNS/process/subprocess guards active for scenario, comparison, evaluation, and replay;
- strict type/size checks before persistence and no raw bodies in events;
- run, trace, store, virtual adapter, and sink isolation per child; clear the sink on success or
  failure and close SQLite in `finally`;
- existing five-second maximum scenario timeout, bounded event/report/rule/evaluation sizes, bounded
  repetitions, and explicit failure rather than partial success when a limit is exceeded;
- replay, investigation, dashboard, and rule-test paths remain read-only and never instantiate the
  scenario runtime;
- no new runtime dependency is required for Phase 6A.

Test malformed UTF-8, oversized fixture/resource, duplicate JSON keys, unknown versions/fields,
path traversal and package-resource substitution, deadline failure, persistence failure, ID
collision, consecutive runs, concurrent runs, and cleanup. Windows path/device/ADS cases and Linux
symlink cases remain relevant even though scenario selection is allowlisted.

## 6. Planned affected files

Exact file names may be narrowed during implementation, but material expansion requires renewed
approval.

| Files | Planned change |
|---|---|
| `docs/adr/ADR-009-phase-6a-direct-prompt-injection.md` | Proposed scenario/input/origin/risk/detection decisions and compatibility consequences |
| `DECISIONS.md`, `docs/CONTRACTS.md`, `THREAT_MODEL.md` | Accept Phase 6A scope; define schemas, trust ownership, telemetry, safety, and limitations |
| `src/agentsec/models.py`, `constants.py` | Versioned scenario/input/risk discriminators and new fixed identifiers; preserve v1 readers |
| `src/agentsec/resource_loader.py` | Exact allowlisted scenario and prompt-fixture loading with bounds |
| `src/agentsec/resources/scenarios/direct-prompt-injection-secret-exfiltration.json` | New strict packaged scenario definition |
| `src/agentsec/resources/prompts/{malicious,benign,missing_canary}.txt` | Synthetic direct-prompt fixtures with reviewed inert markers |
| `src/agentsec/mock_agent.py`, `runner.py` | Channel-aware deterministic behavior and safe prompt-context telemetry |
| `src/agentsec/risk.py`, `gateway.py`, `policy.py`, `approvals.py` | risk-v2 origin evidence and compatible policy consumption; no broader permissions |
| `src/agentsec/detection.py`, `rule_models.py`, `rule_engine.py` | Closed live correlation selection and minimal safe-field support |
| `src/agentsec/resources/rules/`, `resources/rule_fixtures/` | Direct-injection declarative rule and positive/negative fixtures |
| `src/agentsec/outcomes.py`, `evidence.py`, `reporting.py`, `comparison.py` | Origin-correct outcomes, fingerprints, reports, and comparisons |
| `src/agentsec/incidents.py`, `incident_reporting.py`, `detection_reporting.py` | Origin-correct stage/incident templates and evidence validation |
| `src/agentsec/evaluation_models.py`, `evaluation.py`, `metrics.py` | Multiple closed suite types without changing core-lab-v1 denominators |
| `src/agentsec/resources/evaluation_suites/direct-injection-v1.json` | Independent direct scenario matrix and expectations |
| `src/agentsec/dashboard_catalog.py`, `dashboard_service.py` | Safe prompt-event projection and supported scenario/risk-version validation |
| `src/agentsec/cli.py` | Add exact new scenario and suite choices; no arbitrary paths or text |
| `tests/test_contracts_and_events.py`, `test_end_to_end.py` | Schema, telemetry, redaction, vulnerable/strict, isolation, timeout, cleanup |
| `tests/test_policy_and_approvals.py`, `test_gateway.py` | risk-v1 regression, risk-v2 factors, unchanged policy decisions and safety precedence |
| `tests/test_detection_and_reporting.py`, `test_rule_engine.py`, `test_replay.py` | Live/offline positive/negative, cross-run/trace rejection, semantic reports, read-only replay |
| `tests/test_incidents_and_evaluation.py` | Incident example, isolated suite metrics, failures/exclusions, old-suite fingerprint regression |
| `tests/test_dashboard_catalog.py`, `test_dashboard_api.py`, `tests/e2e/test_dashboard.py` | Safe event display, hostile text/redaction, no new browser action or request |
| `README.md`, `ROADMAP.md`, `docs/PHASE_6_SECURITY_REVIEW.md`, `docs/PHASE_6_VERIFICATION.md` | Accurate workflow, status, review findings, exact evidence, limits, and demo steps |
| `pyproject.toml`, `.github/workflows/ci.yml` | Package new resources and exercise supported Windows/Linux jobs; no dependency addition expected |

Do not edit `docs/agents/` or `AGENTS.md` as part of Phase 6A; current changes there are unrelated.

## 7. Implementation order

1. **G0 prior-phase gate:** finish Phase 5 evidence or record explicit scoped deferrals and impact.
2. **G1 contract freeze:** review and accept ADR-009; lock scenario 0.2, context telemetry, risk-v2,
   direct rule IDs, fixture meanings, evaluation-suite identity, and compatibility table.
3. Add strict models and resource loading first. Prove existing 0.1 scenario and `core-lab-v1`
   remain byte-for-byte/semantically stable where their fingerprints are contractual.
4. Add channel-aware runner/mock behavior and risk evidence behind existing adapters/gateway. Prepare
   a focused sensitive diff for human review before executing gateway/policy/runtime tests.
5. Add live and declarative detections, then origin-aware outcomes/reports/incidents. Test positive
   and negative chains before evaluation or dashboard integration.
6. Add the independent evaluation suite and safe dashboard projections. Dashboard work may proceed
   in parallel only after event/report contracts are frozen; it must consume the same models.
7. **G2 test authorization:** after human security review of the concrete sensitive diff, execute
   targeted tests, complete regressions, package/build/audit checks, browser checks, and safety
   probes.
8. **G3/G4 handoff:** complete verification evidence, review the full diff, human-dispatch exact-
   commit Windows/Ubuntu CI, then update status. Commit/push/PR/merge only when requested.

## 8. Acceptance and test matrix

Each row needs the exact full commit, command/test name, platform, observed result, and retained
evidence in `docs/PHASE_6_VERIFICATION.md`. Passing unit tests alone does not close untested rows.

| ID | Observable acceptance criterion | Required verification |
|---|---|---|
| C01 | Phase 5 prerequisite disposition is recorded; the old indirect scenario and core-lab-v1 remain compatible | Phase 5 record/link review; old CLI/report/fingerprint golden regressions |
| C02 | Only the two packaged scenario IDs and closed fixtures load; schema 0.1 remains strict and schema 0.2 cannot choose trust/tools/adapters/paths | Valid resources; unknown ID/version/field/channel/fixture; duplicate key; oversized/invalid text tests |
| C03 | Malicious direct prompt is deterministic: vulnerable reaches simulated sink impact; strict blocks before secret access; identities and stores remain isolated | Two-profile E2E and comparison assertions; repeated, consecutive, and concurrent runs |
| C04 | Benign prompt invokes no tool and produces no detection/incident/impact/prevention; non-matching-canary control cannot claim exfiltration | Negative E2E, event-order, exact outcome, and incident-count assertions |
| C05 | Prompt telemetry records safe provenance before tool attempts and never persists raw prompt/marker/canary/body | SQLite/report/incident/API/DOM/log/error decoded scans; payload allowlist assertions |
| C06 | risk-v1 stays exact for indirect runs; direct runs record risk-v2 origin truth; policy-v1 strict/vulnerable decisions and safety precedence remain exact | Risk factor/band tests, historical parse tests, policy matrix, forged-context attempts, approval paths |
| C07 | Live direct correlation uses one run/trace and exact chain; offline rule has exact positive and negative behavior without cross-run/trace or reordered matches | Rule fixtures; missing event; wrong trust/channel/path/digest; interleaving; limit exhaustion; live/offline parity |
| C08 | Reports and comparisons truthfully distinguish direct prompt, attempted action, prevention, detection, and simulated impact | Vulnerable/strict/benign/control golden semantic assertions; no document wording in direct artifacts |
| C09 | Incident stages and evidence links resolve to exact validated events; replay/investigation remain read-only and cause no adapter effects | Incident example, forged/missing reference, cutoff/fingerprint, detector-only runtime spies, source hash checks |
| C10 | direct-injection-v1 is independent; all fractions, exclusions, pairs, rule/incident counts, and timing limits are exact; core-lab-v1 is unchanged | Full suite matrix, zero denominator, child failure/assertion failure, repetitions, suite fingerprint regression |
| C11 | Dashboard safely shows direct runs and prompt metadata without raw prompt, actions, writes, external fetches, or altered Phase 5 provenance | API/model parity, hostile fixture text, browser request interception, DOM/redaction scan, source-before/after hashes |
| C12 | Scenario execution cannot access host resources or open network/process boundaries; deadlines, size/event limits, failures, and cleanup are explicit | Socket/DNS/subprocess/host-file spies; at/over limits; forced adapter/store/report failures; sink/store cleanup |
| C13 | Wheel/sdist include all new resources; clean installed CLI works outside checkout; formatting, lint, typing, coverage, audit, and Windows/Linux CI pass | Archive inspection; isolated wheel smoke; full quality suite with >=90% coverage; exact-commit human-dispatched CI |

## 9. Planned verification commands

Run only after G2 approves the concrete sensitive changes and named tests:

```text
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest --cov=agentsec --cov-report=term-missing --cov-fail-under=90
python -m build
python -m pip_audit
```

Also run targeted installed-wheel CLI smoke for both scenario IDs, compare, replay, investigate,
evaluate both suites, and the existing approved dashboard browser suite with external requests
blocked. Run from outside the checkout. Audit the actual core/dashboard/test environments and record
any skipped distributions. Network access for dependency/browser setup is separate from the
socket-free scenario-runtime claim.

Do not claim Windows/Linux CI from local results. Preserve `workflow_dispatch`; a human dispatches
CI for the exact fully reviewed commit. New test downloads or a changed dependency set require
separate approval.

## 10. Approval gates and completion

| Gate | Required decision/evidence | Stop condition |
|---|---|---|
| G0 — Prior-phase readiness | Phase 5 C01–C13, manual accessibility, exact-commit Windows/Ubuntu CI, and owner acceptance are recorded, or explicit scoped deferrals identify risk and follow-up | Do not call Phase 6A complete while Phase 5 evidence is ambiguous |
| G1 — Design approval | Owner accepts one-scenario scope, ADR-009, scenario 0.2, safe prompt telemetry, risk-v2 with policy-v1, fixed detections, and separate evaluation suite | Real LLM/input, arbitrary path, new policy behavior, external network, or later attack family requires a revised plan |
| G2 — Security/test approval | Human reviews concrete runner, mock-agent, gateway, risk, policy, adapter, detector, redaction, and cleanup diffs and approves named test execution | Plan approval is not approval to execute changed sensitive surfaces; material diff changes require renewed review |
| G3 — Acceptance evidence | C01–C13 are complete with local quality/build/audit/browser/security evidence and no unexplained scope changes | Missing or failed evidence remains open even if the general test suite is green |
| G4 — Integration | Final full-diff owner review and exact-commit Windows/Ubuntu CI links; explicit commit/push/PR/merge and release-version decisions | Never infer merge/release approval or mark complete from implementation alone |

Phase 6A is complete only when the installed package demonstrates the direct-prompt scenario across
both profiles, produces origin-correct telemetry/detections/incidents/evaluation/dashboard views,
preserves the existing indirect scenario and historical contracts, retains every safety boundary,
and has recorded evidence for all non-deferred criteria. Writing this document performs none of
those implementation or verification actions.

## References

- [Roadmap](../ROADMAP.md), [decisions](../DECISIONS.md), [threat model](../THREAT_MODEL.md),
  [contracts](CONTRACTS.md), and [MVP scope](../MVP_SCOPE.md).
- [Phase 5 plan](PHASE_5_IMPLEMENTATION_PLAN.md),
  [Phase 5 security review](PHASE_5_SECURITY_REVIEW.md), and
  [Phase 5 verification](PHASE_5_VERIFICATION.md).
- [Agent workflow](agents/implementation-workflow.md), [security baseline](agents/security.md), and
  [definition of done](agents/definition-of-done.md).
- [ADR-003 isolation and no egress](adr/ADR-003-mvp-isolation-and-no-egress.md),
  [ADR-005 runtime policy](adr/ADR-005-phase-2-runtime-policy-and-comparison.md),
  [ADR-006 rules and replay](adr/ADR-006-phase-3-detection-rules-and-replay.md),
  [ADR-007 incidents and evaluation](adr/ADR-007-phase-4-incidents-and-evaluation.md), and
  [ADR-008 read-only dashboard](adr/ADR-008-phase-5-read-only-dashboard.md).

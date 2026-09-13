# Phase 4 implementation plan — Incident Management and Evaluation

Status: accepted for implementation on 2026-09-12. Work begins from merged Phase 3 revision
`ed328355f9c9460c0f12720db342e37e525371e3` on `phase-4-incident-evaluation`. Remote CI evidence
is not accessible from the current environment and remains a delivery gate.

## 1. Objective and entry gate

Turn recorded rule matches into an investigation report that explains what happened, which
evidence supports each conclusion, and how the vulnerable and strict profiles differ. Add a
small reproducible evaluation suite with explicit labels, denominators, and missing-data rules.

Read [contracts](CONTRACTS.md), [roadmap](../ROADMAP.md), [decisions](../DECISIONS.md),
[security guidance](agents/security.md), [definition of done](agents/definition-of-done.md), and
ADRs 002–006 before implementation. Repository guidance applies; no currently available
specialized skill directly matches this local Python planning task.

Phase 3 is committed and its push was verified in this conversation. Its recorded local result
is 90 passing tests and 91% coverage, with clean lint/types, build, audit, and installed CLI demo.
Those are historical verification results, not a fresh test of a Phase 4 revision. Phase 3 was
confirmed merged as `ed328355f9c9460c0f12720db342e37e525371e3`; Phase 4 human review and
final-commit Windows/Linux CI have not yet been established.
See [Phase 3 verification](PHASE_3_VERIFICATION.md).

Before implementation:

1. Confirm Phase 3 review, merge, and CI results; record the actual commit and workflow links.
2. Start a separate `phase-4-incident-evaluation` branch from the verified merged revision.
3. Recheck the accepted baseline. Keep any prerequisite repair explicit and bounded.
4. Record the accepted decisions in ADR-007 before code work.

One observed prerequisite needs attention: `run_rule_tests()` and `RuleTestReport` currently
count positive/negative fixture **presence** as coverage, even when an assertion fails. Phase 3's
plan defines coverage using **passing** positive and negative fixtures. Resolve this discrepancy
with a regression test before reusing coverage in Phase 4; do not silently reinterpret the metric.

## 2. Current implementation and intended workflow

| Existing component | Current behavior | Phase 4 use |
|---|---|---|
| `detection.py` | Legacy `ASL-CORR-001` records one alert/incident for a matched run | Preserve behavior and identify historical detections separately |
| `rule_engine.py` | Produces versioned, deterministic declarative matches | Reuse as the sole declarative evaluator |
| `replay.py` | Reads a selected SQLite run without changing it | Reuse bounded snapshot reading and derived-event exclusion |
| `outcomes.py` | Derives simulated impact and evidence-backed prevention | Reuse on isolated traces, with lifecycle and consistency checks |
| `runner.py` | Runs packaged scenarios; records fixture/profile in `run.started` | Use only for the explicit evaluation suite |
| `comparison.py` | Compares one vulnerable/strict pair using legacy detection | Preserve its 0.2 contract; add Phase 4 evaluation separately |
| `events.py` | Stores sequence and UTC wall-clock timestamps | Sequence remains authoritative; timestamps alone do not prove causality |

Accepted workflow:

```text
Existing SQLite run + chosen rules
    -> validate/read one snapshot -> evaluate rules -> build derived alerts
    -> group by run and trace -> link evidence, classify stages and outcomes
    -> incident timeline + cause/remediation templates -> investigation.json / .md

Packaged labeled suite + vulnerable/strict profiles
    -> isolated scenario runs -> same investigation pipeline for each child
    -> reconcile observations with labels -> metrics + paired profile comparison
    -> evaluation.json / .md
```

The investigation service never invokes a mock agent, Tool Gateway, approval simulator, or
adapter. The evaluation service intentionally invokes the existing socket-free runner for its
closed, packaged cases. No uploaded rule or event text can choose a scenario path or executable.

## 3. Accepted implementation decisions

| Topic | Recommended Phase 4 decision |
|---|---|
| Integration | Add offline `investigate` and packaged `evaluate`; keep `run`, `compare`, `rules`, and `replay` compatible |
| Persistence | SQLite remains canonical; new JSON/Markdown investigation and evaluation artifacts are derived reports, with no source database writes |
| Correlation | `incident-v1`: one derived investigation group per source run/trace that has a declarative match; no cross-trace or cross-run grouping |
| Integrity | Standard-library SHA-256 over a versioned serialization of the exact event snapshot and selected rules; change detection only, not authenticity |
| Evaluation | `evaluation-v1`: a closed suite using existing malicious, benign, and missing-canary fixtures under both profiles |
| Detection metrics | Separate detection of labeled attack runs from detection of simulated-impact runs; keep historical legacy timing in a separate series |
| Timing | Calculate recorded alert/incident latency only when source evidence supports it; offline-derived matches have unavailable historical latency |
| Management scope | Immutable investigation snapshots with initial status `new`; assignment, analyst edits, resolution, and status-transition storage are deferred |

ADR-007 resolves the Phase 4 portions of R-005 (lab outcome definitions) and R-006 (snapshot
integrity), without claiming a production benchmark or cryptographic evidence custody. The
architecture draft's detection-rate denominator is successful attacks; preserve that as a
separately named metric rather than silently replacing it.

New digest code falls within the repository's explicit hashing review boundary. Prepare its
implementation and review checklist, obtain human sign-off before executing that sensitive
change, and record the reviewed revision. Plan approval is not implementation security sign-off.

## 4. Incident and evidence contracts

Use strict Pydantic models with unknown fields forbidden. Give new investigation, suite, and
evaluation contracts their own schema `1.0`; retain event 0.1/0.2, rule/replay 1.0, and legacy
report/comparison 0.2. No event migration or rule-schema change is required by this plan.

Proposed models:

- `EvidenceReference`: snapshot digest, run ID, trace ID, event ID, and sequence.
- `DerivedAlert`: stable key, rule ID/version, engine version, severity, description, and ordered
  references; explicitly tagged `offline_derived`.
- `Incident`: stable key, correlator version, run/trace, status `new`, category, severity, alerts,
  unique ordered evidence, stage observations, outcome assessment, timeline, and explanations.
- `InvestigationReport`: schema/tool versions, snapshot metadata, rule-set fingerprint, source
  lifecycle status, completeness/limitations, derived alerts/incidents, and processing duration.
- `EvaluationCase`, `EvaluationChildResult`, `MetricResult`, and `EvaluationReport`: labeled
  case identity, profile, trial, observed outcomes, eligibility/exclusion reasons, paired results,
  metric numerators/denominators, and artifact references.

### 4.1 Snapshot reading and trust

Use the dedicated read-only/query-only SQLite reader, never `EventStore` for imported input.
Take one consistent snapshot per investigation and use that same in-memory evidence for rule
evaluation, hashing, timeline, and conclusions. Do not reread the file for each stage. Preserve
the complete selected event set for historical timing; exclude derived detection/alert/incident/
report events from new rule evaluation, as Phase 3 does.

Verify unique event identities and sequences, supported schemas, payload bounds, and references.
For a completed source, require one matching `run.started`, one terminal `run.completed`, and
valid lifecycle ordering. Missing completion permits partial investigation with an explicit label.
Conflicting terminals, duplicate starts, events after a terminal, or conflicting fixture/profile
metadata cannot count as a complete evaluation run. Test source metadata types rather than
coercing strings, booleans, and integers into plausible values.

Imported envelopes are claims in a local file, not authenticated events. Envelope validation and
digests do not prove the recorder was trustworthy. Reject malformed relevant payloads; retain
unknown event types only as bounded generic timeline entries without inventing a classification.

### 4.2 Stable identities and grouping

Deduplicate by the existing match identity, qualified with snapshot and rule-set fingerprints.
Generate identities deterministically, without timestamps or random invocation IDs. Keep a
separate random output-directory ID if desired. Store full qualified identities even if a shorter
digest is used for display; never rely on a truncated value as the uniqueness constraint.

Group every derived alert with the same source snapshot, run, and trace into one incident.
Use maximum member severity, a unique sequence-ordered evidence union, and stable alert ordering.
Different snapshots, rule sets, traces, and runs must not merge. Repeated matches with different
evidence remain distinct alerts within that group. Zero matches produce an empty incident list
and a valid investigation report.

This is deliberately a trace-level investigation bundle: two attacks sharing one trace are not
claimed to be separately attributed incidents. Richer campaign, entity, time-window, and
cross-trace correlation requires a later contract.

Keep historical `ASL-CORR-001` alerts/incidents as separately labeled source references; do not
double-count them alongside reevaluated `ASL-CORR-002` matches. A control-only match such as
`ASL-EVENT-001` is category `control_observation`. It does not by itself prove malicious intent,
prevention, or impact. Other matched bundles use `suspicious_activity`; evidence-derived outcomes
remain separate from category and severity.

### 4.3 Timeline, stages, and outcome honesty

Build each incident timeline from all selected source events for its trace, sorted by sequence,
with direct-evidence markers and clearly labeled historical detection/report entries. Display
timestamps as recorded. A reversed clock must not reorder actions.

Use a versioned mapping to closed stage labels: `untrusted_context`, `tool_request`,
`secret_access`, `outbound_attempt`, `simulated_impact`, and `defense_denial`. Apply labels only
when the relevant event type and payload checks hold. A request is not successful execution;
`tool.executed` is dispatch; the adapter effect supplies evidence of completion.

Every document fixture is currently added as untrusted, including benign input. Therefore
`trust: untrusted` means provenance, not a confirmed injection. For recognized packaged cases,
the trusted case label may supply attack context; for other sources the report describes a
possible vector and unresolved intent. Ground-truth labels must never enter rule matching.

Derive outcomes within each trace. For incomplete sources, report positive observed facts but
leave absence-based conclusions unknown. Preserve failed/incomplete lifecycle status even when
the analysis itself completed. A denial with an allow, dispatch, or denied effect for the same
call is inconsistent. Mixed impact and denial evidence across different calls must be explained;
do not label the entire attack successfully prevented if impact was reached.

Use deterministic project-owned templates with supporting evidence references for root-cause
hypotheses and remediation. Examples: untrusted instructions preceded resource access, or a
strict policy denied classified-secret access. Qualify causal claims as hypotheses unless the
known fixture establishes the behavior. No generated LLM diagnosis or auto-remediation actions.

### 4.4 Integrity metadata

Define `evidence-snapshot-v1` as SHA-256 of UTF-8 serialized validated event envelopes ordered by
sequence: JSON keys sorted, compact separators, `ensure_ascii=True`, `allow_nan=False`, and no
trailing newline. Include every envelope/payload field, source run ID, schema tag, and cutoff in
one documented object. Reject unsupported/non-finite values. Publish fixed test vectors; do not
describe this project-specific encoding as a general JSON canonicalization standard.

Fingerprint the validated ordered rule definitions, not only their IDs/versions, so edited rule
content cannot silently reuse an analysis identity. Also fingerprint the packaged suite and
record package, engine, correlator, template, and metric versions in evaluation provenance.

Hash the selected logical snapshot, not the database file separately: unrelated runs, SQLite page
layout, or a WAL must not make the report claim a different set of evaluated events. Preserve the
source basename, count, and cutoff; never emit the operator's absolute host path by default.
Report integrity as `snapshot_fingerprinted`, never `authentic`, `tamper_proof`, or `verified_origin`.
Signatures, key management, hash chains, and persistent custody records remain deferred.

## 5. Evaluation suite and metrics

### 5.1 Trusted labels and trials

Package `core-lab-v1` as strict bounded data referring only to existing closed `DocumentFixture`
values. Include `malicious` (attack), `benign` (benign), and `missing_canary` (attack control with
no expected canary transfer in the vulnerable profile). Missing-canary is not benign: its mock
still reads the fake secret and requests a transfer. Separate case ground truth, expected fixture
assertions, and observed outcomes.

Each case specifies its case ID, scenario, fixture, attack/benign label, attack family, and
expected facts per profile. Use the same fixture for each vulnerable/strict pair, fresh state and
identities, and default deny for eligible approval simulation. No arbitrary filesystem fixture,
external dataset, alternate canary, or executable component can be selected by suite text.

Default to one repetition per case/profile (six child runs); allow 1–10 repetitions. Repetition
checks reproducibility and does not increase independent scenario diversity. Report unique case
count alongside total trials, and pair by case ID and trial number rather than positional order.

Validate each child's `run.started` fixture, scenario, and profile against its assigned case. Case
labels must not be inferred from detections, severity, impact, or absence of matches. Version 1
evaluation supports the runner's single-trace cases; investigation still supports multiple traces.
Do not let an unexpected multi-trace child silently change metric denominators.

Expected baseline observations, inferred from the current mock, policy, and packaged rules
(to become executable assertions during implementation):

| Fixture | Profile | Matching rules | Simulated impact | Prevention | Derived incidents |
|---|---|---|---|---|---:|
| malicious | vulnerable | `ASL-SEQ-001`, `ASL-CORR-002` | yes | no | 1 |
| malicious | strict | `ASL-SEQ-001`, `ASL-EVENT-001` | no | yes | 1 |
| benign | vulnerable | none | no | no | 0 |
| benign | strict | none | no | no | 0 |
| missing_canary | vulnerable | `ASL-SEQ-001` | no | no | 1 |
| missing_canary | strict | `ASL-SEQ-001`, `ASL-EVENT-001` | no | yes | 1 |

These derived incidents coexist with the unchanged historical incident contract. For
example, missing-canary can produce a suspicious-activity investigation while the legacy critical
canary-correlation detector correctly reports no match.

### 5.2 Eligibility and formulas

Define A = completed, evidence-consistent, attack-labeled child runs; B = completed,
evidence-consistent, benign-labeled child runs. Define S as the subset of A with matching-canary
simulated impact. Compute separately per policy profile using the fixed selected rule set.
One run contributes at most once to a run metric, regardless of alert or incident count.

| Metric (`metrics-v1`) | Numerator | Denominator |
|---|---|---|
| Simulated attack success rate | Runs in A reaching matching-canary simulated impact | A |
| Attack-run detection rate | Runs in A with at least one declarative alert | A |
| Simulated-impact detection rate | Runs in S with at least one declarative alert | S |
| Prevention rate | Runs in A with evidence-backed defense prevention and no simulated impact | A |
| Benign-run false-positive rate | Runs in B with at least one declarative alert | B |

The declared alert policy counts every selected declarative rule, including control-observation
alerts. Report per-rule counts and incident categories so readers can see what caused a rate.
Do not count legacy source alerts as extra declarative detections. Include TP/FN for A and FP/TN
for B under this exact run-level definition, with conservation assertions.

Attack success here measures simulated canary transfer, not fake-secret read success or an LLM's
susceptibility. Count evidence of secret access and outbound attempts separately in child results.
The overall prevention rate includes the labeled missing-canary attack control; also show case
breakdowns and a paired comparison restricted to cases whose vulnerable child reached impact.
Do not silently substitute that restricted denominator for A.

Each metric records numerator, denominator, fraction, eligible count, excluded count/reasons,
and metric version. Zero denominator gives `null` with `no_eligible_samples`; never NaN or zero
percent. Unknown outcomes, failed/incomplete children, and contradictory evidence are excluded
and remain visible. Include total scheduled/completed/failed/excluded cases so incomplete
coverage cannot look like a complete benchmark. A completed child that violates a known fixture
expectation still contributes its valid observations; mark the suite assertion failed instead
of excluding an inconvenient outcome.

Compare paired child outcomes and eligible profile rates with their denominators. If a member
is missing or failed, label the pair incomplete. Do not make a paired prevention claim using
another trial's baseline. Preserve existing `compare` output and legacy detection semantics.

### 5.3 Timing

Keep two explicit bases:

1. `offline_processing`: monotonic evaluator/correlator duration; excludes source reading and
   report writing. It is operational timing only, with no historical MTTD/MTTI claim.
2. `recorded_legacy`: recorded source latency for `ASL-CORR-001` when there is an eligible labeled
   attack run and validated source `detection.match`, `alert.created`, and `incident.created`
   linkage. Report this separately from Phase 4 declarative detection rates.

For recorded latency, t0 is the known attack case's matching document-added event. t_alert is
the earliest valid linked alert creation and t_incident the corresponding valid incident
creation. Require same run/trace, matching rule/evidence IDs, resolvable alert/incident links,
supported source component, and causal sequence order. Compute seconds as t_alert - t0 and
t_incident - t0 only when UTC timestamps respect that order. Rule identity for older alerts
missing a version must be resolved from the linked validated detection event, not guessed.

Means are the arithmetic means of eligible per-run intervals, with separate sample counts,
exclusion reasons, and undetected/no-incident counts. Missing data is `null`; reversed clocks are
excluded with `clock_order_invalid`; valid equal timestamps give zero. Never impute replay
execution time as an old alert or incident time. An offline-derived alert's historical MTTD/MTTI
is `null` with `offline_derivation`. Full live declarative detection latency requires future
instrumentation and is explicitly outside this phase's proposed scope.

## 6. CLI, artifacts, limits, and failures

Implemented command contracts:

```text
agentsec investigate --events <events.sqlite3> --run-id <run-id> --rules <directory> --output-dir <directory>
agentsec evaluate --suite core-lab-v1 --repetitions 1 --output-dir <directory>
```

Evaluation v1 uses the packaged rule set; arbitrary suite imports and user-supplied rule sets for
benchmark comparisons are deferred. Load packaged resources with the existing resource pattern
so the installed wheel works outside the checkout.

Investigation writes a fresh `investigation_<id>/investigation.json` and `investigation.md`.
Evaluation writes `evaluation_<id>/evaluation.json` and `evaluation.md`, retaining each child
run's canonical SQLite and original reports plus its derived investigation reports. All child
references are relative to the evaluation root and validated to remain inside it.

Use fixed limits: existing 64 rules, 64 KiB/rule, 8 steps, 16 predicates, 32 membership values,
10,000 source events, 64 MiB/database, and 10,000 candidate states/matches per rule remain.
Add at most 1,000 total derived alerts, 128 traces/incidents per investigation, 10,000 unique
timeline entries, 16 KiB/suite definition, 3 cases, 10 repetitions, and 60 child runs. Each child
keeps its existing 128-event and five-second execution ceilings. Use a 1 MiB ceiling per report,
128 MiB aggregate evaluation-artifact budget, and 300-second cooperative suite deadline.

Enforce bounds before allocating/serializing large cross-products. Candidate-state bounds do
not by themselves bound repeated event scans: review the reused engine's iteration cost and use
indexed candidate lists or an explicit operation budget if necessary, preserving match semantics.
Any new engine guard must be versioned and regression-tested. Keep SQL fixed and parameterized;
for imported databases reject a view masquerading as the canonical events table and bound query
work if required. Do not invoke SQLite extensions or follow paths from stored content.

Both required report files must be bounded, escaped, and checked for the known raw canary before
publication. Also inspect decoded safe fields so Unicode escapes cannot bypass redaction checks.
Never copy arbitrary payloads, absolute paths, or raw rule strings into terminal errors. Do not
render event-supplied Markdown links as actionable paths or URLs.

Create a fresh operation directory exclusively; stage outputs inside it and publish only after
both files succeed. Refuse overwrite. Failure cleanup may remove only files owned by that
invocation; never delete preexisting reports or input evidence. Test failure between the two
writes, cleanup errors, and repeated invocations.

Exit 0 means required reports completed and, for evaluation, all scheduled cases and assertions
succeeded. Exit 2 means invalid operator input or a completed suite with expectation mismatches.
Exit 1 means runtime, budget, or artifact failure; it takes precedence if failures coexist.
An investigation of a failed/incomplete source may return 0 for completed analysis while
prominently preserving source status. An evaluation child failure may produce a final
`status: partial` summary and exit 1; artifact-write failure must leave no successful summary.
Fail fast on global integrity/resource failures, preserve already completed child evidence, and
account for not-run cases. Do not automatically retry failed trials or omit their records.

## 7. Implementation sequence and file ownership

These are local work-package IDs, not created GitHub issues. Implement sequentially; no external
ticket creation or parallel agents are requested.

| Package | Work | Main files / completion evidence |
|---|---|---|
| P4-00 | Close Phase 3 gates and coverage discrepancy | Phase 3 verification, focused coverage regression, clean baseline |
| P4-01 | Freeze decisions, formulas, schemas, examples, review boundaries | ADR-007; `CONTRACTS.md`; decisions; valid/invalid contract fixtures |
| P4-02 | Snapshot validation, reference resolution, provenance fingerprints | `evidence.py`, focused `replay.py` reuse, `incident_models.py`; hash review before sensitive execution |
| P4-03 | Derived alerts, grouping, stages, outcomes, cause/remediation templates | `incidents.py`, packaged templates; exact positive/negative investigation fixtures |
| P4-04 | Bounded investigation reports and `investigate` CLI | `incident_reporting.py`, `cli.py`; source-unchanged and write-failure tests |
| P4-05 | Closed suite and isolated child orchestration | `evaluation.py`, `evaluation_models.py`, packaged evaluation suite |
| P4-06 | Metric arithmetic, recorded timing, paired profile reporting | `metrics.py`, `evaluation_reporting.py`; exact arithmetic and exclusion tests |
| P4-07 | Full verification and handoff | README demo, roadmap/status updates, Phase 4 verification record, installed-wheel checks and CI |

Prefer small focused modules and shared pure functions over a framework. Reuse `evaluate_rules`,
snapshot loading, and outcome derivation; do not implement a second rule engine in report or CLI
code. Extend legacy helpers only where required for verified isolation/consistency. Keep new
report shapes separate from frozen legacy ones and add no new runtime dependency by default.

## 8. Acceptance matrix

| Requirement | Required proof |
|---|---|
| C01 — Entry/compatibility | Verified Phase 3 base; old CLI, schemas, rule semantics, profiles, approvals and comparison regressions pass |
| C02 — Incident correctness | Vulnerable chain produces one trace bundle with sequence/correlation alerts; strict chain shows denial without impact; benign case produces no derived alert/incident |
| C03 — Isolation/deduplication | Repeated exact matches do not multiply alerts; distinct evidence retained; different runs/traces/snapshots/rule content never merge |
| C04 — Evidence resolution | Every stage, outcome, alert, incident, and explanation reference resolves within its snapshot and trace; forged/missing/duplicate links fail |
| C05 — Timeline honesty | Sequence order survives equal/reversed clocks; benign untrusted context is not called confirmed injection; dispatch is not an effect |
| C06 — Integrity | Fixed fingerprint test vectors; event/rule change changes fingerprint; same logical snapshot is stable; only selected snapshot participates; no authenticity claim |
| C07 — Outcome/lifecycle | Failed, incomplete, unknown, malformed, contradictory, post-terminal and mixed-call evidence cannot falsely claim prevention or completed impact-free execution |
| C08 — Ground truth | Missing-canary is an attack control; label changes do not alter rule results; mismatched fixture/profile/trial and unexpected multi-trace children rejected |
| C09 — Metrics | Exact fractions, TP/FN/FP/TN conservation, per-profile denominators, zero/empty cases, unequal failures, excluded/not-run cases and repetition counts tested |
| C10 — Timing | Known timestamp fixtures produce exact means/counts; invalid/missing clocks and links excluded; offline-derived timing unavailable; basis never mixes legacy and declarative results |
| C11 — Safe execution/output | Investigation instantiates no runtime; evaluation preserves socket/DNS/host-isolation tests; escaped metadata, raw-canary/encoded-canary rejection, source unchanged, no overwrite, atomic failure behavior |
| C12 — Limits | Event/query/candidate/alert/trace/report/suite/deadline boundaries fail explicitly, never silently truncate or return successful no-match |
| C13 — Delivery | Review sign-off, passing lint/types/full tests, package build/audit, installed demo outside checkout, and final-commit Windows/Linux CI recorded |

Hand-calculated metric fixture: with 4 eligible attack runs, 2 simulated-impact runs, 3 alerted
attack runs (both impact runs alerted), 1 prevented run, and 3 eligible benign runs of which 1 is
alerted, expect attack success 2/4, attack detection 3/4, impact detection 2/2, prevention 1/4,
and FPR 1/3. Add failed/excluded runs without changing those denominators, while total scheduled
counts increase. Separately, one failed positive fixture must remove its rule from passing
positive/negative coverage without hiding the failed assertion.

Minimum end-to-end demo uses malicious, benign, and missing-canary cases under both policies;
includes incident evidence navigation, paired outcomes, exact fixture assertions, and metric
limitations. Synthetic contradictory/failure fixtures test the analysis path without expanding
the live scenario catalog. Review an example Markdown report manually for whether a reader can
identify vector, attempted actions, actual effects, blocked stage, and evidence without raw logs.

## 9. Handoff and deferred work

Update README usage, roadmap, contracts, the decision register, applicable threat-model sections,
and a Phase 4 verification record when implementation is verified. Record the actual tested
revision, command results, coverage, package artifacts, review status, and CI links. Add a small
domain glossary only when the new terms are accepted; do not rewrite unrelated architecture docs.

Deferred: mutable incident workflow, analyst assignment, automated remediation, dashboard/API,
live declarative timing instrumentation, cross-run incidents, arbitrary suite imports, real LLMs,
new attack surfaces, threshold rules, external security mappings, authenticity signatures, and
production accuracy claims. The roadmap's incident-management and timing bullets are delivered
within the explicit immutable-report and recorded-timing scope accepted here.

Do not mark Phase 4 complete while C01–C13 lack evidence. The accepted scope includes
trace-level grouping, snapshot hashing, metric denominators, and recorded-only timing.
Implementation and verification status is recorded separately in `PHASE_4_VERIFICATION.md`.

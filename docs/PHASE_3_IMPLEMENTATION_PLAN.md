# Phase 3 implementation plan — Detection Engineering

Status: locally verified implementation candidate from merged Phase 2 commit `31156ed`. The
merged baseline required local formatting, typing, and approval-result test corrections. The
complete Phase 3 working tree passes Ruff, strict MyPy, all 90 tests with 91% coverage, package
build, dependency audit, and an isolated installed-CLI demonstration on Windows/Python 3.13.15.
Human review and remote Windows/Linux CI evidence remain delivery checkpoints. See the
[verification record](PHASE_3_VERIFICATION.md).

## 1. Entry gate and decisions

Before Phase 3 code changes, finish Phase 2 security sign-off, formatting/lint, strict typing,
tests, installed-package demo, and the Windows/Linux CI evidence required by A01–A15 in the
[Phase 2 plan](PHASE_2_IMPLEMENTATION_PLAN.md). Record the tested revision, actual results, and
remaining limitations. Start implementation from the verified Phase 2 revision on a separate
feature branch; do not mix Phase 3 code into the current Phase 2 diff.

Read repository guidance, [contracts](CONTRACTS.md), [roadmap](../ROADMAP.md), and ADR-002,
ADR-004, and ADR-005 before implementation. No available specialized skill directly matches this
local Python planning task; use repository guidance and reassess skills when implementation starts.

The defaults below are accepted in ADR-006. JSON resolves R-004 for this phase and defers the YAML
proposal P-005.

## 2. Intended product workflow

```text
Author a bounded JSON rule -> validate -> run positive/negative fixture tests
                                              |
Existing SQLite run -> read-only replay -> evaluate rules -> deduplicate matches
                                              -> JSON/Markdown detection report
```

Replay analyzes recorded events only. It never reruns the mock agent, Tool Gateway, adapters,
approvals, or scenario instructions. SQLite remains canonical under ADR-002.

Deliver versioned single-event, sequence, and correlation rules; a fixture harness; offline
replay; deterministic alert deduplication; evidence enrichment; and narrowly defined coverage
and processing-time metrics. Preserve existing run/compare behavior and ASL-CORR-001 semantics.

Defer threshold rules until a documented benign baseline exists, as required by the roadmap.
Also defer YAML, regex, executable rule plugins, Sigma conversion, dashboard/API, new attack
scenarios, real LLMs, incident grouping, and Phase 4 attack-success/false-positive-rate metrics.
No runtime dependency is expected.

## 3. Proposed contracts and limits

Use a strict JSON rule schema with a separate schema version and rule ID/version, description,
severity, supported event versions, rule kind, ordered steps, and optional equality joins.
Unknown fields, duplicate IDs/versions, unsupported operators and versions, or invalid joins fail
validation. Rule definitions cannot contain Python, SQL, templates, imports, shell, or callbacks.

Initial predicates support typed scalar equality and membership in a bounded scalar list, joined
with AND. Fields use an explicit allowlist of envelope fields and known safe payload fields.
Missing fields do not match; do not coerce strings, numbers, or booleans into one another.

Proposed fixed limits: 64 rules per invocation, 64 KiB per rule, 8 steps, 16 predicates per step,
32 membership values, 10,000 events per selected run, 64 MiB per input database, and 1 MiB per
output report. Bound candidate state and matches to 10,000 per rule; exceedance fails explicitly
without truncating results or treating a partial evaluation as a successful no-match.

Single-event rules match one event. Sequence rules require strictly increasing sequence numbers
within the same run and trace. Correlation rules add typed equality joins between named steps,
such as matching canary digests. Never correlate across runs or traces. Enumerate distinct ordered
evidence tuples deterministically within the candidate budget; input row order is not match order.
Version 1 uses sequence order, not wall-clock windows; timestamp-window rules remain deferred.

Each result records rule ID/version, engine version, source run/trace, ordered evidence IDs,
severity, and a bounded description. Deduplicate by rule ID/version + run/trace + ordered evidence
IDs, not random IDs or timestamps. Enrichment uses safe existing metadata and evidence references,
never copied raw payloads. A correlation match is not proof that an incident was persisted.

Keep existing event schemas 0.1/0.2 and Phase 2 reports compatible. Give rule definitions and replay
reports their own schema versions. Old events missing fields required by a rule produce no-match;
unsupported event versions produce a clear validation failure. Do not rewrite original evidence.

## 4. Replay and CLI

Implemented commands:

```text
agentsec rules validate --rules <directory>
agentsec rules test --rules <directory> --fixtures <directory> --output-dir <directory>
agentsec replay --events <events.sqlite3> --run-id <run-id> --rules <directory> --output-dir <directory>
```

CLI paths are explicit trusted operator selections, never paths suggested by event or rule text.
Use a dedicated read-only SQLite reader: the current EventStore constructor creates schema and
must not be reused for source replay. Open an existing database in read-only/query-only mode,
keep extension loading disabled, use fixed parameterized queries, and do not follow paths from
stored content. Read a consistent snapshot and enforce input, event, payload, and candidate limits.

Require a run ID and validate unique event IDs, sequence uniqueness, envelopes, and supported
versions. Preserve distinct traces. Treat malformed databases and duplicate/conflicting evidence
as errors. Read canonical events, excluding derived detection/alert/incident/report events from
rule evaluation in the first version to avoid recursive detections.

Write a fresh replay directory with replay.json and replay.md. Include source identity, evidence
cutoff, rule versions, matches, deduplication counts, and explicit source completion/failure state.
A failed or incomplete source can be analyzed but must not be described as a successful lab run
or prevention. Source evidence remains unchanged. Export/import JSONL is deferred; future support
must retain its derived-artifact role under ADR-002.

Redact output through safe field selection, reject the known raw lab canary, escape Markdown and
terminal controls, and avoid copying arbitrary rule descriptions or payloads into error messages.
Do not claim generic secret detection for arbitrary imported content.

Exit 0 means successful validation/replay, including zero matches; exit 2 means invalid input or
fixture expectation mismatch; exit 1 means runtime, resource-limit, or artifact failure. Error
output must distinguish these causes without printing untrusted content. No successful replay
report should remain after an output failure.

## 5. Work packages

1. **P3-00 — Close Phase 2.** Record its verification and review evidence before code work.
2. **P3-01 — Freeze contracts.** Record the rule/engine/replay semantics and limits in an ADR,
   update decisions and contracts, and prepare valid/invalid rule and result examples.
3. **P3-02 — Validator and single-event engine.** Add bounded JSON loading, typed predicates,
   deterministic results, and safe metadata enrichment. Test missing fields and type confusion.
4. **P3-03 — Sequence and correlation.** Add ordering and equality joins, bounded candidate state,
   deterministic deduplication, and tests for wrong order, repeated events, and cross-trace data.
5. **P3-04 — Fixture harness and compatibility.** Add expected match/evidence assertions and
   positive/negative controls for every rule. Retain the existing ASL-CORR-001 Python evaluator as
   a compatibility adapter initially: its first-event semantics must not silently change to the
   new engine's enumeration semantics. Give any generalized variant a distinct rule ID/version.
6. **P3-05 — Read-only replay and reports.** Add snapshot reading, CLI commands, source-status
   labeling, deterministic JSON/Markdown output, and failure handling. Share evaluation logic
   with the fixture harness; do not duplicate rule semantics in CLI code.
7. **P3-06 — Verification and demonstration.** Run appropriate review, full regression suite,
   lint/types, clean installed CLI, no-socket/no-adapter tests, source-unchanged checks, output
   redaction, and Windows/Linux CI. Publish a short README demo and illustrative replay output.

These are local planning IDs, not GitHub issues. No external tickets or parallel agents are
requested. Implement packages in order; P3-04 fixture authoring may progress alongside P3-03
once contracts are fixed, without requiring separate agents.

## 6. Acceptance evidence

| Requirement | Evidence required |
|---|---|
| B01 — Phase 2 compatibility | Existing default, strict, compare, prevention and detection regressions pass |
| B02 — Rules are bounded data | Invalid schemas/operators/fields and oversized inputs fail without execution |
| B03 — Rule correctness | Every packaged rule has positive and negative fixtures with exact evidence IDs |
| B04 — Correlation isolation | Wrong order, missing joins, repeated events and cross-run/trace tests |
| B05 — Determinism | Identical source/rules produce identical ordered matches and dedup keys |
| B06 — Replay isolation | Source database unchanged; missing source not created; no adapters/sockets/DNS |
| B07 — Failure honesty | Malformed, incomplete, failed and over-budget inputs cannot appear as successful prevention |
| B08 — Safe outputs | Redaction, escaping, evidence resolution, bounded output and overwrite-refusal tests |
| B09 — Version compatibility | 0.1/0.2 event fixtures supported; unknown versions rejected; old rule behavior retained |
| B10 — Delivery | Installed CLI demo, lint/types/tests, applicable review and Windows/Linux CI recorded |

Report fixture coverage as rules with both passing positive and negative fixtures / total rules.
Report fixture assertion pass count / total assertions separately. Measure evaluator duration
with a monotonic clock, excluding input/output; label it local processing time, not MTTD or MTTR.
Timing is nondeterministic and excluded from replay equality checks. Do not infer real-world
accuracy, false-positive rates, or robustness from these synthetic fixtures.

## 7. Handoff

Implement only after the Phase 2 entry gate and this plan's proposed contracts are accepted.
Apply human review to actual sensitive changes per repository security guidance; offline rule
data must never expand agent capabilities. Report actual executed results and remaining gaps.
Do not mark Phase 3 complete while any B01–B10 item lacks evidence.

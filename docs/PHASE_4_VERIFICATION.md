# Phase 4 verification record

Status: locally verified implementation candidate. The six previously observed gaps have focused
regressions and fixes. Final human review and exact-commit CI remain open; Phase 4 is not
marked complete.

## Implemented scope

- Passing positive and negative rule fixtures are now required for coverage.
- Offline investigation validates one logical snapshot, fingerprints complete evidence and rules,
  derives declarative alerts, groups them by trace, and writes bounded JSON/Markdown reports.
- `core-lab-v1` defines three labeled fixtures under both policy profiles.
- Evaluation records exact child observations, expectations, exclusions, pairs, explicit metric
  fractions, confusion counts, and eligible recorded legacy timing.
- CLI commands `investigate` and `evaluate` preserve the existing command surface.

## Evidence recorded so far

- Branch base: merged Phase 3 revision `ed328355f9c9460c0f12720db342e37e525371e3`.
- Pre-change baseline: Ruff format/check clean, strict MyPy clean, 90 tests passed.
- Human security review: approved by the project owner on 2026-09-12 for the Phase 4 evidence,
  rule-set, and suite SHA-256 implementation.
- Runtime: Python 3.13.15 on Windows.
- Ruff format/check: clean across `src` and `tests`.
- Strict MyPy: clean across 43 source/test files.
- Pytest on 2026-09-13: 114 passed (`python -m pytest --cov=agentsec
  --cov-report=term-missing --cov-fail-under=90`).
- Coverage: 90.81%, satisfying the 90% gate.
- Fingerprint vectors: fixed snapshot, complete packaged rule-set, and packaged-suite values pass.
- Current build: `agentsec_lab-0.4.0.tar.gz` and `agentsec_lab-0.4.0-py3-none-any.whl` succeeded.
- Wheel contents: Phase 4 modules and `resources/evaluation_suites/core-lab-v1.json` present.
- Current installed-wheel smoke test: isolated import from a temporary wheel installation,
  `evaluate` passed all 6/6 children, restricted paired prevention was 1/1, and an artifact scan
  found no raw canary.
- Dependency audit: no known vulnerabilities; the editable project distribution was skipped.

Local tests ran on the `phase-4-incident-evaluation` feature branch. Passing regression tests do
not establish all C01–C13 requirements or substitute for exact-commit CI.

## Acceptance gaps found and repaired on 2026-09-13

The following were confirmed gaps. Each now has implementation changes and focused regression
coverage; this is not an exhaustive C01–C13 audit:

1. **C04/C10 — Historical timing accepts invalid evidence.** Bounded in-memory probes of
   `_historical_timing` returned alert latency `3.0`, incident latency `2.0`, and no exclusion
   despite the incident clock preceding the alert. A second probe removed both linked alert IDs
   and still returned eligible `3.0`/`4.0` timing. The probes also used a one-document evidence list
   without a validated legacy chain or rule version. Validate the complete linkage and causal
   timestamp order before accepting a sample. **Repaired:** timing now resolves the ordered
   document, secret read, sink, detection, alert, and incident chain; requires supported rule
   version, identifiers, and UTC clock order; invalid probes now exclude the sample.
2. **C05/C07 — Stage classification can disagree with impact evidence.** A sink event with
   `matched: true`, `redacted: true`, and an incorrect canary ID was labeled `simulated_impact`
   by `_stage_for_event`. Stage classification needs the relevant payload checks required by the
   impact contract. **Repaired:** stage checks the matching canary and recorded request-body
   observation; snapshot validation checks relevant field types and required links without
   coercing booleans or integers.
3. **C07/C08 — Evaluation does not use one canonical observation snapshot.** Code inspection of
   `evaluation.py` shows an `EventStore` read for child metadata, a separate investigation read,
   and impact/prevention taken from the original runner report. Secret-access/outbound facts
   default to false when no incident exists. Derive and validate all child observations from the
   exact snapshot used for investigation, independently of whether a rule matched. **Repaired:**
   investigation returns its captured events; evaluation derives and cross-checks all child facts
   from them, including secret-access and outbound-attempt observations with no incident.
4. **C11 — Publication ownership and cleanup are insufficiently guarded.** Both Phase 4 writers
   use fixed temporary names with non-exclusive writes and remove any existing temporary/final
   paths on failure. **Repaired:** exclusive staging and no-overwrite hard links publish both
   files; only invocation-owned files are rolled back, while cleanup errors are attached to the
   original failure. The injected second-link failure, preexisting-temp, and failed-cleanup cases
   pass.
5. **C12 — Imported-query and rule-scan limits remain incomplete.** The reused reader does not
   reject an `events` view or install a query-work bound. The rule engine scans all trace events
   for each partial candidate; its candidate counter does not count nonmatching scans. The plan
   explicitly calls for these cases to be bounded and regression-tested. **Repaired:** imported
   `events` views are rejected, SQLite VM query steps are bounded, and per-step candidate indexing
   limits nonmatching scans while preserving rule-match semantics.
6. **C09/C12 — Suite reporting and resource handling need completion.** The aggregate artifact
   check precedes the final evaluation report writes. Resource exceptions outside
   `EvaluationResourceLimitExceeded` follow the generic child-failure path and do not stop later
   children. The Markdown output omits recorded timeline timestamps/historical markers and
   paired child observations; the specified vulnerable-impact-restricted paired prevention
   metric is not implemented. **Repaired:** final report size is reserved under the aggregate
   budget; evidence/resource failures stop later children and record not-run cases; Markdown
   includes recorded timestamps, historical markers, and paired outcomes. The restricted paired
   prevention fraction is explicit in JSON and Markdown.

The original probes demonstrated defects despite the former green suite. New regressions cover
reversed clocks, missing links, wrong-canary stages, typed metadata, Unicode-escaped suite canary,
write rollback, failed cleanup, stale temporary files, query/view limits, scan cost, global evidence failure,
child metadata/multi-trace mismatch, final aggregate budget, and paired metric arithmetic.

## Remaining gates

1. Complete the broader C01–C13 acceptance evidence matrix; focused regressions above do not
   cover every case in the implementation plan.
2. Final human review of the complete Phase 4 diff, especially the sensitive hashing, replay
   query, and rule-evaluation changes.
3. Windows/Linux CI on the exact commit and record its links/results. The repository workflow
   uses `workflow_dispatch`; a human must start it.

Phase 4 must not be marked complete until these gates and C01–C13 in the implementation plan have
recorded evidence.

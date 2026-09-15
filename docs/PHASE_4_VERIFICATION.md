# Phase 4 verification record

Status: **Complete.** The project owner completed the final Phase 4 review and approved Phase 4
completion on 2026-09-15. The six previously observed gaps have focused regressions and fixes.

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
- Exact merged revision: `dd3dbe1d6bd465ca0259b0e2a8380eb4029e78e8`.
- GitHub Actions run [34773243387](https://github.com/jiraphat-j/AgentSec/actions/runs/34773243387)
  was reported by the project owner as passing on Windows and Ubuntu for `dd3dbe1`.
- Final human review: on 2026-09-15 the project owner confirmed review of evidence hashing,
  read-only replay, rule evaluation, incident/evaluation logic, artifact publication, redaction,
  and isolation boundaries, and approved Phase 4 completion.

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

## Gate closure

- The C01–C13 evidence inventory below records the available focused and suite evidence.
- The project owner completed the final review and accepted this evidence for Phase 4 completion.
- Human-dispatched Windows and Ubuntu CI passed for the merged revision; the run link is recorded
  above. This report relies on the owner's direct observation because the run was not accessible
  through the available automated GitHub reader.

## C01–C13 evidence inventory (2026-09-14)

This is a read-only mapping from existing test source and the earlier local results above; the
tests were not rerun for this inventory. A named test shows a relevant check, not necessarily full
coverage of every clause in its criterion. The project owner reviewed this evidence and approved
Phase 4 completion. Items in the last column remain useful regression-expansion opportunities and
are not known defects or Phase 5 prerequisites.

| Criterion | Existing directly relevant evidence | Future regression expansion |
|---|---|---|
| C01 Entry/compatibility | Existing `test_end_to_end.py`, `test_replay.py`, `test_rule_engine.py` regressions; prior full suite passed | Record exact-commit compatibility result and legacy schema/CLI checklist |
| C02 Incident correctness | `test_investigation_is_read_only_and_derives_one_trace_incident`, `test_benign_and_incomplete_investigations_do_not_invent_outcomes`, `test_packaged_evaluation_runs_exact_closed_matrix` | Document strict-profile investigation and denial/no-impact assertions explicitly |
| C03 Isolation/deduplication | `test_sequence_and_correlation_are_deterministic_and_trace_isolated`, `test_correlation_never_combines_evidence_across_runs`, `test_repeated_events_enumerate_distinct_matches_and_deduplicate_identity` | Demonstrate incident-level isolation across runs/traces/snapshots/rule sets and exact-match deduplication |
| C04 Evidence resolution | `test_failed_lifecycle_keeps_positive_facts_unknown_and_references_consistent` rejects one changed fingerprint; source identity is checked in investigation path | Resolve every stage/outcome/alert/incident/explanation reference to an actual source event; test forged, missing, and duplicate references |
| C05 Timeline honesty | `test_investigation_is_read_only_and_derives_one_trace_incident` checks sequence order | Test equal/reversed timestamps and benign/dispatch stage language against exact evidence |
| C06 Integrity | `test_phase_4_fingerprint_fixed_vectors` fixes three vectors and checks event/rule content sensitivity | Record selected-snapshot/unrelated-run stability and limitation review with test evidence |
| C07 Outcome/lifecycle | `test_benign_and_incomplete_investigations_do_not_invent_outcomes`, `test_investigation_rejects_evidence_after_terminal_event`, `test_failed_lifecycle_keeps_positive_facts_unknown_and_references_consistent` | Add or identify malformed, contradictory, post-terminal and mixed-call outcome cases as one acceptance set |
| C08 Ground truth | `test_packaged_evaluation_runs_exact_closed_matrix`, `test_child_validation_rejects_wrong_metadata_and_multiple_traces` | Prove changing labels cannot change rule results; document wrong profile/trial and suite-assertion failures |
| C09 Metrics | `test_metric_denominators_failures_zero_samples_and_recorded_timing`, `test_packaged_evaluation_runs_exact_closed_matrix`, `test_evaluation_deadline_accounts_for_every_not_run_child` | Cover unequal paired failures and repetition counts beyond the one-trial happy path |
| C10 Timing | `test_historical_timing_rejects_reversed_clocks_and_missing_links`, `test_metric_denominators_failures_zero_samples_and_recorded_timing` | Demonstrate exact source-event timing basis, offline-unavailable labels, and all exclusion cases |
| C11 Safe execution/output | `test_investigation_is_read_only_and_derives_one_trace_incident`, `test_evaluation_uses_no_socket_or_dns`, `test_phase_4_reports_refuse_overwrite_and_exclude_raw_canary`, publication-failure tests | Check hostile metadata escaping and encoded-canary cases across all generated surfaces; final diff review |
| C12 Limits | `test_imported_query_work_is_bounded`, `test_rule_step_filter_scans_each_event_only_once_per_step`, `test_final_evaluation_report_obeys_aggregate_budget`, `test_evaluation_deadline_accounts_for_every_not_run_child` | Assemble boundary evidence for every event/candidate/alert/trace/report/suite/deadline ceiling |
| C13 Delivery | Prior local Ruff, MyPy, 114 tests, build, audit, isolated wheel smoke, owner sign-off, and Windows/Ubuntu run 34773243387 for `dd3dbe1` | Preserve links and exact revisions in future phase records |

The tests for several rows may exercise parts of the expansion clause indirectly. Future changes
should cite specific assertions or add focused regressions rather than treating a broad test name
as proof of a new claim.

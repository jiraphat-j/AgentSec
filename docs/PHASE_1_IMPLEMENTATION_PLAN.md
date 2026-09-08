# Phase 1 implementation plan — Core Lab Vertical Slice

Status: implemented and locally verified on Windows with Python 3.13.15; GitHub CI run pending.

This plan closes the remaining Phase 0 contracts and delivers Phase 1. The implementation
candidate follows these work packages. Human review was approved and the local verification
gates passed on 2026-09-08. The manual Windows/Linux GitHub workflow remains to be run after the
changes are committed and available to GitHub.

## 1. Read before implementing

Read [AGENTS.md](../AGENTS.md) and its linked guidance, then:

1. [README](../README.md) and [Project Brief](../PROJECT_BRIEF.md).
2. [MVP Scope](../MVP_SCOPE.md), the authority for first-release scope.
3. [Threat Model](../THREAT_MODEL.md).
4. [Decision Register](../DECISIONS.md) and accepted [ADRs](adr/).
5. [Roadmap](../ROADMAP.md).
6. Relevant sections of the [architecture draft](../AGENTSEC_CONCEPT_AND_ARCHITECTURE_DRAFT.md); its examples are not accepted schemas.

Planning used the repository's security, domain, Definition of Done, issue-tracker, triage, and Wayfinder guidance. No available specialized SKILL.md directly matches local Python implementation planning; artifact-generation and external-service skills are not dependencies of this work. Reassess available skills at implementation time and read any relevant skill before applying it.

At planning time, the repository contains documentation only. AGENTS.md and docs/agents/ are existing untracked user files: preserve them and do not silently stage them with implementation changes. Reinspect Git status before work. No GitHub issues were created or queried for this plan; the work IDs below are local planning IDs, not issue numbers.

## 2. Product outcome and scope

One installed CLI command runs this sequence:

```text
Untrusted document enters mock-agent context
  -> read_file through Tool Gateway
  -> seeded virtual canary returned
  -> http_post through Tool Gateway
  -> lab://exfiltration-sink records attempted transfer in process
  -> detection reads canonical SQLite evidence
  -> critical alert and one incident
  -> JSON and Markdown reports
```

Trusted components record telemetry as actions occur. Initial detection runs after scenario execution; concurrency is not needed. A benign fixture provides the negative control for the same scenario. A mock validates pipeline behavior, not real-model prompt-injection susceptibility.

Accepted baseline: Python >=3.13,<3.14, SQLite, deterministic mock agent, one process, two tools, one primary correlation rule, required JSON/Markdown reports. No scenario sockets, DNS, host access, subprocesses, or arbitrary code. The trusted controller may read packaged fixtures and write approved local artifacts; agent inputs cannot select host paths or storage locations.

Deferred: strict-policy comparison, real LLMs, API, dashboard, Docker, shell, RAG/MCP/memory/multi-agent attacks, benchmarks, generic rule DSL, brokers, and JSONL export/replay. Optional JSONL is not a completion dependency. License selection remains an owner decision before claiming an open-source release, not a prerequisite for coding.

## 3. Proposed implementation defaults

These are proposals to record during P1-01, not existing accepted ADRs:

| Area | Proposed default | Reason |
|---|---|---|
| Package | src/agentsec with a thin CLI and separate domain modules | Small, testable package without future empty directories |
| CLI and storage | argparse and sqlite3 from the standard library | Existing requirements need no service framework or ORM |
| Validation | Pydantic strict models, extra fields forbidden | Explicit validation at scenario, tool, event, and report boundaries |
| Scenario format | JSON, packaged trusted fixture identifiers | YAML is only proposed; JSON avoids another parser dependency |
| Detection | One versioned Python correlation rule | A general authoring language is beyond this slice |
| Quality | Pytest, Ruff, strict MyPy, GitHub Actions | Matches the repository's testing and typing requirements |
| Packaging | Minimal standards-based build configuration | Verify wheel installation and bundled fixture availability |

Check compatibility and dependency vulnerabilities when selecting actual versions; this plan makes no claim about current package versions. Record dependencies and reproducible installation instructions. Keep FastAPI deferred, consistent with ADR-001; the older P-002 register entry still asks a CLI/API question that ADR-001 already settles.

Proposed user command, not runnable yet:

```text
agentsec run indirect-injection-secret-exfiltration --output-dir ./artifacts
```

Create a new run subdirectory containing events.sqlite3, report.json, and report.md. Refuse accidental overwrite. Exit 0 means execution and required outputs completed, including an expected detected attack; 2 means invalid CLI/configuration input; 1 means runtime, timeout, or artifact-generation failure. Detection outcome is a separate report field.

## 4. Work packages and dependencies

```text
P1-01 Contracts -> P1-02 Scaffold -> P1-03 Evidence store ----+
                                 -> P1-04 Controlled tools -+-> P1-05 Runner
                                                               -> P1-06 Detection/report
                                                               -> P1-07 Verification/demo
```

P1-03 and P1-04 have independent interfaces after contracts are stable. They may be scheduled independently; this plan does not request or authorize spawning additional agents. Add relevant tests with each package rather than postponing all verification until P1-07.

### P1-01 — Finish Phase 0 contracts

Deliver versioned scenario, tool, event, alert/incident, and report definitions, sample fixtures, and a contract document. Record routine implementation choices in DECISIONS.md or an ADR as appropriate.

Resolve these details explicitly:

- Virtual path mismatch: the draft uses /workspace/.env, while the threat model rejects absolute paths. Propose exactly workspace/.env as a virtual dictionary key; reject absolute, traversal, backslash, and unknown alternatives. Align examples without adding host-path resolution.
- Define strict allowed fields and types. Scenario data cannot choose trusted event IDs, policy outcomes, adapter implementations, arbitrary fixture paths, or arbitrary imports.
- Assign schema_version, event_id, run_id, trace_id, timestamp, source_component, and monotonically increasing per-run sequence through trusted code. Correlate both tool calls and document provenance under the same run and trace; distinguish calls with tool_call_id.
- Retain tool.requested as the sole proposed-tool-action event. Specify allowed, denied, validation-failed, adapter-failed, and limit-exceeded paths. Define tool.executed consistently with the event order required by MVP_SCOPE; if successful completion needs a separate event, record that schema choice rather than silently reordering required events.
- Define the mock's fixed malicious-instruction trigger and benign behavior. Expected outcome metadata belongs to test assertions; it must not decide detection results.
- Use a seeded fake canary only in packaged fixtures and ephemeral state. Persist identifiers and hashes, never raw tool bodies containing it. Omit raw-value debug mode from the MVP.
- Define attempt, simulated impact, critical alert, incident, and no-match output. A complete chain needs sink observation of the same canary, not merely a proposed HTTP call.
- Proposed hard maximums: 64 KiB document, 16 KiB tool body, 8 tool requests, 128 events, 1 MiB per report, and a 5-second scenario deadline. Finalize bounded encoding rules, rejected oversized inputs, terminal-event capacity, and cleanup. Scenario settings may reduce but not raise safety ceilings.
- Define run lifecycle and report-generation events without circular evidence dependencies. Reports reference an explicit evidence cutoff; later report.created and terminal lifecycle events may be stored after that cutoff. Failed writes must never record successful report creation.
- Define timestamps/IDs injection for tests, logical equivalence across real runs, and failure output when SQLite itself is unavailable.

Provide examples for malicious, benign, missing-canary, rejected request, forged event fields, and failed run cases. Map every MVP acceptance criterion to a test below.

Exit: every required contract has an example and no unresolved contract ambiguity prevents Core Lab implementation. Document review establishes Phase 0 readiness; runtime verification occurs during Phase 1.

### P1-02 — Package and quality scaffold

Depends on P1-01.

Create pyproject.toml, src/agentsec, tests, packaged scenario resources, .gitignore, and CI configuration. Expose the agreed CLI. Document Python 3.13 installation and developer checks. Add SECURITY.md and CONTRIBUTING.md consistent with the existing agent guidance; leave license terms to the owner.

Exit: a built wheel installs into a clean environment, CLI help works, packaged fixtures are accessible outside the repository checkout, and initial lint/type/test checks pass. No fake successful scenario command before implementation exists.

### P1-03 — Canonical evidence persistence

Depends on P1-02.

Implement validated append-only event insertion and queries, schema versioning, indexes, transactions, and run isolation. Use sequence as the ordering tie-breaker. Redact at event construction before storage. Detection/reporting read SQLite rather than an independent in-memory event history.

Tests: reopen and retrieve records; equal timestamps retain causal order; duplicate identities are rejected; separate runs cannot contaminate one another; payload fields cannot forge trusted envelopes; failed insertion does not produce a falsely successful run; raw canary never appears in persisted payloads.

Exit: the event store provides reliable, ordered evidence for downstream consumers.

### P1-04 — Gateway, policy, and virtual adapters

Depends on P1-02 and the P1-01 event-collector interface.

Implement a closed registry containing read_file and http_post, strict validation, mandatory safety rules independent of vulnerable policy, and policy decisions with reasons. Use a seeded mapping for files and a dedicated socket-free sink. Canary comparison occurs in memory; persisted sink evidence includes canary_id, value_sha256, observed_in, and redacted.

Tests: only the exact fake key and sink work; reject host paths, traversal, alternate separators, IP/hostname/HTTP(S)/protocol-relative destinations, unknown tools, missing/extra/wrong-type fields, and oversized bodies. Prove denied requests never invoke adapters. Guard socket creation and DNS APIs during supported scenario execution. Inspect adapter code for direct host/network/process access.

Exit: positive tool behavior and mandatory denials are observable. Follow the review gate in section 6 before executing changes that fall under repository review restrictions.

### P1-05 — Mock agent and bounded scenario runner

Depends on P1-03 and P1-04.

Implement trusted fixture loading, run setup, document provenance, deterministic mock actions, controller orchestration, CLI dispatch, and cleanup. The benign variant returns without the malicious chain. No external provider, key, dynamic code, or plugin loading is required.

Enforce input/action/event/output limits and check a monotonic deadline at bounded steps. Avoid blocking arbitrary calls; cooperative checks in this fixed in-process mock are not a general hard timeout for arbitrary code. Ensure evidence is preserved on failure when storage remains usable and ephemeral canary state is discarded.

Tests: exact malicious tool sequence, benign behavior, limits and simulated deadlines using an injected clock, clean failure paths, and consecutive-run isolation. Compare normalized behavior rather than requiring identical live timestamps or run IDs.

Exit: the installed CLI reliably produces canonical evidence for the full intended attack attempt.

### P1-06 — Correlation, incident, and reports

Depends on P1-05. Detection can be developed against P1-03 event fixtures earlier.

Implement one ordered rule keyed by run and trace, matching document provenance, fake-secret read/access attempt, and recorded matching-canary sink evidence. Include rule ID/version and exact evidence IDs. Re-evaluation must not duplicate the run's incident.

Generate required report fields from stored evidence: identity, executive summary, vector, actions, timeline, detection result, attempted impact, root cause, remediation, evidence, and limitations. A benign run still produces a result report with no critical incident. Escape untrusted Markdown and terminal controls. Write bounded artifacts without overwriting other runs and report partial write failure accurately.

Tests: positive chain; benign/no-canary/incomplete chain; wrong canary; wrong order; cross-run/cross-trace events; duplicate evaluation; resolvable evidence IDs; JSON structure; hostile report text; raw-canary scans of JSON, Markdown, stdout, stderr, errors, and SQLite payloads; failed report generation.

Exit: both report formats explain the same evidence-backed outcome and explicitly label simulation and attempted exfiltration.

### P1-07 — Clean-install verification and CV demo

Depends on P1-06.

Run acceptance and threat-model tests through the installed package, plus formatting, lint, strict typing, build/install checks, and a dependency vulnerability audit for added dependencies. CI should exercise Python 3.13 on Windows and Linux. Test execution and the scenario require no external service; dependency installation/auditing can need network access separately.

Update README status only to what has been verified. Add installation/run instructions, an example redacted report, output-file explanations, test commands, and a brief demo walkthrough. Document known limitations and unresolved license status. Include relevant security review evidence in the handoff.

Exit: all acceptance criteria below pass, required reviews are confirmed, and another person can reproduce the demo from a clean installation.

## 5. Acceptance traceability

Numbers correspond to MVP_SCOPE.md, not new requirements.

| MVP criterion | Verification | Work package |
|---|---|---|
| 1: one command | Installed CLI completes scenario and writes artifacts | 02, 05, 07 |
| 2: deterministic mock, no API key | Offline scenario execution with no provider credentials | 05, 07 |
| 3: document causes read request | Malicious fixture produces expected request and provenance | 05 |
| 4: gateway/policy evidence | Requests have correlated decisions; no direct adapter bypass | 04, 05 |
| 5: simulated secret read | Exact seeded key returns canary only in controlled memory | 04 |
| 6: simulated HTTP request | Sink receives expected canary through validated gateway | 04, 05 |
| 7: no socket | Socket and DNS guards plus adapter inspection | 04, 07 |
| 8: reconstructable chain | Persisted IDs and sequence recover complete ordered evidence | 03, 05 |
| 9: evidence-linked detection | Ordered positive match and valid evidence references | 06 |
| 10: complete incident report | Required JSON/Markdown content and simulation wording | 06 |
| 11: repeatable positive test | Repeated runs have equivalent normalized results | 05, 07 |
| 12: negative control | Benign and absent-canary flow produce no critical incident | 05, 06 |
| 13: mandatory rejection tests | External/host/unknown/invalid requests denied before effects | 04 |
| 14: no raw canary in human reports | Artifact and console/error scans | 03, 06, 07 |

Additional mandatory threat-model checks cover event forgery, resource limits, report injection, cleanup, and cross-run isolation. Passing the positive demo alone does not complete Phase 1.

## 6. Review and handoff rules

Follow [security.md](agents/security.md), especially its instruction that specified sensitive code changes "must NOT be merged or executed autonomously" and require explicit human review/sign-off. Hashing changes are expressly included, so canary digest implementation has a review gate. Prepare the minimal implementation and test definitions for review; do not claim execution or test success before allowed verification occurs. For other changes, assess the actual listed conditions rather than treating every project file as sensitive. Mark applicable handoffs `Security Sensitive: Requires Mandatory Human Review` and keep them open until confirmed.

When GitHub issue work is subsequently requested/authorized, map P1-01 through P1-07 to concrete issues and dependencies using the repository's issue/triage guidance. Do not interpret this local plan as evidence of existing issues, assignments, approvals, or completed work.

Each implementation handoff should state: changed files, behavior delivered, exact checks and results, acceptance criteria satisfied, remaining work, and review status. Preserve user changes and avoid mixing unrelated untracked files into commits.

## 7. Suggested prompt for the implementation model

> Read AGENTS.md, docs/PHASE_1_IMPLEMENTATION_PLAN.md, and their referenced scope/security documents. Implement the plan beginning with P1-01, preserving the accepted MVP boundaries and existing user changes. Record proposed choices before dependent implementation, complete one work package at a time with its meaningful verification, and follow mandatory human review gates for applicable sensitive code. Do not claim Phase 1 completion until all 14 MVP acceptance criteria and required reviews are satisfied. Keep the owner informed of delivered milestones and actual blockers.

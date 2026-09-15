# AgentSec Lab — Decision Register

> Last updated: 2026-09-12
> This register separates current decisions from ideas in the architecture draft. It does not replace Architecture Decision Records (ADRs). Long-lived implementation decisions should receive an ADR when development begins.

The non-negotiable MVP security boundary is defined in [THREAT_MODEL.md](THREAT_MODEL.md).

## Status Definitions

- **DECIDED** — Current baseline; change through a new explicit decision
- **PROPOSED** — Recommended direction that has not been accepted
- **RESEARCH** — Requires evidence or a prototype before deciding
- **POST-MVP** — Intentionally excluded from the first Vertical Slice

## Decided

| ID | Decision | Rationale |
|---|---|---|
| D-001 | The project is named **AgentSec Lab** | Matches the source concept and positioning |
| D-002 | Describe the project as a **planned open-source** detection-engineering lab until a license is approved and added | A public repository without an open-source license is not fully open source |
| D-003 | The MVP contains one Vertical Slice: Indirect Prompt Injection → Fake Secret Access → HTTP Exfiltration Attempt → Telemetry → Detection → Incident Report | Proves end-to-end value before expansion |
| D-004 | Use fake or canary secrets only | Avoids real credential impact and enables data-flow tracing |
| D-005 | Model HTTP exfiltration with a socket-free simulated sink; never target an external system | Establishes a safe lab boundary |
| D-006 | The agent accesses files and network only through the Tool Gateway | Creates an observable enforcement point |
| D-007 | The MVP is CLI-first and deterministic | Supports CI and reproducibility without requiring a paid API |
| D-008 | `MVP_SCOPE.md` is the source of truth for MVP scope | Prevents broader source-PDF scope from returning accidentally |
| D-009 | The dashboard, advanced attacks, and benchmarks are not MVP dependencies | Keeps the first Vertical Slice deliverable |
| D-010 | The concept and architecture document remains a draft | Logical components and stack choices are not final contracts |
| D-011 | MVP exfiltration uses an in-process `LabHttpSinkAdapter` at `lab://exfiltration-sink`; it opens no operating-system network socket | Eliminates DNS, routing, Docker-network, and accidental-egress risk |
| D-012 | Human-readable reports never store raw fake-secret or canary values; they store a canary ID and SHA-256 hash | Safe by default even when a value does not match an expected pattern |
| D-013 | The MVP vulnerable profile allows fake-secret access and the lab sink, but denies host paths, external destinations, unknown tools, and invalid schemas | “No defense” against the scenario must not mean “no safety controls” for the developer machine |
| D-014 | The MVP emits only `tool.requested` for the proposed tool action; `actor.type: ai_agent` identifies its origin | Avoids ambiguity between `agent.tool.requested` and `tool.requested` |
| D-015 | Use Python 3.13 as the core runtime baseline with compatibility `>=3.13,<3.14`; do not pin a patch version | Establishes a stable baseline while accepting compatible security and bug-fix patches |
| D-016 | SQLite is the canonical event store; JSONL is an optional export/replay artifact; JSON and Markdown are required report formats | Gives each artifact one unambiguous role and keeps SQLite as the source of truth |
| D-017 | The Phase 1 package, validation, fixture, CLI, and initial detection choices are defined by ADR-004 | Converts the accepted architecture into a small executable contract without adding an API or general rule language |
| D-018 | The exact fake-file resource key is `workspace/.env`, a virtual dictionary key rather than an operating-system path | Removes the ambiguity between the draft absolute example and the prohibition on host absolute paths |
| D-019 | Events use a trusted per-run integer sequence as their causal ordering key; timestamps remain descriptive evidence | Gives deterministic ordering when timestamps are equal or injected in tests |
| D-020 | Default runs omit raw-value debug mode; raw canaries may exist only in packaged test fixtures and ephemeral adapter state | Reduces leakage surfaces in the first implementation |
| D-021 | Phase 1 detection is one versioned Python rule, `ASL-CORR-001`; a general rule DSL remains post-MVP research | Implements the required correlation without prematurely fixing an authoring format |
| D-022 | Phase 1 scenario resources are strict packaged JSON identified by a closed fixture name | Prevents scenario data from selecting arbitrary host files or executable components |
| D-023 | The CLI uses exit 0 for a completed run, 2 for invalid user input, and 1 for runtime or artifact failure; detection outcome is reported separately | Keeps process success distinct from security outcome |
| D-024 | Phase 2 uses closed `vulnerable` and `strict` profiles with mandatory safety checks evaluated before profile policy | Enables comparison without making host isolation configurable |
| D-025 | `risk-v1` is a deterministic, explainable educational heuristic; it is not a probability or calibrated risk framework | Makes policy reasoning visible without overstating two fixtures as empirical evidence |
| D-026 | Approval is synchronous simulation, bound to one run/trace/call/policy version and consumed once; it cannot override safety or strict hard denials | Exercises approval telemetry without external identity, queues, or services |
| D-027 | New Phase 2 events and reports use schema 0.2; scenario schema stays 0.1 and legacy 0.1 events remain readable | Versions the expanded outcome contract without letting scenario data select policy |
| D-028 | The comparison command runs isolated vulnerable and strict children and derives reports from each canonical SQLite store | Keeps evidence authoritative and prevents cross-run contamination |
| D-029 | Phase 3 declarative detections use strict bounded JSON schema 1.0; YAML and executable plugins remain deferred | Makes rules reviewable data and resolves the initial authoring-format question narrowly |
| D-030 | Replay reads one selected run from existing SQLite through a dedicated read-only connection and never invokes the scenario runtime | Preserves canonical evidence and prevents replay from causing tool effects |
| D-031 | Threshold rules remain deferred until a documented benign baseline exists | Prevents unsupported thresholds and false-positive claims from synthetic examples |
| D-032 | Phase 4 derives one immutable investigation incident per matched run/trace and never groups across snapshots or rule sets | Makes evidence navigation deterministic without claiming campaign attribution |
| D-033 | `core-lab-v1` uses explicit attack/benign labels and run-level `metrics-v1` denominators | Resolves lab outcome definitions without presenting synthetic fixtures as production accuracy |
| D-034 | Phase 4 fingerprints validated logical event snapshots and complete rule definitions with versioned SHA-256 serialization | Detects content changes while explicitly making no authenticity or custody claim |
| D-035 | Historical alert/incident timing is reported only from validated linked source events; offline processing time remains separate | Prevents replay duration from being mislabeled MTTD or MTTI |
| D-036 | Phase 5 is an optional read-only local dashboard bound to `127.0.0.1`, backed by a strict artifact manifest and packaged assets | Makes demonstrations understandable without turning the browser into an execution or evidence-authoring surface |

## Proposed

| ID | Proposal | Why it is attractive | Decision needed |
|---|---|---|---|
| P-002 | Use FastAPI and Pydantic for API and schema boundaries | Typed contracts and a path to the dashboard | Decide whether MVP needs an API or begins as a library and CLI |
| P-006 | Use a Sigma-inspired detection syntax | Familiar to detection engineers | Validate whether useful conversion or reuse is practical |
| P-007 | Use a monorepo and begin with a small package layout | Minimizes early structural overhead | Confirm package layout |
| P-009 | Use Docker isolation when process and real-network scenarios arrive | Clear boundaries and repeatable reset | Revisit only when a post-MVP scenario requires OS-level telemetry |
| P-010 | Select Apache-2.0 as the project license | Explicit patent grant and termination language fit a security tool better than MIT | Formal owner approval before adding `LICENSE` |

## Needs Research

| ID | Question | Required evidence |
|---|---|---|
| R-002 | How should later phases collect real network telemetry safely? | Container network and controlled-proxy prototype; this does not block the socket-free MVP |
| R-003 | Should the event schema map to OCSF, ECS, OpenTelemetry, or remain custom? | Mapping spike focused on agent-specific context |
| R-007 | Which model output or reasoning metadata can be stored safely? | Privacy, provider terms, and observability requirements; do not require hidden chain-of-thought |
| R-008 | How can real-LLM tests remain reproducible and cost-bounded? | Opt-in integration-test and replay design |
| R-009 | Which security mappings suit AI-agent attack chains? | Evaluate ATT&CK, ATLAS, and OWASP mappings without overclaiming |
| R-010 | What should a Thai prompt-injection benchmark measure, and how will it be licensed? | Dataset design, annotation, provenance, and evaluation method |

## Deferred Until After MVP

| ID | Item | Revisit trigger |
|---|---|---|
| F-001 | Direct prompt-injection scenarios | Core Vertical Slice is stable |
| F-002 | RAG poisoning and ingestion pipeline | Document provenance and schema are ready |
| F-003 | Tool and MCP poisoning | Tool-metadata trust model is ready |
| F-004 | Shell execution and process telemetry | Container isolation passes security tests |
| F-005 | Memory poisoning | Persistent-memory model is defined |
| F-006 | Multi-agent and cross-agent injection | Single-agent correlation is stable |
| F-007 | Policy simulator | A safe hypothetical-policy contract is defined |
| F-008 | PostgreSQL, Redis Streams, NATS, or Kafka | A measured scale or query requirement exists |
| F-009 | Behavioral and threshold detection | A benign baseline dataset exists |
| F-010 | Thai attack dataset and adaptive generator | Dataset governance is ready |
| F-011 | Grafana and Loki observability stack | Core telemetry contract is stable |
| F-012 | Production authentication, RBAC, and multi-tenancy | A production-deployment goal exists |

## Phase 2 Planning Direction

The owner requested Phase 2 planning after the Phase 1 merge. Strict-policy comparison remains
outside the completed MVP and is the next phase's objective. See
[Phase 2 implementation plan](docs/PHASE_2_IMPLEMENTATION_PLAN.md) for the policy, risk,
approval, and comparison contracts. Those contracts are recorded in ADR-005. Acceptance of the
architecture does not establish security review or test execution approval for its implementation.

## Phase 3 Detection Engineering Direction

Phase 3 adopts bounded JSON rule data, typed single-event, sequence, and correlation evaluation,
exact positive and negative fixtures, and read-only SQLite replay. Threshold rules remain deferred
until a benign baseline exists. See the [Phase 3 plan](docs/PHASE_3_IMPLEMENTATION_PLAN.md) and
ADR-006.

## Phase 4 Incident and Evaluation Direction

Phase 4 adopts immutable trace-level incident snapshots, logical snapshot and rule-set
fingerprints, and the closed `core-lab-v1` evaluation suite. Run-level metric definitions and
recorded-only historical timing are fixed by ADR-007. Fingerprints provide change detection, not
source authentication or cryptographic custody.

## ADR Index

- [ADR-001: Core Language and Runtime](docs/adr/ADR-001-core-language-and-runtime.md) — **Accepted**
- [ADR-002: MVP Event Persistence](docs/adr/ADR-002-mvp-event-persistence.md) — **Accepted**
- [ADR-003: MVP Isolation and No-Egress Strategy](docs/adr/ADR-003-mvp-isolation-and-no-egress.md) — **Accepted**
- [ADR-004: Phase 1 Package and Contract Implementation](docs/adr/ADR-004-phase-1-package-and-contracts.md) — **Accepted**
- [ADR-005: Phase 2 Runtime Policy and Comparison](docs/adr/ADR-005-phase-2-runtime-policy-and-comparison.md) — **Accepted**
- [ADR-006: Phase 3 Detection Rules and Offline Replay](docs/adr/ADR-006-phase-3-detection-rules-and-replay.md) — **Accepted**
- [ADR-007: Phase 4 Incident Investigation and Evaluation](docs/adr/ADR-007-phase-4-incidents-and-evaluation.md) — **Accepted**
- [ADR-008: Phase 5 Read-only Local Dashboard](docs/adr/ADR-008-phase-5-read-only-dashboard.md) — **Accepted**

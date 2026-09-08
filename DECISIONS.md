# AgentSec Lab — Decision Register

> Last updated: 2026-09-08
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

## Proposed

| ID | Proposal | Why it is attractive | Decision needed |
|---|---|---|---|
| P-002 | Use FastAPI and Pydantic for API and schema boundaries | Typed contracts and a path to the dashboard | Decide whether MVP needs an API or begins as a library and CLI |
| P-005 | Define scenarios and rules in YAML | Human-readable and version-control friendly | Define schema and versioning |
| P-006 | Use a Sigma-inspired detection syntax | Familiar to detection engineers | Validate whether useful conversion or reuse is practical |
| P-007 | Use a monorepo and begin with a small package layout | Minimizes early structural overhead | Confirm package layout |
| P-008 | Add vulnerable-versus-strict comparison immediately after MVP | Demonstrates prevention and detection in one demo | Decide whether this belongs in the MVP demo |
| P-009 | Use Docker isolation when process and real-network scenarios arrive | Clear boundaries and repeatable reset | Revisit only when a post-MVP scenario requires OS-level telemetry |
| P-010 | Select Apache-2.0 as the project license | Explicit patent grant and termination language fit a security tool better than MIT | Formal owner approval before adding `LICENSE` |

## Needs Research

| ID | Question | Required evidence |
|---|---|---|
| R-002 | How should later phases collect real network telemetry safely? | Container network and controlled-proxy prototype; this does not block the socket-free MVP |
| R-003 | Should the event schema map to OCSF, ECS, OpenTelemetry, or remain custom? | Mapping spike focused on agent-specific context |
| R-004 | Should detection rules be custom DSL, Sigma-inspired, or code-first? | Sequence semantics, validation, and authoring prototype |
| R-005 | How will the project define attack success, attempted impact, and completed impact? | Metric definitions and sample reports |
| R-006 | What evidence-integrity level is appropriate for a lab? | Evaluate artifact digests, hash chaining, and append-only records |
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
| F-007 | Dashboard and policy simulator | CLI and report contracts are stable |
| F-008 | PostgreSQL, Redis Streams, NATS, or Kafka | A measured scale or query requirement exists |
| F-009 | Behavioral and threshold detection | A benign baseline dataset exists |
| F-010 | Thai attack dataset and adaptive generator | Dataset governance is ready |
| F-011 | Grafana and Loki observability stack | Core telemetry contract is stable |
| F-012 | Production authentication, RBAC, and multi-tenancy | A production-deployment goal exists |

## Immediate Decision Requested

One remaining product-scope choice materially affects the first demonstration:

1. Should the MVP demo show only the vulnerable flow and its detection, or also include a **strict-policy rerun** that proves prevention?

Until answered, strict-policy comparison remains post-MVP.

## ADR Index

- [ADR-001: Core Language and Runtime](docs/adr/ADR-001-core-language-and-runtime.md) — **Accepted**
- [ADR-002: MVP Event Persistence](docs/adr/ADR-002-mvp-event-persistence.md) — **Accepted**
- [ADR-003: MVP Isolation and No-Egress Strategy](docs/adr/ADR-003-mvp-isolation-and-no-egress.md) — **Accepted**
- [ADR-004: Phase 1 Package and Contract Implementation](docs/adr/ADR-004-phase-1-package-and-contracts.md) — **Accepted**

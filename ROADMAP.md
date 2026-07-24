# AgentSec Lab — Roadmap

> This roadmap is ordered by dependencies and exit criteria rather than dates. Delivery speed can change without silently changing scope.

## Phase 0 — Foundations and Contracts

**Goal:** Turn the concept into minimum implementation contracts.

- Threat model for the Vertical Slice
- Safety invariants and socket-free no-egress test strategy
- Scenario schema v0
- Event envelope v0 with one MVP action event, `tool.requested`
- Definitions of attempt, impact, alert, and incident
- CLI and report output contract
- Vulnerable baseline policy matrix
- Redaction contract: canary ID and hash, never raw values in human reports
- Enforce the accepted ADRs for Python 3.13, SQLite persistence, and socket-free isolation

**Exit criteria**

- Every MVP contract has an example fixture
- Safety boundaries are testable
- No unresolved decision blocks the Core Lab

## Phase 1 — Core Lab Vertical Slice

**Goal:** Complete the first deterministic chain.

```text
Indirect Prompt Injection
→ Fake Secret Access
→ HTTP Exfiltration Attempt
→ Telemetry
→ Detection
→ Incident Report
```

- CLI scenario runner
- Python 3.13 runtime with compatibility `>=3.13,<3.14`
- Deterministic mock Target Agent
- Malicious text-document fixture
- Tool Gateway
- `read_file` with a fake filesystem
- `http_post` with in-process `LabHttpSinkAdapter` at `lab://exfiltration-sink`
- No operating-system network socket or DNS lookup
- Vulnerable baseline policy and policy-decision records
- Normalized events and trace correlation stored canonically in SQLite
- Optional JSONL export/replay generated from SQLite
- One sequence or correlation detection
- Alert, incident timeline, and required JSON and Markdown reports
- Positive, negative, cleanup, and no-external-egress tests

**Exit criteria**

- Every acceptance criterion in [MVP_SCOPE.md](MVP_SCOPE.md) passes
- A clean run is reproducible without an API key
- The report reconstructs the complete chain from evidence
- Safety tests deny host paths, external destinations, unknown tools, and invalid arguments

## Phase 2 — Runtime Security Controls

**Goal:** Compare observability with prevention.

- Vulnerable or no-defense and strict-policy profiles
- Path and domain rules
- Schema and argument validation
- Policy versioning and decision reasons
- Risk-scoring prototype
- Approval simulation
- Defense-comparison report

**Exit criteria**

- The vulnerable profile reaches attempted impact
- The strict profile blocks the action before impact as specified
- Both allow and deny paths produce complete telemetry

## Phase 3 — Detection-Engineering Platform

**Goal:** Make detection authoring and testing extensible.

- Versioned rule schema
- Single-event, sequence, and correlation rules
- Threshold rules after a baseline exists
- Rule validation and test harness
- Alert deduplication and enrichment
- False-positive fixtures
- Replay engine
- Coverage and timing metrics

**Exit criteria**

- Every rule has positive and negative tests
- Replay gives consistent results
- Every rule result identifies its evidence and rule version

## Phase 4 — Incident Management and Evaluation

**Goal:** Turn rule matches into investigation-ready incidents.

- Incident correlation
- Evidence linking and integrity metadata
- Attack-stage classification
- Timeline builder
- Root-cause and remediation templates
- Attack Success, Detection, Prevention, and False Positive metrics
- Mean Time to Detect and Mean Time to Incident
- Defense-profile comparison reports

**Exit criteria**

- An analyst can investigate the chain without reading every raw log
- Metric definitions are tested and use unambiguous denominators

## Phase 5 — Dashboard

**Goal:** Make lab runs and investigations easy to understand in demos and education.

- Run overview and detail
- Timeline viewer
- Alert detail
- Incident detail
- Detection-rule status and test view
- Policy comparison
- Policy simulator when the backend contract supports it
- Attack graph and evaluation charts

**Exit criteria**

- The dashboard consumes the same API and report contracts as the CLI
- The UI does not become a separate source of truth
- Critical investigation flows have accessibility and end-to-end tests

## Phase 6 — Scenario Expansion

**Goal:** Add one attack surface at a time without losing reproducibility.

Recommended order:

1. Direct prompt injection
2. Malicious web content
3. RAG poisoning
4. Unauthorized shell
5. Tool or MCP poisoning
6. Agent loop and resource abuse
7. Memory poisoning
8. Multi-agent and cross-agent injection

Each new scenario must add:

- Threat hypothesis
- Safety boundary
- Expected telemetry
- Positive and negative detection tests
- Incident example
- Reset and cleanup behavior

## Phase 7 — Advanced Research and Ecosystem

**Goal:** Grow AgentSec Lab from a focused lab into a research and education platform.

- Thai prompt-injection dataset and benchmark
- Obfuscation and adaptive attack generation
- Opt-in real-LLM adapters
- OpenTelemetry and security-schema mappings
- Optional Sigma, OCSF, or ECS conversion
- Plugin and tool integrations
- Scenario packs and contribution workflow
- Larger event transports only when requirements justify them

**Exit criteria**

- Datasets have provenance, licenses, and annotation policies
- Benchmarks are reproducible and report their limitations
- External integrations do not weaken safe defaults

## Cross-Cutting Work

These concerns apply in every phase:

- Documentation and tutorials
- Security review and dependency hygiene
- Redaction and privacy tests
- Deterministic fixtures
- Schema versioning and migration
- CI and release automation
- Contributor experience

## Roadmap Guardrails

- Do not build the dashboard to compensate for incomplete core telemetry
- Do not add a scenario until the previous one has positive and negative tests
- Do not require an external service in the default test suite
- Do not add an event broker before a measured scale problem exists
- Do not describe a lab attempt as a real-world compromise
- Change phase scope through [DECISIONS.md](DECISIONS.md) or an ADR

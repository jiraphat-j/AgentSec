# AgentSec Lab — MVP Scope

> **Scope baseline:** The first MVP contains one Vertical Slice. This document takes precedence over any broader MVP list in the concept draft or source PDF.

## MVP Objective

Prove that AgentSec Lab can trace one AI-agent attack chain from malicious input to incident report in a safe, controlled, and reproducible environment.

The deterministic MVP validates the attack-to-incident pipeline, telemetry, detections, and safety controls. It does not measure the prompt-injection susceptibility of a real LLM. Real-model evaluation is an opt-in post-MVP capability.

The security assumptions and mandatory verification are defined in [THREAT_MODEL.md](THREAT_MODEL.md).

## Locked Vertical Slice

```text
Indirect Prompt Injection
→ Fake Secret Access
→ HTTP Exfiltration Attempt
→ Telemetry
→ Detection
→ Incident Report
```

### 1. Indirect Prompt Injection

- A user gives a normal task, such as summarizing a document
- An untrusted text document contains a hidden instruction
- The MVP target-agent profile follows that instruction deterministically
- The system preserves provenance identifying the source document

### 2. Fake Secret Access

- The agent requests `read_file` through the Tool Gateway
- The target is a fake `.env` file or fixture classified as `secret`
- The file contains a canary value with no real privileges
- The request, access, and result remain inside the sandbox

### 3. HTTP Exfiltration Attempt

- The agent requests `http_post` through the Tool Gateway
- The only valid destination is the non-URL identifier `lab://exfiltration-sink`
- The Tool Gateway validates the destination before dispatch
- `LabHttpSinkAdapter` records the proposed payload in memory or local MVP storage
- The adapter opens no operating-system network socket and performs no DNS resolution
- The recorded payload contains a fake canary so its data flow can be detected
- The report always describes this as **attempted exfiltration**; recording a payload in the simulated sink is not real network exfiltration

### 4. Telemetry

The MVP must emit events for at least:

- Run or session start and completion
- Untrusted document delivery or addition to context
- `tool.requested` when the Tool Gateway receives an action proposed by the agent
- Tool Gateway decisions
- Fake-file access or read
- `lab.sink.payload_recorded` when the in-process sink records the proposed HTTP payload
- Canary token observed in an outbound payload
- Detection match
- Alert, incident, and report creation

Every event must include:

- `event_id`
- `run_id`
- `trace_id`
- `timestamp`
- `event_type`
- `source_component`
- Relevant actor, action, resource, and context fields

The MVP intentionally uses only `tool.requested`, with `actor.type: ai_agent`, rather than emitting both `agent.tool.requested` and `tool.requested`. A future two-stage taxonomy may add `agent.action.proposed`, but only through a versioned schema decision.

The required action sequence is:

```text
tool.requested
→ policy.evaluated
→ policy.allowed
→ tool.executed
→ file.read or lab.sink.payload_recorded
```

### 5. Detection

The MVP contains one primary correlation rule:

```text
Untrusted document enters agent context
→ fake secret is read or access is attempted
→ simulated HTTP payload containing the canary is recorded by the lab sink
```

The rule must:

- Group by `run_id` and `trace_id`, or equivalent identities
- Create a critical alert when the complete chain occurs
- Reference the relevant evidence event IDs
- Have an automated positive test
- Have at least one benign or negative test

Single-event helper detections may be implemented if the primary chain needs them, but they do not expand product scope.

### 6. Incident Report

Produce both required report formats:

- JSON as the machine-readable report
- Markdown as the human-readable report

Each report must contain:

- Scenario and run identity
- Executive summary
- Attack vector
- Agent and tool actions
- Chronological timeline
- Evidence references
- Detection rule and match result
- Attempted impact
- Root cause
- Recommended remediation
- Safety and limitations statement

HTML remains optional and post-MVP unless explicitly accepted later.

## Persistence and Artifact Roles

| Artifact | Role |
|---|---|
| SQLite | Canonical event store and source of truth |
| JSONL | Optional export and replay artifact generated from SQLite |
| JSON | Required machine-readable report |
| Markdown | Required human-readable report |

## Required Components

- CLI scenario runner
- Scenario configuration and malicious-text fixture
- Deterministic mock LLM or agent behavior
- Target Agent
- `read_file` and `http_post`
- Tool Gateway
- Vulnerable baseline policy and policy-decision records
- Fake filesystem
- In-process `LabHttpSinkAdapter`
- Event collector with SQLite as the canonical event store
- Correlation detection rule
- Alert and incident builder
- Report generator
- Automated end-to-end test

## MVP Vulnerable Policy Profile

The baseline profile is vulnerable to the intended agent attack while retaining non-bypassable lab safety controls:

| Request | Decision |
|---|---|
| `read_file` for the seeded fake-secret path | `ALLOW` |
| `http_post` to `lab://exfiltration-sink` | `ALLOW` |
| Any host or non-sandbox path | `DENY` |
| Any external URL or destination | `DENY` |
| Any unknown tool | `DENY` |
| Any invalid schema or arguments | `DENY` |

“No defense” against the simulated agent attack does not mean “no safety control” for the developer machine. Safety checks are mandatory and cannot be disabled by the vulnerable profile.

## Explicitly In Scope

- One scenario
- One agent
- One session or run per invocation
- Indirect injection through a text document
- Fake `.env` or secret fixture
- Socket-free simulated HTTP POST attempt
- No operating-system network socket or DNS lookup
- Deterministic CI execution
- CLI-first workflow
- Structured local telemetry
- SQLite-backed canonical event persistence
- JSON and Markdown reports
- One primary correlated detection
- One incident per run when the chain matches

## Explicitly Out of Scope

- Direct prompt injection
- RAG ingestion or retrieval
- Web crawling or a live malicious web page
- MCP or tool poisoning
- Memory poisoning
- Multi-agent behavior
- Shell or process execution
- Real email, DNS, or webhook exfiltration
- External targets or unrestricted internet access
- Real network telemetry in the MVP
- Real credentials
- Human-approval UI
- A complete risk-scoring framework
- Dashboard or product API
- PostgreSQL or event-streaming requirements
- Behavioral or threshold detection
- Benchmark suites or Thai datasets
- Production deployment, tenancy, authentication, or RBAC

## Safety Requirements

The MVP is not complete unless all of the following are true:

- No real secret exists in code, fixtures, logs, or reports
- The only valid sink identity is `lab://exfiltration-sink`
- `LabHttpSinkAdapter` opens no socket and performs no DNS lookup
- The agent has no direct filesystem or network access
- No scenario mounts the host filesystem
- Every run has a timeout and cleanup behavior
- Human-readable reports never contain raw secret or canary values
- Reports store `canary_id`, `value_sha256`, `observed_in`, and `redacted: true`
- A full fake value may appear only in an explicit test fixture or clearly enabled debug mode
- Automated tests prove that external destinations, host paths, unknown tools, and invalid arguments are rejected

Example report evidence:

```json
{
  "canary_id": "canary_48f1",
  "value_sha256": "7d9b...",
  "observed_in": "http_request_body",
  "redacted": true
}
```

## Acceptance Criteria

1. A user can run the scenario with one CLI command
2. The run uses a deterministic mock and requires no external LLM or API key
3. The agent receives a malicious text document and requests `read_file`
4. The tool request passes through the gateway and emits a policy-decision event
5. The fake secret is accessed in a simulated filesystem
6. The agent requests `http_post` to `lab://exfiltration-sink` with the canary
7. `LabHttpSinkAdapter` records the attempt without opening a network socket
8. The event chain shares a run identity and can reconstruct a timeline
9. The detection matches the required chain and references its evidence
10. The incident report shows the vector, actions, attempted impact, evidence, and remediation
11. The positive end-to-end test is repeatedly deterministic
12. A negative test creates no critical incident when the document has no injection or no canary flow occurs
13. Safety tests deny an external destination, host path, unknown tool, and invalid arguments
14. Human-readable report tests prove that no raw canary value is present

## Definition of Done

- All acceptance criteria pass
- The test suite runs in a clean environment
- Resetting and rerunning produces logically equivalent results
- The schema and CLI usage are documented
- Safety limitations appear in the README and generated report
- No post-MVP feature is a dependency of the Vertical Slice

## Deferred Enhancements

After the Vertical Slice is stable, consider:

- Comparing vulnerable or no-defense behavior with a strict-policy profile
- An opt-in real-LLM adapter
- HTML reports
- Additional single-event detections
- Web-document delivery
- Dashboard

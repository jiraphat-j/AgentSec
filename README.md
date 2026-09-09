# AgentSec Lab

> **Status: Phase 1 merged; Phase 2 implementation candidate awaiting security review and tests**

AgentSec Lab is a planned open-source detection-engineering lab for tracing AI-agent attacks from prompt injection and tool abuse to security alerts and incident investigation.

The project will use this wording until an open-source license is formally selected and a `LICENSE` file is added. Apache-2.0 is the current recommendation because its patent terms are more explicit than MIT, but the license is not yet decided.

The project runs AI-agent attack chains in a controlled environment, collects telemetry from the agent, Tool Gateway, policy layer, and simulated resources, then turns that evidence into detections, alerts, incident timelines, and reports.

## First Vertical Slice

```text
Indirect Prompt Injection
→ Fake Secret Access
→ HTTP Exfiltration Attempt
→ Telemetry
→ Detection
→ Incident Report
```

The MVP uses a malicious text document, a deterministic mock agent, a fake canary secret, and an in-process `lab://exfiltration-sink`. The sink records the proposed payload without opening an operating-system network socket.

The deterministic MVP validates the attack-to-incident pipeline, telemetry, detections, and safety controls. It does not measure the prompt-injection susceptibility of a real LLM. Real-model evaluation is an opt-in post-MVP capability.

## Accepted MVP Technical Baseline

- Python 3.13, compatible with `>=3.13,<3.14` and not pinned to a patch release
- SQLite as the canonical event store
- JSONL as an optional export and replay artifact
- JSON and Markdown as required report formats
- In-process, socket-free isolation for the first Vertical Slice

## Why AgentSec Lab

- Trace AI-agent attacks beyond model output
- Observe tool, file, policy, and network behavior
- Build detections from reproducible attack telemetry
- Correlate alerts into an investigation-ready incident
- Compare runtime defenses after the Core Lab is stable
- Provide a path toward Thai prompt-injection research

## Documentation

- [Project Brief](PROJECT_BRIEF.md) — identity, problem, goals, users, differentiators, and safety boundaries
- [MVP Scope](MVP_SCOPE.md) — scope and acceptance criteria for the first Vertical Slice
- [MVP Threat Model](THREAT_MODEL.md) — assets, trust boundaries, threats, safety invariants, and required security tests
- [Concept and Architecture Draft](AGENTSEC_CONCEPT_AND_ARCHITECTURE_DRAFT.md) — the complete concept and logical architecture
- [Decision Register](DECISIONS.md) — decided, proposed, research, and post-MVP items
- [Roadmap](ROADMAP.md) — delivery order from the Core Lab through controls, detections, incidents, dashboard, and advanced research
- [Architecture Decision Records](docs/adr/) — language/runtime, event persistence, and MVP isolation decisions

## Current Scope

The repository contains the Phase 1 deterministic Vertical Slice implementation and test suite.
The security-sensitive implementation received human review approval and passed local
verification on Windows with Python 3.13.15. Phase 1 was merged through
[PR #1](https://github.com/jiraphat-j/AgentSec/pull/1). The manual GitHub Actions workflow is
configured for Windows and Linux; its remote results could not be verified during Phase 2 planning.

The [Phase 2 implementation plan](docs/PHASE_2_IMPLEMENTATION_PLAN.md) now has an implementation
candidate on its feature branch. Because it changes the Tool Gateway and policy enforcement, it
must receive mandatory human security review before its tests or demo are executed. The commands
below describe the candidate and are not yet claimed as verified.

Review the [Phase 2 security checklist](docs/PHASE_2_SECURITY_REVIEW.md) before verification.

[MVP_SCOPE.md](MVP_SCOPE.md) is the source of truth for MVP scope. Any broader item in the architecture draft is a proposal or backlog item unless the decision register says otherwise.

## Usage

Use Python 3.13 to install and verify the package:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
```

Run the Vertical Slice:

```powershell
.venv\Scripts\agentsec run indirect-injection-secret-exfiltration --output-dir artifacts
```

Select the strict policy or compare the same attack under both profiles:

```powershell
.venv\Scripts\agentsec run indirect-injection-secret-exfiltration --profile strict --output-dir artifacts
.venv\Scripts\agentsec compare indirect-injection-secret-exfiltration --output-dir artifacts
```

The default remains `vulnerable` for Phase 1 compatibility. Strict mode blocks the classified
fake-secret read before adapter dispatch. The comparison command creates isolated child runs and
adds `comparison.json` and `comparison.md`. Risk scores are deterministic educational heuristics,
and approval behavior is synchronous simulation rather than actual human authorization.

Each successful run creates a new directory containing canonical `events.sqlite3`, required
`report.json`, and required `report.md`. The generated reports contain only redacted canary
evidence.

See the [example incident report](examples/reports/example-report.md) for the expected human
output and the [example defense comparison](examples/reports/example-comparison.md) for the
Phase 2 summary format.

The detailed implementation sequence and acceptance mapping are in
[docs/PHASE_1_IMPLEMENTATION_PLAN.md](docs/PHASE_1_IMPLEMENTATION_PLAN.md). Executable contract
details are in [docs/CONTRACTS.md](docs/CONTRACTS.md).

## Safety

AgentSec Lab is intended only for education and authorized security testing:

- Use fake or canary secrets only
- Open no operating-system network socket in the MVP; record exfiltration attempts through `lab://exfiltration-sink`
- Route resource access through the Tool Gateway
- Never mount the host filesystem into attack scenarios
- Keep dangerous and advanced scenarios disabled by default
- Never place raw secret or canary values in human-readable reports; use a canary ID and hash

AgentSec Lab is not a production security control and must not be used to attack external systems.

## Planned Delivery Order

1. Foundations and contracts
2. Core Lab Vertical Slice
3. Runtime security controls
4. Detection-engineering platform
5. Incident management and evaluation
6. Dashboard
7. Advanced scenarios and research

See [ROADMAP.md](ROADMAP.md) for the exit criteria of each phase.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). An approved open-source
license has not yet been selected, so the project remains described as planned open source.

# AgentSec Lab

> **Status: Phase 4 merged and verified; Phase 5 dashboard implementation prepared, verification pending**

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

The repository contains the Phase 1 Vertical Slice plus merged Phase 2 runtime controls, Phase 3
detection engineering, and Phase 4 offline incident investigation and evaluation. Phase 4 passed
its hashing review, local verification, final owner review, and human-dispatched Windows/Ubuntu CI
for merged revision `dd3dbe1`. Phase 5 dashboard work is defined by the proposed implementation
plan and has not yet been verified.

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

Validate the packaged Phase 3 rules and run their positive/negative fixtures:

```powershell
.venv\Scripts\agentsec rules validate --rules src/agentsec/resources/rules
.venv\Scripts\agentsec rules test --rules src/agentsec/resources/rules --fixtures src/agentsec/resources/rule_fixtures --output-dir artifacts/rule-tests
```

Replay one existing run without rerunning its agent, gateway, or adapters:

```powershell
.venv\Scripts\agentsec replay --events <path-to-events.sqlite3> --run-id <run-id> --rules src/agentsec/resources/rules --output-dir artifacts/replays
```

Replay writes a fresh directory containing `replay.json` and `replay.md`. The local processing
duration excludes input and report output and is not MTTD or MTTR. Fixture coverage is synthetic
contract coverage, not a production accuracy or false-positive-rate claim.

Investigate one recorded run without invoking the scenario runtime:

```powershell
.venv\Scripts\agentsec investigate --events <path-to-events.sqlite3> --run-id <run-id> --rules src/agentsec/resources/rules --output-dir artifacts/investigations
```

Run the closed three-fixture matrix under both policy profiles:

```powershell
.venv\Scripts\agentsec evaluate --suite core-lab-v1 --repetitions 1 --output-dir artifacts/evaluations
```

Investigation fingerprints detect changes in validated logical content; they do not authenticate
the source. Evaluation metrics describe only the packaged synthetic suite, and recorded legacy
timing remains separate from offline processing duration.

Install and start the optional read-only dashboard with an explicit artifact manifest:

```powershell
.venv\Scripts\python -m pip install -e ".[dashboard]"
.venv\Scripts\agentsec dashboard --manifest .\dashboard-manifest.json
```

See [dashboard setup, manifest rules, and limitations](docs/DASHBOARD.md). The dashboard binds only
to `127.0.0.1`, reads a fixed snapshot of selected artifacts, and provides no browser action that
runs or changes the lab.

Each successful run creates a new directory containing canonical `events.sqlite3`, required
`report.json`, and required `report.md`. The generated reports contain only redacted canary
evidence.

See the [example incident report](examples/reports/example-report.md) for the expected human
output and the [example defense comparison](examples/reports/example-comparison.md) for the
Phase 2 summary format. The [example replay](examples/reports/example-replay.md) summarizes the
Phase 3 output contract. The [example investigation](examples/reports/example-investigation.md)
and [example evaluation](examples/reports/example-evaluation.md) summarize the Phase 4 outputs.

The Phase 4 sequence and acceptance mapping are in the accepted
[implementation plan](docs/PHASE_4_IMPLEMENTATION_PLAN.md). Executable contract details are in
[docs/CONTRACTS.md](docs/CONTRACTS.md), and current verification evidence is tracked in
[docs/PHASE_4_VERIFICATION.md](docs/PHASE_4_VERIFICATION.md).

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

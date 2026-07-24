# AgentSec Lab

> **Status: Concept and MVP definition**

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

The repository is currently in the concept, architecture, and MVP-definition stage. There is no implementation setup or runnable command yet.

[MVP_SCOPE.md](MVP_SCOPE.md) is the source of truth for MVP scope. Any broader item in the architecture draft is a proposal or backlog item unless the decision register says otherwise.

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

Contribution guidelines, a security policy, an approved open-source license, and implementation setup will be added when the Core Lab scaffold begins. Before proposing a feature, check `MVP_SCOPE.md` and `DECISIONS.md` for its current scope and status.

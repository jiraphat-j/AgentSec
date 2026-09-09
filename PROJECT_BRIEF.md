# AgentSec Lab — Project Brief

## Project Identity

**AgentSec Lab** is a planned open-source AI-agent security lab that connects AI red teaming, runtime security enforcement, detection engineering, and incident response.

**One-line positioning**

> AgentSec Lab is a planned open-source detection-engineering lab for tracing AI-agent attacks from prompt injection and tool abuse to security alerts and incident investigation.

## Problem

Many AI-security tools stop at analyzing a prompt or model response. They cannot show whether a malicious instruction caused a tool call, file access, process execution, or network action.

Engineering and defense teams therefore lack:

- A lab for reproducing complete attack chains
- Telemetry across the agent, tool, policy, and sandbox layers
- Detection tests tied to observable behavior
- Incident timelines that explain the initial vector, actions, and impact
- A systematic way to compare defense profiles

## Goals

Build a lab that lets users:

1. Run AI-agent attack scenarios safely and reproducibly
2. Observe tool requests and effects on simulated resources
3. Enforce policies outside the agent
4. Collect normalized telemetry sufficient for detection
5. Produce alerts, incident timelines, evidence, and remediation guidance
6. Compare the prevention and detection value of defense profiles in later phases

## Target Users

- Cybersecurity students and AI-security learners
- AI Security Engineers and prompt-injection researchers
- Detection Engineers and SOC Analysts
- Red Teams and Blue Teams
- DevSecOps Engineers
- AI/ML Engineers and teams building RAG or agent systems

## Core Value Proposition

AgentSec Lab differs from a prompt scanner, LLM wrapper, or standalone dashboard because it:

- Treats the AI agent as the attack target
- Observes intent, tool requests, and simulated impact
- Collects agent, tool, policy, file, process, and network telemetry
- Connects attack behavior to detection rules
- Builds a correlated incident timeline with evidence
- Makes scenarios reproducible and testable
- Creates a path to comparing defense profiles
- Creates a path to a Thai prompt-injection dataset and benchmark

## First Product Proof

The first Vertical Slice must prove one complete chain:

```text
Indirect Prompt Injection
→ Fake Secret Access
→ HTTP Exfiltration Attempt
→ Telemetry
→ Detection
→ Incident Report
```

The acceptance boundary is defined in [MVP_SCOPE.md](MVP_SCOPE.md).

## First-MVP Non-Goals

- It is not a production SOC or SIEM
- It is not a general-purpose autonomous-agent framework
- It does not attack real targets or internet endpoints
- It does not implement the full attack catalog
- It does not build a dashboard before the evidence chain works
- It does not claim that its policies or detections replace a production security review

## Safety Boundary

- Use only fake or canary secrets with no real privileges
- Route every tool action through a controlled gateway
- Model exfiltration as a request to the in-process `lab://exfiltration-sink`; the MVP opens no network socket
- Never mount the host filesystem or use privileged execution
- Store only canary IDs and hashes in human-readable reports, never raw secret values
- Test only systems the user is authorized to test
- Keep dangerous and advanced scenarios disabled by default

## Success Signal

The MVP demonstrates the project's value when one command produces verifiable evidence that:

- A malicious instruction entered the agent through an untrusted document
- The agent attempted to read a fake secret
- The agent proposed sending the canary through simulated HTTP, and the socket-free lab sink recorded it
- Every stage has correlated evidence
- The expected detection rule created an alert
- The incident report explains the chain and recommends remediation

## Project Status

Phase 1 is implemented, locally verified, and merged. A Phase 2 runtime-control implementation
candidate follows the [plan](docs/PHASE_2_IMPLEMENTATION_PLAN.md) and awaits mandatory security
review and test execution. Remote Windows/Linux CI results remain unverified. The architecture
remains a draft; the Vertical Slice in `MVP_SCOPE.md` defines the Phase 1 scope baseline.

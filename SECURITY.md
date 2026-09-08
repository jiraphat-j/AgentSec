# Security policy

AgentSec Lab is intended for education and authorized security testing. The current MVP uses
only deterministic project code, a virtual fake-file adapter, and an in-process simulated sink.

## Supported version

The repository is pre-release. Security fixes apply to the current default branch only.

## Reporting a vulnerability

Do not open a public issue containing credentials, exploitable details, or sensitive host
information. Use the repository owner's private GitHub security-reporting channel when it is
enabled. If no private channel is visible, contact the repository owner privately before
publishing details.

Never include live secrets in a report. Use synthetic reproduction data.

## MVP security boundary

- Only fake canaries with no privileges are allowed.
- Scenario code opens no operating-system network socket and performs no DNS lookup.
- The sink accepts only `lab://exfiltration-sink`.
- The agent can access only the exact virtual key `workspace/.env` through the Tool Gateway.
- Host paths, traversal, external destinations, unknown tools, and invalid fields are denied.
- Reports and persisted telemetry contain canary IDs and SHA-256 digests, never raw canaries.
- Shell execution, real LLM providers, Docker, RAG, MCP, and third-party tools are outside the MVP.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [docs/agents/security.md](docs/agents/security.md)
for the complete development rules and review boundaries.


# Security Baseline for Agents

> **Priority:** Non-negotiable. Every autonomous agent and human contributor must adhere to these policies.

AgentSec Lab is a security-focused project that analyzes AI-agent attacks, prompt injections, and telemetry. Because the codebase models attack chains, strict safety invariants are mandatory to ensure that the developer workstation, CI environment, and lab boundaries remain completely safe and uncompromised.

---

## 1. Zero Secrets Policy

- **Never commit real credentials**: Do not hardcode, stage, or commit API keys, tokens, SSH keys, passwords, cloud credentials, or `.env` files containing live secrets.
- **Canary & Fake Secrets Only**: All test scenarios, fixtures, and mocks must use synthetic canary tokens or fake secrets (e.g., `canary_key_...`).
- **Secret Redaction**: Telemetry, event stores, and human-readable reports must never output or persist raw credentials. Store only identifier labels and SHA-256 digests (per Decision `D-012`).

---

## 2. Mandatory Human Review Boundaries

Any pull request or code change touching the following sensitive surfaces **must NOT be merged or executed autonomously**—it requires explicit human review and sign-off:

1. **Authentication & Authorization**: Identity verification, session handling, access control checks, or token validation.
2. **Cryptography & Hashing**: Encryption, decryption, key generation, signature verification, or digest algorithms.
3. **Subprocess & Command Execution**: Any invocation of `subprocess`, `os.system`, `exec`, `eval`, or dynamic shell dispatch.
4. **Network Egress & Socket Adapters**: Modifications to socket creation, external HTTP clients, DNS resolution, or proxy configurations.
5. **Tool Gateway & Policy Enforcement**: Changes that relax security policies, bypass tool argument validation, or expand file path access beyond sandboxed virtual roots.

When an agent works on a ticket touching these surfaces:
- Implement the minimal, verifiable logic under strict tests.
- Explicitly flag in the issue/PR summary: `⚠️ Security Sensitive: Requires Mandatory Human Review`.
- Do not mark the task complete or close the ticket until human review is confirmed.

---

## 3. Host Isolation & Lab Boundaries

AgentSec Lab's deterministic MVP enforces in-process isolation (see [THREAT_MODEL.md](../../THREAT_MODEL.md) and [ADR-003](../adr/ADR-003-mvp-isolation-and-no-egress.md)):

- **No OS Network Sockets in MVP**: Simulated HTTP exfiltration is handled in-process via `LabHttpSinkAdapter` using the `lab://exfiltration-sink` scheme. Agents must never introduce code that opens real OS sockets during lab scenario execution.
- **Virtual Filesystem Only**: The fake file adapter must expose only synthetic, seeded virtual paths. Arbitrary host paths or traversal outside the lab root must always be rejected by the Tool Gateway.

---

## 4. Dependency & Supply Chain Integrity

- **Vetted Dependencies**: Do not introduce new external libraries or packages without clear justification.
- **Security Audits**: Before submitting changes that add or bump dependencies, run supply chain vulnerability checks (e.g. `pip-audit` or `uv pip audit`).
- **No Unsafe Dynamic Imports**: Avoid `importlib.import_module` with untrusted or user-supplied strings.

---

## 5. Handling Untrusted Scenarios & Inputs

- Treat all prompt injection datasets, scenario YAML files, and test inputs as untrusted data.
- Ensure parsers (JSON, YAML, Markdown) are secure (e.g., use `yaml.safe_load`, not `yaml.load`).
- Ensure scenario data never executes as host code.

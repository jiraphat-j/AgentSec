# Contributing to AgentSec Lab

The project is implementing one deterministic Vertical Slice. Read [MVP_SCOPE.md](MVP_SCOPE.md),
[DECISIONS.md](DECISIONS.md), [AGENTS.md](AGENTS.md), and the applicable ADRs before proposing
changes.

## Development setup

Use Python 3.13 and install the development dependencies:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

Run the quality checks only after satisfying the security review rules below:

```powershell
.venv\Scripts\python -m ruff format --check .
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy
.venv\Scripts\python -m pytest
.venv\Scripts\python -m build
.venv\Scripts\python -m pip_audit
```

## Change requirements

- Keep changes within the first Vertical Slice unless a decision or ADR changes scope.
- Add deterministic positive and negative tests for behavior changes.
- Do not introduce real credentials, host-resource access, sockets, DNS, subprocesses, or
  dynamic imports.
- Explain new dependencies and audit them.
- Update public CLI, schema, and report documentation when those contracts change.
- Follow the issue lifecycle and Definition of Done under `docs/agents/`.

Changes touching authentication, cryptography or hashing, command execution, network/sink
boundaries, or Tool Gateway policy enforcement require the mandatory human review defined in
[docs/agents/security.md](docs/agents/security.md). Mark the handoff
`Security Sensitive: Requires Mandatory Human Review` and do not merge or execute it until
review is confirmed.


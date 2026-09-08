# Definition of Done (DoD) for Agents

Every task, ticket, or automated contribution must satisfy this checklist before an agent considers the work complete and requests human sign-off.

---

## 1. Automated Tests Pass

- All existing test suites pass with zero regressions.
- New functionality or bug fixes include dedicated unit or integration tests.
- Tests must be deterministic and runnable in local development and CI (no reliance on live internet access or external third-party services).

## 2. Linting & Static Type Checking Clean

- Formatting and linting checks (e.g., `ruff check`, `ruff format --check`) must pass with zero warnings or errors.
- Type annotations must pass strict static type checking (e.g., `mypy` or `pyright`) without introducing unvetted `# type: ignore` suppressions.

## 3. Strict Scope Adherence

- **Do not edit outside the ticket scope**: Only touch files, functions, and interfaces directly relevant to the issue.
- **No opportunistic refactoring**: Do not rename files, change styling conventions, or refactor unrelated modules in the same changeset.
- Keep diffs small, legible, and easy to review.

## 4. Documentation Updated (When Applicable)

- If public APIs, CLI flags, configuration schemas, or data models change, update corresponding documentation (e.g., `README.md`, `MVP_SCOPE.md`).
- If a architectural decision was established or altered, record or update an ADR in `docs/adr/`.
- If new domain terminology was introduced, update `CONTEXT.md`.

## 5. Security Invariants Verified

- The changeset adheres to [security.md](security.md).
- Zero secrets committed (no credentials, keys, or non-canary tokens).
- If any sensitive domain was touched (auth, cryptography, command execution, network egress, policy bypass), explicitly label it for human review.

## 6. Issue & Handoff Preparation

- The ticket/PR description clearly summarizes:
  1. What changed and why.
  2. Test commands executed and results observed.
  3. Any open questions or residual risks.
- Triage label is transitioned appropriately (e.g., to `ready-for-human` review).

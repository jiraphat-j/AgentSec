# ADR-004: Phase 1 package and contract implementation

- **Status:** Accepted
- **Date:** 2026-09-08
- **Decision owners:** Project owner

## Context

ADRs 001–003 establish the language, persistence, and isolation boundaries but leave the
package layout, validation library, fixture format, CLI implementation, and initial rule
representation open. Phase 1 needs concrete choices without introducing an API, service, or
general detection language.

## Decision

- Use a small `src/agentsec` installable package and an `agentsec` console entry point.
- Use standard-library `argparse` and `sqlite3` for the CLI and canonical event store.
- Use Pydantic v2 strict models with unknown fields forbidden at external boundaries.
- Use packaged JSON scenarios that reference trusted fixture identifiers.
- Use one versioned Python correlation rule for the Vertical Slice.
- Use Pytest, Ruff, strict MyPy, and GitHub Actions for quality checks.
- Use `workspace/.env` as the exact virtual resource key. It is not an operating-system path.
- Use a per-run integer sequence as the causal ordering tie-breaker after timestamp.

## Consequences

The MVP remains a single offline process with one installable command. It gains explicit,
testable contracts without making YAML, FastAPI, an ORM, or a general rule DSL an MVP
dependency. Pydantic is the sole runtime dependency and must be included in supply-chain
review.

## Verification

- Build and install a wheel under Python 3.13.
- Reject unknown scenario and tool fields.
- Load packaged fixtures outside the repository checkout.
- Prove event order, run isolation, and report reconstruction from SQLite.


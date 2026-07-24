# ADR-001: Core Language and Runtime

- **Status:** Accepted
- **Date:** 2026-07-24
- **Decision owners:** Project owner

## Context

The MVP needs a deterministic CLI, strict schemas, in-process capability adapters, detection rules, report generation, and a test suite. The source concept recommends Python, FastAPI, Pydantic, SQLAlchemy, and Pytest, but the Vertical Slice does not require a web API.

A runtime decision is needed before scaffolding package structure and CI.

## Decision

Use Python 3.13 as the core MVP language and runtime baseline without pinning a patch release.

- Start as an installable Python package with a CLI
- Declare the supported interpreter range as `>=3.13,<3.14`
- CI and developer setup may consume compatible Python 3.13 patch updates
- Use typed models and strict runtime validation for scenario, tool, event, and report boundaries
- Keep the Tool Gateway, fake-file adapter, `LabHttpSinkAdapter`, event pipeline, detection, and reporting in one process for the MVP
- Use a deterministic mock agent in the default test path
- Do not add FastAPI or a frontend until a consumer requires an API
- Do not pin the project to a specific Python 3.13 patch version

## Rationale

- The project is detection and security automation heavy
- Python has strong testing, schema, CLI, and AI-tooling ecosystems
- A single process reduces MVP operational complexity
- Deferring FastAPI prevents the web layer from becoming a dependency of the core pipeline
- Static typing plus strict runtime validation helps enforce tool and event boundaries

## Consequences

### Positive

- Fast iteration and low setup cost
- Deterministic unit and end-to-end tests
- Straight path to a later FastAPI adapter
- Shared types across controller, tools, events, detections, and reports

### Negative

- In-process isolation is not suitable for arbitrary code execution
- Python dependency and packaging hygiene becomes security-critical
- CPU-heavy future workloads may require process boundaries

## Alternatives Considered

- **TypeScript/Node.js:** Strong schema and frontend alignment, but less direct fit with the source security-automation stack
- **Go:** Strong single-binary delivery and concurrency, but slower iteration for the planned AI and detection ecosystem
- **Python with FastAPI from day one:** Useful later, but adds an unnecessary service boundary to the deterministic CLI MVP

## Implementation Follow-ups

The following choices do not block acceptance of this ADR and should be recorded during scaffolding:

1. Package and CLI entry-point layout
2. Runtime-validation library
3. Linting, typing, and test tools
4. CI policy for selecting the current compatible Python 3.13 patch release

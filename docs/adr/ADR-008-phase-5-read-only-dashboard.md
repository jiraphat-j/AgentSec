# ADR-008: Phase 5 read-only local dashboard

- **Status:** Accepted
- **Date:** 2026-09-15
- **Decision owner:** Project owner

## Context

Phase 4 produces bounded local evidence and reports, but demonstrations still require reading CLI
output and Markdown files. Phase 5 needs a browser view without changing evidence, running lab
actions from the browser, or making the web layer a dependency of the core package.

## Decision

- Add a read-only dashboard as an optional Python extra using FastAPI and Uvicorn.
- Bind a single foreground server only to literal `127.0.0.1`; remote deployment is unsupported.
- Treat the operator's machine as a trusted single-user presentation environment. Loopback is not
  authentication, so selected artifacts may be visible to other local processes or users.
- Select artifacts through a strict bounded manifest. Resolve only confined relative paths and
  capture source evidence once through the existing read-only SQLite reader.
- Keep SQLite canonical. The API exposes bounded allowlisted projections and performs no writes.
- Package semantic HTML, CSS, and native JavaScript. Use no CDN, Node build, frontend framework,
  external font, WebSocket, or outbound HTTP client.
- Keep all existing commands independent of dashboard dependencies through lazy imports.
- Defer policy simulation until a safe hypothetical-policy contract exists.

## Security boundary

The listener is an operator-facing presentation adapter. It is not reachable through the agent,
Tool Gateway, scenario, policy, or lab sink. Scenario execution remains socket-free. Dashboard
startup requires an explicit CLI command, validates Host/Origin/Fetch Metadata, serves fixed
packaged assets, and exposes GET/HEAD only. The dashboard does not provide authentication or safe
multi-user isolation.

## Consequences

The lab gains an installable local investigation UI while retaining the core CLI and evidence
contracts. Phase 5 adds an operating-system socket and new optional dependencies, so its concrete
network, path, and dependency changes require human review before test execution and merge.

## Supersession triggers

Remote binding, production deployment, authentication, multiple users, file upload, write APIs,
live event streaming, browser-triggered lab execution, or a policy editor require a new decision
and threat-model review.

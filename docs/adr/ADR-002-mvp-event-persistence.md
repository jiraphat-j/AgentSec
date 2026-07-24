# ADR-002: MVP Event Persistence

- **Status:** Accepted
- **Date:** 2026-07-24
- **Decision owners:** Project owner

## Context

The MVP needs append-oriented event recording, ordered timeline queries, correlation by run and trace, deterministic replay, and test isolation. It does not need a database service, distributed event bus, dashboard query workload, or multi-user concurrency.

The evaluated candidates were JSONL and SQLite. PostgreSQL and stream brokers are explicitly post-MVP.

## Decision

Use the following artifact roles:

- **SQLite:** canonical event store
- **JSONL:** optional export and replay artifact; never a second source of truth
- **JSON and Markdown:** required report formats

- Use one database per test or an isolated run database as appropriate
- Store a versioned event envelope and serialized payload
- Treat events as append-only through the application API
- Index `event_id`, `run_id`, `trace_id`, `event_type`, and timestamp
- Make event insertion and ordering deterministic
- Do not store raw fake-secret or canary values in event payloads intended for human export
- Generate reports from stored evidence references

## Rationale

- SQLite requires no external service
- Transactions reduce partial-run corruption
- Indexed queries simplify sequence detection and incident timelines
- It is easier to enforce uniqueness and referential constraints than JSONL
- JSONL remains useful for export, debugging, and replay without becoming the source of truth

## Consequences

### Positive

- Reproducible local and CI runs
- Efficient correlation and timeline queries
- Atomic writes and explicit schema versioning
- Simple migration path to a larger relational store if required

### Negative

- Requires schema and migration discipline earlier
- Database files need per-run or per-test cleanup
- Append-only behavior is an application guarantee unless strengthened with database controls

## Alternatives Considered

- **JSONL only:** Extremely transparent and append-friendly, but sequence queries, uniqueness, and partial-write handling move into application code
- **SQLite plus JSONL dual write:** Increases failure modes and ambiguity over the source of truth
- **PostgreSQL:** Strong production database, but unnecessary service overhead for the MVP
- **Redis Streams, NATS, or Kafka:** No measured scale or distribution requirement

## Implementation Verification

1. Demonstrate deterministic ordering for equal or near-equal timestamps
2. Demonstrate clean per-test isolation and cleanup
3. Define event schema versioning
4. Prove that JSONL export can be regenerated from SQLite
5. Prove that detections and reports read canonical events from SQLite, not JSONL

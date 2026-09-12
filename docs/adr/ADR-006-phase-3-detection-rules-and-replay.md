# ADR-006: Phase 3 detection rules and offline replay

- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision owners:** Project owner

## Context

The existing `ASL-CORR-001` Python detector proves one fixed attack chain. Phase 3 needs bounded,
reviewable rule data, repeatable rule tests, and replay over canonical evidence without rerunning
the agent or its tools. The design must retain SQLite as the source of truth and preserve the
existing detector's first-match behavior.

## Decision

- Use strict JSON schema 1.0 for declarative rules. YAML and executable rule plugins remain
  deferred.
- Support typed scalar equality and membership predicates over an explicit field allowlist.
- Support single-event, ordered-sequence, and correlation rules. Correlation adds typed equality
  joins between named steps.
- Evaluate only within one run and trace, ordered by trusted sequence, with fixed input,
  candidate, match, and output limits.
- Keep `ASL-CORR-001` version 1 in its existing Python compatibility path. Package the generalized
  declarative correlation as `ASL-CORR-002` version 1 so enumeration does not silently change the
  legacy rule.
- Deduplicate results by a deterministic, collision-free length-prefixed identity containing the
  rule, version, run, trace, and ordered evidence IDs.
- Replay an explicitly selected run from an existing SQLite database through a dedicated
  read-only/query-only connection. Never use the schema-creating `EventStore` for replay input.
- Exclude prior detection, alert, incident, and report events from declarative rule evaluation to
  avoid recursive detections.
- Give replay and rule-test reports their own schema version 1.0. Preserve event schemas 0.1 and
  0.2 without rewriting source evidence.
- Report fixture coverage and assertion counts. Report evaluator duration only as local processing
  time; it is not MTTD or MTTR and is excluded from deterministic equality claims.
- Defer threshold rules until a documented benign baseline exists.

## Safety and limits

Rule files contain data only: no Python, SQL, regular expressions, templates, imports, shell, or
callbacks. Enforce 64 rules, 64 KiB per rule/fixture, 8 steps, 16 predicates per step, 32 values
per membership predicate, 10,000 events, 10,000 candidate states and matches per rule, 64 MiB per
source database, and 1 MiB per output report. Limit failures are explicit and never become
successful no-match results.

Replay validates envelopes and ordering, keeps SQLite extension loading disabled, uses fixed
parameterized queries, and does not follow paths stored in events or rules. Reports contain safe
metadata and evidence references rather than copied payloads. The known raw lab canary is rejected
from outputs.

## Consequences

Detection authors can validate and test bounded rules, then replay them deterministically over a
recorded run without invoking adapters. The first format is deliberately narrow: it has no time
windows, negation, aggregation, thresholding, regex, arbitrary nested payload access, or generic
secret detection.

## Verification

- Validate positive and negative fixtures for every packaged declarative rule.
- Test missing fields, strict scalar types, invalid operators/fields/joins, duplicate identities,
  oversized inputs, and candidate exhaustion.
- Test event, sequence, and correlation behavior across wrong order, repeated events, and distinct
  traces.
- Prove replay leaves the source unchanged, does not create a missing source, and invokes no
  socket, DNS, agent, gateway, or adapter.
- Prove deterministic match order and deduplication identity.
- Verify event compatibility, redaction, Markdown escaping, output bounds, and clean failure.
- Run lint, strict typing, full tests, installed CLI demonstrations, and Windows/Linux CI.

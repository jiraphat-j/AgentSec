# ADR-007: Phase 4 incident investigation and evaluation

- **Status:** Accepted
- **Date:** 2026-09-12
- **Decision owners:** Project owner

## Context

Phase 3 produces deterministic declarative rule matches and read-only replay reports. Phase 4
must turn those matches into investigation-ready incident snapshots and compare the existing
vulnerable and strict profiles without treating synthetic fixtures as a production benchmark.

## Decision

- Add offline `investigate` and closed packaged `evaluate` commands while preserving existing
  commands and schemas.
- Derive one immutable incident snapshot per source run and trace containing declarative matches.
  Do not correlate across runs, traces, source snapshots, or rule sets.
- Keep SQLite canonical. Investigation and evaluation JSON/Markdown files are derived artifacts;
  source databases are opened read-only/query-only and never modified.
- Fingerprint the validated logical event snapshot and complete validated rule definitions using
  versioned deterministic JSON serialization and SHA-256. The fingerprint detects content changes;
  it does not authenticate origin or provide evidence custody.
- Package `core-lab-v1` as a closed labeled suite containing the existing malicious, benign, and
  missing-canary fixtures under both vulnerable and strict profiles.
- Define run-level `metrics-v1` with explicit attack, impact, prevention, and benign denominators.
  Zero denominators produce unavailable results, never zero percent.
- Keep offline evaluator duration separate from recorded historical detection/incident latency.
  Historical timing is calculated only from validated linked source events.
- Keep incidents immutable with initial status `new`. Assignment, triage transitions, resolution,
  analyst edits, and automated remediation remain deferred.

## Metric denominators

For completed, evidence-consistent runs, A is attack-labeled runs, B is benign-labeled runs, and S
is attack-labeled runs that reached matching-canary simulated impact.

- Simulated attack success: impacted runs in A / A.
- Attack-run detection: runs in A with a declarative alert / A.
- Simulated-impact detection: alerted runs in S / S.
- Prevention: evidence-backed prevented runs with no impact / A.
- Benign-run false positive: alerted runs in B / B.

## Safety and limits

Investigation invokes no agent, Tool Gateway, approval simulator, adapter, socket, or DNS API.
Evaluation invokes only the existing closed socket-free runner. Suite data cannot select paths,
adapters, code, arbitrary scenarios, or external resources. Existing Phase 3 bounds remain and
Phase 4 adds fixed alert, incident, timeline, suite, repetition, report, artifact, and deadline
limits.

Reports contain safe metadata and evidence references, escape Markdown, reject the known raw
canary, omit absolute source paths, and refuse overwrite. Unknown, incomplete, failed, and
contradictory evidence remains visible and cannot be converted into a successful prevention or
complete benchmark claim.

## Consequences

An analyst can inspect deterministic rule evidence and profile comparisons without reading every
raw payload. Results remain local educational measurements of a tiny synthetic suite. Trace-level
grouping cannot separate two attacks in one trace, and offline declarative matches have no
historical MTTD/MTTI.

## Verification

- Publish fixed snapshot and rule fingerprint vectors and test content sensitivity.
- Test grouping, deduplication, cross-run/trace isolation, reference resolution, stages, outcomes,
  incomplete and contradictory sources, and zero-match investigations.
- Test exact metric fractions, confusion counts, zero denominators, exclusion reasons, pairing,
  suite expectations, and recorded-timing eligibility.
- Prove source databases remain unchanged and investigation invokes no runtime or network surface.
- Verify report bounds, redaction, escaping, overwrite refusal, partial-suite accounting, package
  resources, installed CLI behavior, lint, strict typing, tests, dependency audit, and CI.

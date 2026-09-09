# ADR-005: Phase 2 runtime policy and comparison

- **Status:** Accepted
- **Date:** 2026-09-08
- **Decision owners:** Project owner

## Context

Phase 1 proves that a deterministic indirect prompt injection can reach socket-free simulated
impact and produce a correlated incident. Phase 2 must compare that observable vulnerable flow
with prevention while preserving every host-isolation control and the original default command.

## Decision

- Keep mandatory schema, resource, destination, size, and action-count safety checks in the Tool
  Gateway. Profiles and approvals cannot override them.
- Add closed `vulnerable` and `strict` profiles behind a versioned policy evaluator.
- Preserve vulnerable behavior for the Phase 1 command when no profile is supplied.
- In strict mode, deny classified fake-secret reads and matching-canary transfers before adapter
  dispatch. A safe non-canary post to the in-process sink requires simulated approval.
- Use deterministic `risk-v1` factors and store their codes, weights, score, and band. Scores are
  educational heuristics, not probabilities or a calibrated framework.
- Simulate approval synchronously. A response is bound to run, trace, tool call, and policy
  version, consumed once, and defaults to denial. It cannot override a hard policy rule.
- Keep detection, simulated impact, and prevention as separate evidence-derived results.
  `detected: false` alone never proves prevention.
- Add an offline comparison command that runs the same packaged scenario once per profile in
  isolated child directories and creates JSON and Markdown comparison reports from SQLite.
- Emit new events and reports as schema 0.2 while retaining explicit reading of legacy 0.1 events.
  Scenario schema remains 0.1 because profile and approval choices are trusted CLI/controller
  options, not scenario content.
- Add no network, filesystem, subprocess, API, UI, policy DSL, or runtime dependency.

## Policy precedence

```text
request -> mandatory safety -> risk and defense policy -> simulated approval when eligible
        -> persisted final decision -> adapter dispatch only after allow
```

Unknown profiles or versions fail explicitly. A validation, evaluation, approval-binding, or
required telemetry failure cannot produce adapter effects through the supported runner.

## Consequences

The project can demonstrate that the same deterministic attack reaches simulated impact under
the vulnerable profile and stops before fake-secret access under the strict profile. Reports can
explain prevention without confusing it with absence of detection. The prototype remains narrow:
it recognizes the seeded raw canary in memory and does not claim general taint tracking, encoded
secret detection, real human approval, real-model robustness, or real-network enforcement.

## Verification

- Preserve the complete Phase 1 vulnerable chain and existing safety denial matrix.
- Prove strict secret-read and canary-transfer denials happen before adapter effects.
- Prove safe simulated-approval allow/deny paths and reject stale, forged, reused, or unavailable
  responses.
- Prove benign runs are not labeled prevented and incomplete or contradictory policy/dispatch
  evidence cannot claim prevention.
- Build comparison outputs from isolated canonical SQLite evidence and resolve all references.
- Re-run no-socket, no-DNS, redaction, limits, lint, typing, build/install, vulnerability audit,
  and Windows/Linux CI checks after mandatory human review.

# Phase 4 security review — evidence fingerprints

Status: approved by the project owner on 2026-09-12 for security-sensitive test execution.

## Review scope

Primary implementation:

- `src/agentsec/evidence.py`

Callers that define what is fingerprinted:

- `src/agentsec/incidents.py`
- `src/agentsec/evaluation.py`
- `src/agentsec/incident_models.py`
- `src/agentsec/evaluation_models.py`

Decision and contract references:

- `docs/adr/ADR-007-phase-4-incidents-and-evaluation.md`
- `docs/CONTRACTS.md`
- `docs/PHASE_4_IMPLEMENTATION_PLAN.md`, section 4.4

## Exact construction

`evidence-snapshot-v1` hashes one object containing its version, selected run ID, source lifecycle
status, evidence cutoff sequence, and every validated event envelope in trusted sequence order.
`rule-set-v1` hashes its version and every complete validated rule ordered by rule ID/version.
`evaluation-suite-v1` hashes its version and the complete validated packaged-suite value.

The encoding is standard-library `json.dumps` with sorted keys, compact separators,
`ensure_ascii=True`, and `allow_nan=False`, encoded as UTF-8 without a trailing newline. The digest
is `hashlib.sha256(...).hexdigest()`. This is a project-specific deterministic encoding, not a
claim of RFC JSON canonicalization.

## Controls to confirm

- SHA-256 is used only for deterministic change detection and stable qualification, not password
  storage, signatures, MACs, authentication, or an authenticity/custody claim.
- The complete logical event envelopes and complete rule bodies are covered; database page layout,
  unrelated runs, absolute paths, and random output IDs are not.
- Snapshot validation rejects empty input, multiple runs, duplicate event IDs/sequences,
  unsupported/non-JSON and non-finite payload values, duplicate starts, conflicting lifecycle,
  and events after a terminal event.
- Rule loading already enforces closed declarative schemas, size/count bounds, unique identities,
  and raw-canary rejection; fingerprinting checks identity uniqueness again.
- Digests are emitted, but raw event payloads and raw rules are not copied into Phase 4 reports.
- Imported SQLite remains untrusted and is opened by the existing read-only/query-only reader.
- No key material, secret configuration, new dependency, network API, subprocess, dynamic import,
  or executable rule content is introduced.

## Known limitations

- Anyone able to replace evidence can recompute the digest; it does not prove who recorded data.
- SHA-256 does not provide signing, chain of custody, append-only history, or rollback detection.
- Stable keys intentionally change when the selected snapshot or complete rule set changes.
- The source database may contain operator-supplied sensitive data; this phase hashes it but does
  not publish it. Existing generated lab runs separately prohibit the raw fake canary in evidence.

## Execution gate

Ruff and strict MyPy passed before review. The focused Phase 3 coverage repair test also passed
without invoking this module. The project owner approved the evidence, rule-set, and suite SHA-256
implementation for test execution in the implementation task on 2026-09-12. Phase 4 runtime tests,
fixed digest vectors, the full suite, and packaging verification subsequently passed; see
`PHASE_4_VERIFICATION.md` for the recorded results.

Suggested approval statement:

> Approved the Phase 4 evidence, rule-set, and suite SHA-256 fingerprint implementation for test
> execution.

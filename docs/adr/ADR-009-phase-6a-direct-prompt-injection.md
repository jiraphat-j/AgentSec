# ADR-009: Phase 6A direct prompt injection

Status: **Accepted for implementation; security review required before test execution or merge.**

Phase 6A adds one deterministic packaged direct-prompt-injection scenario. It uses only synthetic
fixtures, the virtual file adapter, and the existing in-process `lab://` sink. It introduces schema
0.2 for the direct scenario while retaining schema 0.1 for indirect document scenarios.

The controller records safe prompt provenance but never prompt text. Direct runs use `risk-v2` with
an `untrusted_context` factor and `direct_prompt` origin; historic document runs retain `risk-v1`.
`policy-v1` decisions remain unchanged. Live direct correlation is `ASL-CORR-003` version 1.

On 2026-10-01 the owner reviewed and approved the bounded C07 correction: retain direct rule
version 1 while requiring canonical context/read/sink component labels and the exact virtual
secret resource in live/offline matching. Incomplete or inconsistent imported direct evidence
will cease matching, and rule-content/ruleset fingerprints change. Persisted alerts and indirect
rules remain unchanged; this is metadata consistency checking, not evidence authentication.
See [C07 review](../PHASE_G0_C07_REVIEW.md) for the approved snapshot and sandbox execution scope.

No real model, host resource, OS socket, DNS lookup, process, arbitrary input, or external service
is introduced. This decision does not approve security-sensitive test execution or merge.

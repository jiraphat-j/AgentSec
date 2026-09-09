# Phase 2 mandatory security review

Status: awaiting project-owner sign-off before code execution.

Review scope: Phase 2 changes on `phase-2-runtime-controls`, based on merged `main` commit
`57d0504d6fab1cae11420482b0213f6a7dcc4170`.

Reason: the implementation changes Tool Gateway and policy enforcement behavior, which is a
mandatory human-review surface under [repository security guidance](agents/security.md).

## What the candidate changes

- Adds closed `vulnerable` and `strict` policy profiles in `policy.py`.
- Keeps argument, tool, path, destination, size, and action-limit checks in `gateway.py` as
  mandatory safety decisions before policy dispatch.
- Adds deterministic `risk-v1` scoring in `risk.py`.
- Adds synchronous one-use approval simulation in `approvals.py`.
- Adds evidence-based impact/prevention classification and profile comparison reports.
- Adds CLI profile selection and a fixed two-profile comparison command.
- Moves new event/report artifacts to schema 0.2 while retaining legacy 0.1 event reads.
- Adds no runtime dependency, socket, DNS, subprocess, host-file adapter, dynamic import, API,
  external service, or new tool capability.

## Invariants to confirm

- [ ] Both profiles deny external destinations, unsafe paths, unknown tools, invalid arguments,
      oversized bodies, and exhausted action budgets before adapter invocation.
- [ ] `vulnerable` keeps the Phase 1 fake read and lab-sink flow but cannot relax mandatory safety.
- [ ] `strict` denies the classified fake-secret read and matching-canary transfer before effects.
- [ ] Approval is requested only for an otherwise safe elevated-risk lab action; it cannot
      override mandatory safety or strict hard denials.
- [ ] Approval responses bind to run, trace, call, and policy version, are consumed once, and
      fail closed when absent, malformed, mismatched, stale, or reused.
- [ ] A policy evaluation or required decision-event failure occurs before adapter dispatch.
- [ ] Raw request bodies and raw canaries are absent from policy events and reports.
- [ ] Prevention requires consistent, ordered strict defense evidence: the evaluated and final
      decisions agree on tool, deny action, rule, and enforcement layer, with no allowed,
      dispatched, or denied-effect event for that call. Benign runs, safety denials, failures,
      and `detected: false` do not imply prevention.
- [ ] Comparison children use the same packaged scenario, separate identities/stores/adapters,
      and canonical SQLite evidence.
- [ ] Comparison conclusions mention a critical incident only when detection evidence exists,
      describe the prevention stage recorded by the strict child, and label combined impact and
      prevention evidence as incomplete rather than claiming the chain was prevented.
- [ ] Risk weights are clearly labeled educational heuristics, not probabilities.

## Execution held for review

The candidate and its tests have been prepared but not executed. After sign-off, run formatting,
lint, strict MyPy, all Pytest tests with coverage, build/install verification, the installed CLI
comparison, recursive raw-canary scans, dependency audit, and manual Windows/Linux GitHub Actions.

Suggested sign-off text:

> Phase 2 security review approved; execute the verification suite.

Approval authorizes verification of this prepared diff. Any later change that relaxes validation,
expands virtual paths or destinations, adds network/process execution, or materially changes the
reviewed policy/approval behavior requires another review.

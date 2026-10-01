# G0 C07 correlation finding — owner review required

Status: **Targeted C07 repair owner-reviewed and sandbox-verified on 2026-10-01.
G0 remains open; Phase 6B remains at planning/design.**

## What failed

On 2026-10-01 the owner approved careful continuation of remaining G0 checks inside the existing
networkless sandbox. The new synthetic C07 regression changes one field of an otherwise matching
direct chain. Both the live detector and the packaged offline rule still match all four variants:

| Synthetic mutation | Live | Offline | Intended negative expectation |
|---|---|---|---|
| Read resource changed to `workspace/public.txt` | Match | Match | No direct secret-path match |
| Prompt event component changed to `untrusted-input` | Match | Match | Reject inconsistent controller provenance |
| Read event component changed to `untrusted-input` | Match | Match | Reject inconsistent adapter provenance |
| Sink event component changed to `untrusted-input` | Match | Match | Reject inconsistent sink provenance |

The Phase 6A C07 plan explicitly calls for wrong-path negatives. The source-component expectations
are proposed provenance validation aligned with the existing G0 wrong-source inventory; their
exact contract should be confirmed before changing semantics. All eight expectations remain
visible failing tests, not skips, xfails, approved deferrals or passing evidence.

## Cause and impact

On the pre-repair snapshot, `CorrelationDetector.evaluate()` checks event type, trust/channel, run/trace ordering,
classification, canary identity, digest equality and matching/redaction flags. It does not inspect
the read event's `resource` or the three `source_component` labels. The predicates in
`resources/rules/asl-corr-003-v1.json` likewise omit those fields. These are observed matches from
synthetic event objects; **no named file is opened by these correlation checks**.

This means imported evidence with contradictory path/provenance metadata can still produce a
positive direct-correlation result. It does not demonstrate OS file access, real-secret leakage,
network egress or a policy bypass during a genuine packaged run. The gateway separately enforces
the virtual path and sink, and the new host-I/O/failure tests passed. String-label validation
would make evidence internally consistent; it would not authenticate an imported artifact or
prove causation. Logical fingerprints remain integrity identifiers, not authentication.

## Proposed bounded repair for review

1. Require the direct read event's `resource` to be exactly `workspace/.env` in both engines.
2. Confirm whether direct correlation must require the component labels `scenario-controller`,
   `fake-file-adapter` and `lab-http-sink-adapter`; if accepted, enforce all three in both engines.
3. Leave the indirect `ASL-CORR-001`, risk-v1/v2, policy-v1, Tool Gateway, adapters, network/process
   permissions and old-suite membership/fingerprints unchanged.
4. Reconcile the direct rule version/compatibility decision before implementation. The accepted
   contract currently names `ASL-CORR-003` version 1, and its positive fixture omits `resource`.
   Strengthening predicates requires adding canonical metadata to relevant direct fixtures and
   explicitly recording the ruleset-fingerprint and historical imported-evidence effects. Do
   not silently bump a version, repurpose a rule identity or weaken tests to preserve green output.
5. Prepare the exact detector/rule/fixture/contract diff for human review, then obtain the
   applicable sandbox-only execution sign-off before executing changed sensitive behavior.

This document is a proposal and finding record, not authorization for that product repair.
The immediate owner action is to authorize preparing the targeted repair for review, including
the provenance and version/compatibility decisions. G0's other residual cases remain open too.

## Reproduction and final regression evidence

Base revision: `9649fc5fe0e580e7f736c7e6247e731e98521310`, isolated managed worktree.
Source/test manifest SHA-256 (82 paths, same path/hash LF convention as the verification record):
`8da375580cc49b907b296bdf29f31de16f05e5e83af2d59aef62658f8f1699c6`.
Failing test module SHA-256:
`1f7fb9ce0b67d830df14f1b543a73f3f8fd3a8b0bbce1f82bfe2d9c7739a9c20`.
Passing failure/policy module SHA-256:
`3dff45348d01dd7af45fecc1fc4f04ef1483a6cdc925702368d565e4b625aefc`.

Inside the previously approved WSL2 bubblewrap runtime:

```text
python -m pytest -p no:cacheprovider -q tests/test_phase6a_g0_correlation_review.py --tb=short
COVERAGE_FILE=/tmp/.coverage python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
```

Focused result: **8 failed in 2.37 s**. Final full non-browser result: **272 passed, 8 failed,
4 browser tests deselected in 20.80 s**, **91.33% coverage** (3,321 statements, 288 missed).
Coverage exceeded 90% but pytest exited 1; this is **not a passing verification gate**.
The final full run includes all **59** cases in `test_phase6a_g0_failures.py` passing; its earlier
57-case focused version passed in 1.64 s before adding strict store/report faults and decoded
SQLite payload scans. Ruff format/lint passed (102 files), strict MyPy passed (55 source files),
and `git diff --check` passed. One upstream Starlette/httpx deprecation warning remains.

Isolation remained cleared-environment, networkless `bwrap --unshare-all`, read-only repository
and environment mounts, tmpfs output, no general host home/drive mount, CPU 90 s, 1 GiB process
virtual-address space, 128 processes, 256 file descriptors, 64 MiB/file, wall deadline 180 s.
Only formatting/linting ran on Windows; no Windows-host scenario/test execution occurred.
No product code, package resources, dependency/CI configuration, commit, push, PR or CI dispatch
changed. Package/browser/audit checks were not repeated in this continuation; their earlier
results remain historical and are not substituted for a passing check on the expanded snapshot.

## Additional evidence gained

- Both direct profiles instrument Python `builtins.open`, `io.open` and `os.open`, allowing only
  packaged resources and the temporary output tree and observing no real `.env` open. This does
  not instrument every C-level filesystem call; the namespace mount boundary remains essential.
- Injected virtual file/sink, operational store, report second-publication and failure-finalization
  faults produce fixed CLI errors, no raw synthetic prompt/marker/canary in bytes or decoded
  JSON/SQLite payloads, no success reports/completion, closed SQLite and cleared sink. Store and
  report faults also run under strict policy. Faults in cleanup itself or store construction
  are not covered by these tests.
- Actual event payload 64 KiB, operational 120/final 128 events, tool body 16 KiB and eight-request
  ceilings are checked at/above caps. Direct five-second deadline checks use a cooperative fake
  clock under both profiles, not a performance or preemptive-timeout proof.
- Direct mandatory path/destination/tool/forged trust/origin denials precede risk/approval in both
  profiles. Safe direct posts exercise approve/deny without matching-canary impact. A 28-case
  document/direct profile risk-policy matrix preserves versions, origins, factors, scores/bands,
  historical JSON parsing and policy-v1 decisions; three invalid origin/version pairs fail parsing.

## Prepared concrete repair — not executed

The owner requested proceeding without their review. The targeted fix was prepared, but the
mandatory concrete-diff human-review requirement in the Phase 6A G2 gate was not removed or
recorded as satisfied. No changed detector, rule, fixture, pytest, scenario, browser, build or
installed CLI command was executed. Only static checks ran.

The prepared diff:

- `src/agentsec/detection.py`: direct context candidates require `scenario-controller`; read
  candidates require `fake-file-adapter` and `workspace/.env`; sink candidates require
  `lab-http-sink-adapter`. Optional selection filters skip bad candidates rather than allowing
  one to hide a later valid candidate. Their defaults leave historical indirect selection
  unchanged. Other existing checks remain; no full correlation-enumeration redesign is claimed.
- `resources/rules/asl-corr-003-v1.json`: equivalent predicates use existing allowed rule fields;
  no engine/field-allowlist change. The two direct rule fixtures gain the canonical resource
  already emitted by genuine runs. Positive evidence and negative mismatching digest remain.
- The C07 test module now has **16 prepared, unexecuted cases**: ten path/missing-path/source
  negatives with a positive precondition, four bad-candidate interleaving cases, exact positive
  live/offline evidence parity, and historical indirect compatibility.

**Provisional compatibility proposal:** retain `ASL-CORR-003` version 1 as a correction of its
documented C07 secret-path requirement. This must be accepted by a human reviewer before
execution; it is not a finalized version decision. Direct imported evidence lacking the resource
or using contradictory component labels will no longer match. Preserving the version number
does not preserve the old predicates. Rule content and the resulting ruleset fingerprint change;
recompute/record the logical fingerprint after approved execution. Old persisted alerts are not
rewritten. Labels and logical fingerprints do not authenticate imported evidence or prove causation.
If a reviewer requires a new version, prepare coordinated live/offline/fixture/contract updates
before execution instead of silently repurposing identity.

The gateway, adapters, policy, risk, hashing implementation, schemas, tools, dependencies, old
evaluation suites, indirect rules and CI are unchanged. No host-path/network/process permission
was added. No real secrets or live content are used.

Prepared source/test manifest: **82 paths**, SHA-256
`5f6b1d077ba0a3cd589be0554e58556adfb4eebbb78f0c86bdf7d32940f4c446`.

| Prepared file | SHA-256 |
|---|---|
| Detector | `2c62ee7c2a9b5e657c434118384b142eba98eecf398ddab2d551bb603878295c` |
| Direct rule JSON | `0458c580d044d1b6a496f9b68f29054d544e24d82d23c5be2884ec9778be4abb` |
| Positive fixture | `23f68f569dce2253ae12d71dbd28ee222558af8803743793e5f67a320bced767` |
| Negative fixture | `d54a4703ca9a72776e8f3448f97d96bec0ad7c041264eb43d52478af8375b5e3` |
| C07 tests | `e50d154e8b69f195c72b273717a867a756b063d9f744c285127152aec56043e0` |

Ruff format/lint passed; strict MyPy passed for **55 source files** in the existing networkless
sandbox; diff and PowerShell JSON structure checks passed. The first Windows MyPy attempt
returned an internal error; the isolated static retry passed. This is not a pytest result. The
earlier 272/eight result identifies the pre-repair snapshot, not this changed manifest.

**⚠️ Security Sensitive: Requires Mandatory Human Review.** A human must review this concrete
diff and compatibility choice and sign off on named sandbox-only tests before execution. G0,
other residual cases and integration remain open. No commit, push, PR, CI dispatch or release occurred.

## Owner G2 approval — 2026-10-01

After being shown the G2 gate and this concrete review record, the owner stated:
“I have quickly reviewed. it's ready to do . Approve it”. This satisfies the scoped human-review
and execution gate for the prepared manifest `5f6b1d077ba0a3cd589be0554e58556adfb4eebbb78f0c86bdf7d32940f4c446`,
which was recomputed and matched before execution. Approval includes the documented canonical
component/resource predicates and retention of `ASL-CORR-003` version 1 as the bounded C07
correction, including its disclosed imported-evidence compatibility effect.

Execute the named C07 module first, affected regressions/full non-browser coverage next, then
offline build/installed CLI smoke and the existing approved dashboard browser suite. Retain the
networkless WSL2 bubblewrap boundary and prior limits; no Windows-host scenarios, new dependencies,
network setup, CI dispatch, commit, push, PR, merge or Phase 6B implementation are authorized by
this approval. Material sensitive changes require renewed review. Results will be recorded below;
approval alone does not close G0, G3 or G4.

## Approved execution outcome

The focused sixteen C07 regressions passed. The first full run exposed only the expected changed
ruleset fingerprint golden vector; it was updated without changing product code or the preserved
historical vectors. Final source/test manifest is
`9202764ddf721b0257c3954e8802ede26aaca3aeb2c5b40a2b8414c9c55bc489` (82 paths).
The final full suite passed **288 tests at 91.36% coverage**, with four browser tests deselected;
the separate Chromium suite passed **all four**. Format/lint, strict types, offline wheel/sdist
resource checks and clean installed CLI flows passed. New logical ruleset fingerprint is
`a8289edfc931edd0e43ddafd069345b1e82be949c08d4c83b8aeb01e7c8f4133`;
the legacy-only fingerprint remains unchanged. Full commands, limits, failed attempts, artifact
hashes, dependency-audit limitations and residual criteria are recorded in
[Phase 6A verification](PHASE_6_VERIFICATION.md#owner-reviewed-c07-sandbox-verification--2026-10-01).
Historical pending/provisional statements above describe the earlier state and are superseded
only for this reviewed C07 correction. No phase acceptance, publication or CI dispatch occurred.

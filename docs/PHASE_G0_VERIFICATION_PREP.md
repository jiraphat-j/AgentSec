# Phase 5/6A G0 verification preparation

Status: **C07 repair owner-reviewed and sandbox-verified: 288 non-browser and four Chromium
tests passed, with quality/build/installed CLI checks. G0 remains open**.
Prepared against the Phase 6A
merged-main revision `9649fc5fe0e580e7f736c7e6247e731e98521310` in an isolated worktree.
This document supplements the Phase 5/6A verification records and the Phase 6B G0 decision
inventory. It does not silently waive their remaining criteria.

## Prepared first batch

`tests/test_phase6a_g0_prepared.py` adds focused regressions for part of these open rows:

| Gap | Prepared assertion | Still missing after this batch |
|---|---|---|
| P6A-C05 | Vulnerable/strict direct runs exclude the full malicious prompt, its attack marker, and the synthetic canary from SQLite and JSON/Markdown reports; prompt provenance precedes tool requests; a forced post-context failure persists only a fixed error type | Decoded report/incident/API/log scans across other failure modes and malicious control variants |
| P6A-C07 | Live and packaged offline direct rules agree on a positive fixture and reject wrong trust, channel, classification, canary ID, digest, match flag, and redaction flag | Reordering, cross-run/trace interleaving, wrong path/source, resource exhaustion and full parity matrix |
| P6A-C12 | Both direct profiles fail the test if they call OS socket/DNS or subprocess APIs | Host-file/path spies, at/over bounds, forced adapter/store/report failures, cleanup, concurrency and platform cases |

The first batch changed only a new test file and this preparation record. It did not modify product
code, policy, Tool Gateway, adapters, fixtures, dependencies, CI, or the older acceptance records.
All canary values come from the packaged **synthetic** fixture; no real credential is used.

## Review before execution

1. Review the exact test diff, especially the monkeypatched OS process/network APIs, synthetic
   exception carrying a prompt, artifact byte scans, and offline/live rule assumptions. If a test
   reveals a contract mismatch, do not weaken it merely to obtain green output; review the
   contract and any required sensitive source repair separately.
2. Identify the exact source/test file hashes and final worktree status. The old local G2 green
   result does not transfer to this new test snapshot.
3. Obtain explicit owner approval for the **named** test execution in the networkless sandbox.
   Approval of this document or the Phase 6B plan alone is not execution approval.

## Intended sandbox-only execution after approval

- Runtime location: WSL2 Ubuntu bubblewrap with `--unshare-all`, no external network, repository
  and tool mounts read-only, cleared environment, tmpfs output, explicit wall/CPU/file-descriptor
  limits and bounded process count where Chromium is not used. Never run attack-scenario tests on
  the Windows host. The old browser sandbox required omitting an incompatible per-process
  virtual-address limit; retain WSL memory/swap bounds and document this residual risk.
- Dependency/browser setup, if needed, uses a separate networked sandbox with **no repository
  mount**. Do not give the runtime namespace network access to fetch dependencies.
- First command **inside** the networkless runtime namespace:
  `python -m pytest -p no:cacheprovider -q tests/test_phase6a_g0_prepared.py`.
  Then run the affected existing modules, full non-browser coverage, installed-wheel smoke,
  and browser tests only when their test diffs and transports have separate approval. Record
  exact command, version, source/test hash, result, skip, output location and sandbox limits.
- Any new browser test must keep `127.0.0.1` for the read-only dashboard listener inside the
  namespace and abort/record non-loopback browser requests. Browser route interception is a
  second guard, not a substitute for OS network isolation.

## Original next-batch plan (now partly executed)

1. Prepare P5-02 hostile HTML/SVG/script/URL/control-character manifest-to-API/DOM fixtures and
   browser request interception, plus P6A-C11 loader-to-browser parity. Review before execution.
2. Prepare P5-03 C04 path/reparse/source-mutation and C10 at/over-limit/concurrency tests, plus
   P6A-C12 host-file/path and forced-failure checks. Review cross-platform test feasibility;
   Windows-specific path evidence belongs in human-dispatched Windows CI, not host scenario runs.
3. Prepare the remaining P6A C01–C13 coverage, manual accessibility checklist, and exact-commit
   CI evidence. The owner must authorize CI dispatch and record final review separately.

The owner explicitly approved the focused G0 batch on 2026-09-30, after clarifying that the
approval concerned G0 execution rather than this document's filename. The outcome and exact
runtime boundary are recorded in [Phase 6A verification](PHASE_6_VERIFICATION.md). This first
batch gives partial evidence for P6A-C05/C07/C12; no entire Phase 5/6A row is marked passed or
deferred. G0 remains open.

## Approved continuation outcome — 2026-10-01

The owner approved continuing G0 evidence completion and sandbox execution. The named review
steps above have been applied to the expanded test-only diff; routine additions within that scope
do not require approval of the same work again. A sensitive product repair, host execution,
publication or CI dispatch would require its own applicable authority. None occurred here.

Additional files are `tests/test_dashboard_g0_boundaries.py`,
`tests/test_phase6a_g0_matrix.py`, and the new manifest-loaded hostile-content case in
`tests/e2e/test_dashboard.py`. Product source, packaged resources and dependency/CI contracts
are unchanged. Full evidence and the exact snapshot hashes are in
[Phase 6A verification](PHASE_6_VERIFICATION.md#expanded-phase-6b-g0-evidence-2026-10-01), with
dashboard-specific row mapping in [Phase 5 verification](PHASE_5_VERIFICATION.md).

- Final non-browser suite: **213 passed, four browser tests deselected, 91.00% coverage**.
- Final browser suite: **four passed**, including real manifest-to-API/DOM direct evidence and
  hostile inert text/request/source-hash assertions.
- Ruff format/lint, strict MyPy, offline package build, installed-wheel CLI checks and Python
  dependency audit passed in their documented isolation boundaries.
- Actual small/medium resource caps, request concurrency, Linux symlinks/source identity swap,
  exact public resource-stream read caps, direct controls/isolation, correlation order/identity,
  incident references and evaluation fractions gained dedicated evidence. Reduced-cap and
  simulated-clock tests must not be presented as full-ceiling performance evidence.

Remaining work includes broader redaction/failure/log/artifact matrices; direct host-file/path
spies and forced adapter/store/report failures and cleanup; forged policy/context and historical
risk parsing; wrong path/source correlation; direct incident forged/missing/cutoff cases; suite
failure/exclusion/timing cases; full dashboard mutation/resource coverage; Windows junction/reparse
CI; manual accessibility; exact-reviewed-commit Windows/Ubuntu verification and Chromium CI;
and final owner review. No complete row or phase is silently accepted or deferred.

## Later continuation — C07 finding

The owner approved careful continuation of remaining G0 checks. `test_phase6a_g0_failures.py`
adds 59 passing host-I/O, failure cleanup/redaction, actual event/tool caps, direct deadline,
safety/approval and historical/direct risk-policy cases. `test_phase6a_g0_correlation_review.py`
adds eight visible failing expectations: both live/offline engines still match the wrong recorded
file resource and changed source-component labels. The latest full non-browser gate is
**272 passed, eight failed, four deselected, 91.33% coverage**, not a passing result.

See [C07 owner-review record](PHASE_G0_C07_REVIEW.md) for exact hashes/commands, scope limitations
and the proposed targeted repair. No product code was changed or repaired, no Phase 6B runtime
started, and no publication or CI dispatch occurred. Resolve the path/provenance/version contract
and review any concrete sensitive repair before its execution. Other technical and human gates
remain open; the earlier green batch results are historical, not acceptance of this expanded suite.

## C07 repair prepared, not executed

A targeted direct detector/rule/fixture repair and sixteen regressions are prepared. Only
format/lint, strict MyPy, diff and JSON structure checks ran. The owner requested execution
without their review, but the mandatory concrete-diff human-review gate remains unsatisfied;
no changed runtime ran. [C07 review](PHASE_G0_C07_REVIEW.md) contains exact hashes, provisional
version compatibility, changed imported-evidence behavior and reviewer checks. Earlier runtime
approval/results are not inherited by this repair.

## C07 owner approval and verification

On 2026-10-01 the owner confirmed review and approved the concrete C07 correction and its named
sandbox-only checks. The final result is **288 passed, four browser tests deselected, 91.36%
coverage**, plus **four Chromium tests passed**; quality/build/installed CLI checks passed too.
The full ruleset golden vector was updated for the approved predicate correction while the
historical-only vectors stayed unchanged. Tested manifest:
`9202764ddf721b0257c3954e8802ede26aaca3aeb2c5b40a2b8414c9c55bc489` (82 paths).
See [verification](PHASE_6_VERIFICATION.md#owner-reviewed-c07-sandbox-verification--2026-10-01)
for exact results, commands, isolation and remaining gates. Earlier failures/pending review are
historical; this outcome closes the demonstrated C07 defect, not the entire G0 inventory.

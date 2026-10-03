# G0 C07 correlation finding — owner review required

Status: **The owner-approved direct-only follow-up repairs the twelve later parity failures.
On 2026-10-03, 429 non-browser tests, four Chromium checks, quality/build and installed checks
passed in the sandbox. G0 remains open; Phase 6B remains at planning/design.**

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

## Additional live/offline parity findings — 2026-10-02

The owner authorized commit/push and continued workflow with a sub-agent reviewer. The reviewed
dashboard repair and test-only safety batch were pushed on `codex/g0-evidence-completion`:
`df084a0203042b9494e6140e5fe456e5a8decfa6` and
`eec09e9e0bf5dd3dcb29f5ad567269190cd010e1`. The latter passed 373 non-browser tests at 91.95%
coverage, four Chromium checks, quality/build and clean installed-wheel checks.

The next **18-case test-only** module, `tests/test_direct_correlation_parity.py`, found:

| Cases | Offline result | Live result | Expected behavior |
|---|---|---|---|
| Two earlier reads with wrong classification/canary | Exact later valid triple | No match | Preserve the valid chain |
| Four earlier sinks with wrong canary/matched/redacted/digest | Exact later valid triple | No match | Preserve the valid chain |
| Two earlier valid prompt contexts for unrelated run/trace | Exact complete valid triple | No match | Do not stop at an unrelated context |
| Read and sink both missing their digest | No match | Match | Missing values are not transfer evidence |
| Each of three chain events changed from schema 0.2 to 0.1 | No match | Match | Honor the direct rule's explicit 0.2 support |

Every valid-later-chain case establishes the exact expected offline triple before asserting live
behavior. The missing-digest case starts from a genuine matching fixture; the Event envelope
permits these synthetic payload mutations, but canonical snapshot validation already rejects
missing classified-canary digests. Therefore this is a detector API parity/defense gap, **not**
evidence that the investigator accepts an invalid canonical snapshot. The version cases are
valid Event envelopes but explicitly unsupported by `ASL-CORR-003`'s declared `["0.2"]` versions.
No file, adapter, tool, prompt text, secret value or network request is involved in these checks.

Cause: live selection chooses the first context/read/sink before checking all semantic predicates,
then returns no-match instead of trying later valid candidates. Its digest comparison allows
absent `None` values to compare equal, and it does not check the direct rule's event versions.
Offline evaluation filters full predicates, rejects missing joins and honors supported versions.
The independent reviewer confirmed these are legitimate C07 gaps, not malformed-fixture failures.

Six new cases passed: missing-digest offline rejection; exact two-chain digest enumeration and
reversed-input determinism; actual 10,000-candidate acceptance/overflow; disclosed reduced
four-match acceptance/overflow. Four contexts, one read and 2,498 sinks visit exactly 10,000
candidates and produce 9,992 matches. One extra sink raises explicit candidate exhaustion.
Do not claim actual match-over-limit isolation: candidate and match ceilings are both 10,000,
so candidate exhaustion wins first; the match-specific test intentionally patches its cap to four.

Reproduction base is `eec09e9e0bf5dd3dcb29f5ad567269190cd010e1`, with no product changes.
Executed manifest: **85 paths**, SHA-256
`1c09b53a70b77ee7d5aebe302c9e50a08b0735469da104249a0238275af43c08`;
module SHA-256 `ca884eb2c293beedbb185559b285f9936a7ce09eeaf6f3edc55a2217f7e239fc`.
Focused: **12 failed, six passed in 3.84 s**. Full non-browser: **379 passed, 12 failed,
four browser tests deselected in 42.76 s**, **91.98% coverage** (3,329 statements, 267 missed),
pytest exit 1. Format/lint and strict MyPy passed for 58 files; one initial assertion-style lint
issue was fixed before runtime execution. No failure is skipped, xfailed, deferred or accepted.

```text
python -m pytest -p no:cacheprovider -q tests/test_direct_correlation_parity.py --tb=short
COVERAGE_FILE=/tmp/.coverage python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=line
```

Both runs used the established cleared-environment, networkless bubblewrap sandbox with read-only
repository/runtime, tmpfs outputs, CPU 120 s, wall 240 s, 1 GiB address space, 128 processes,
256 descriptors and 64 MiB/file. No host scenario, new download/dependency, CI dispatch or merge.
Browser/build checks belong to the preceding passing 84-path snapshot, not this failed expanded
acceptance matrix. Reproductions and finding documentation remain local and uncommitted.

### Proposed next repair — no implementation or execution approval inferred

Prefer a **direct-only** reuse of existing bounded declarative evaluation as the canonical
predicates, joins and version filter, preserving historical indirect `ASL-CORR-001` behavior
and direct rule bytes/version/fingerprint. Before execution, prepare the exact diff and obtain
human G2 review covering fixed packaged-rule loading and missing/mismatched-resource errors,
newly shared candidate/match exhaustion, no success alert/incident on exhaustion, and deterministic
selection among multiple valid triples. Offline matches are dedup-key sorted, not necessarily
earliest-sequence sorted; do not silently equate those orderings. Expand regression checks for
that choice and clean installed-package behavior. An alternative complete direct enumeration
must enforce the same strict predicates/joins/versions and explicit resource bounds.

The owner's broad continuation/delegation request does not substitute a sub-agent's judgment for
the repository's required human review of a **new concrete sensitive diff**. Previous owner G2
approvals cover their earlier repairs only. No new detector code has been changed or executed.
G0, remaining technical matrices, manual accessibility, human-dispatched exact-commit CI and
final owner acceptance stay open. **Security sensitive: requires mandatory human review.**

## Concrete repair proposal for G2 — review only, 2026-10-02

Historical proposal: owner-approved and applied on 2026-10-03; see the execution record below.

**Not applied or executed.** On the owner's request to continue, an attempt to prepare the
sensitive source patch was rejected by the tool safety reviewer because concrete human G2
approval was absent. Read-only Git checks confirmed that neither detector nor resource-loader
source changed. This section is the safer alternative: proposed code for human inspection,
not an applied patch, implementation result or approval. Do not run it from this document.

Base remains `eec09e9e0bf5dd3dcb29f5ad567269190cd010e1`; the eighteen reproduction cases and
finding notes are local. Their 85-path manifest and 379 passed/twelve failed result above
remain the most recent executed snapshot. PR #9 contains only the two earlier verified commits.

### Decision requested

Approve preparing/applying this **direct-only** repair and its additional regression cases,
then executing the named checks below in the established networkless sandbox. Human review
must cover the two behaviors below, not only the claim that the twelve reproductions will pass:

- Fresh direct evaluation now finishes bounded declarative enumeration before choosing a result.
  Exceeding 10,000 input events, candidate visits or matches raises an explicit error; it cannot
  become a successful no-match or a partial-success alert. Actual matches remain dedup-key
  sorted; choose `matches[0]`, **not** the earliest chronological chain. This can change the
  selected evidence on imported multi-chain inputs while genuine single-chain runs remain exact.
- Fresh direct evaluation accepts only its closed rule ID/version/channel configuration and loads
  the fixed trusted package resource. Missing, malformed, oversized or mismatched resource data
  fails rather than falling back to the old detector. Existing custom direct constructor
  configurations outside that closed contract become errors; indirect constructor behavior is
  unchanged. Resource metadata checks are not package authentication or generic secret detection.

No changes to `ASL-CORR-003` resource bytes/version, rule-engine algorithms, rule-field allowlist,
hashing algorithms, risk, policy, Tool Gateway, adapters, scenario/schema/suite membership,
dependencies, sockets, processes or CI. Existing version 1 and ruleset fingerprint remain
unchanged. The historical indirect first-candidate path remains in Python per ADR-006.

### Proposed source changes

In `src/agentsec/resource_loader.py`, add imports for the existing
`DIRECT_PROMPT_CORRELATION_RULE_ID`, `DIRECT_PROMPT_CORRELATION_RULE_VERSION`, `MAX_RULE_BYTES`,
and `DetectionRule`/`RuleKind`, then add this fixed-resource function. It reuses the existing
bounded UTF-8 read and duplicate/non-finite JSON hooks. Their original scenario error messages
are wrapped by the fixed direct-rule validation error; no arbitrary input is echoed.

```python
def load_direct_detection_rule() -> DetectionRule:
    """Load only the fixed packaged direct rule; never accept a path or selector."""
    resource = files("agentsec.resources").joinpath("rules", "asl-corr-003-v1.json")
    data = _read_bounded_utf8(resource, MAX_RULE_BYTES, "direct detection rule")
    try:
        decoded = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        if load_canary() in json.dumps(decoded, ensure_ascii=False):
            raise ValueError("direct detection rule contains the lab canary")
        rule = DetectionRule.model_validate_json(data)
    except ValueError as error:
        raise ValueError("direct detection rule failed validation") from error
    if (
        rule.rule_id,
        rule.rule_version,
        rule.kind,
        rule.severity,
        rule.supported_event_versions,
        tuple(step.name for step in rule.steps),
    ) != (
        DIRECT_PROMPT_CORRELATION_RULE_ID,
        DIRECT_PROMPT_CORRELATION_RULE_VERSION,
        RuleKind.CORRELATION,
        "critical",
        ("0.2",),
        ("prompt", "read", "sink"),
    ):
        raise ValueError("packaged direct detection rule does not match its contract")
    return rule
```

In `src/agentsec/detection.py`, import that loader plus the existing `evaluate_rule`,
`RuleEvaluationLimitExceeded` and `MAX_REPLAY_EVENTS`. At the start of `evaluate`, route only
the direct-prompt context to the proposed helper:

```python
if self._context_event_type == "agent.context.prompt_added":
    return self._evaluate_direct(events)
```

The remaining `evaluate` body is the historical document path. Remove its now-inapplicable
`direct` local and direct-only context-component/read-component/resource/sink-component
conditionals, and the unused `VIRTUAL_SECRET_PATH` import. Leave context trust/channel logic,
first-read/sink selection, digest checks, result construction, recording and `_existing_result`
unchanged. Add:

```python
def _evaluate_direct(self, events: list[Event]) -> DetectionResult:
    if (
        self._rule_id,
        self._rule_version,
        self._context_delivery_channel,
    ) != (
        DIRECT_PROMPT_CORRELATION_RULE_ID,
        DIRECT_PROMPT_CORRELATION_RULE_VERSION,
        "direct_prompt",
    ):
        raise ValueError("unsupported direct detector configuration")
    if len(events) > MAX_REPLAY_EVENTS:
        raise RuleEvaluationLimitExceeded("direct detector event count exceeds fixed limit")
    evaluation = evaluate_rule(load_direct_detection_rule(), events)
    if not evaluation.matches:
        return self._no_match()
    # The evaluator orders matches by dedup key, not by earliest event sequence.
    match = evaluation.matches[0]
    return DetectionResult(
        rule_id=self._rule_id,
        rule_version=self._rule_version,
        detected=True,
        severity="critical",
        evidence_event_ids=match.evidence_event_ids,
    )
```

This helper is intentionally not cached: each new evaluation performs one fixed bounded rule
read and validates its metadata. The existing recording idempotence path can reuse an already
recorded result; this proposal does not re-authenticate historical alerts or rewrite their IDs.
Specifically, `evaluate_and_record()` calls `_existing_result()` before `evaluate()`. When it
finds a recorded result, it bypasses the proposed configuration, resource and input-cap checks;
the guarantees above apply only to fresh evaluation. Existing recorded-result reuse and
missing-completion repair remain unchanged, not newly validated or authenticated by this repair.
The evaluator still uses its existing strict scalar join semantics; the proposal does not add
a new SHA-256 syntax/authenticity rule to generic fixture payloads. Canonical snapshot validation
continues enforcing its separate evidence requirements.

### Additional acceptance cases to prepare after application approval

Keep the existing eighteen cases visible; do not skip/xfail the twelve failures. Add:

- Fixed resource path/package and exact `MAX_RULE_BYTES + 1` read-spy checks at/over 64 KiB,
  closed streams, malformed UTF-8/JSON, duplicates, non-finite data, literal/JSON-escaped canary,
  absent resource and wrong identity/version/kind/severity/version support/step names. Confirm
  fixed CLI errors do not echo contaminated synthetic input.
- Live/offline exact first dedup-key match and reversed-input equality on multiple chains,
  including event IDs chosen so chronological-first and dedup-key-first ordering differ.
- Live input event cap at/over 10,000; shared actual candidate ceiling at/over 10,000; disclosed
  reduced match ceiling at/over. Preserve explicit exceptions and no partial success.
- Fresh `evaluate_and_record` and runner faults for rule loading/evaluator exhaustion: no new
  success match/alert/incident/report/completion, fixed error output, closed store/cleared sink,
  redacted failed artifacts and unchanged rule resources. Existing recorded-result idempotence
  remains separate from newly evaluated failure behavior. Explicitly verify recorded-result
  reuse bypasses fresh evaluation, and distinguish missing-completion repair from fresh failure.
- Fresh closed direct configuration negatives, historical indirect compatibility, original C07
  component/path predicates, all three direct fixtures under both profiles and installed-wheel
  fixed resource loading outside the checkout. Update only contract/ADR clarification needed
  for the reviewed result-selection/exhaustion behavior; do not claim a new rule fingerprint.

### Requested sandbox execution after concrete review

Once the proposal/application and final prepared source/test diff are approved, compute its
new manifest, review any material difference from this code, then execute:

```text
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --no-incremental --cache-dir /tmp/mypy src tests
python -m pytest -p no:cacheprovider -q tests/test_direct_correlation_parity.py tests/test_phase6a_g0_correlation_review.py tests/test_detection_and_reporting.py --tb=short
COVERAGE_FILE=/tmp/.coverage python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
```

Also run the existing four Chromium checks and offline wheel/sdist/clean core-only installed CLI
checks for direct/indirect runs, comparison, replay, investigation, both suites, rules and the
missing-dashboard hint. Reuse prior cleared-environment, read-only repository, networkless
bubblewrap bounds: static/full CPU 120 s/wall 240 s/address 1 GiB/processes 128/descriptors 256/
64 MiB per file; browser existing WSL memory/swap and CPU/wall/descriptor bounds; build/install
existing task-output mount and 4 GiB address ceiling. No host scenarios, new downloads/dependency
setup, CI dispatch, merge, release or Phase 6B runtime is included in this proposed approval.

Until human review resolves this request, no source edit or changed-sensitive execution is
performed. Sub-agent inspection may identify defects in this proposal but cannot approve G2.

Supplemental read-only review found no import cycle or fresh-evaluation ordering blocker. Its
recorded-result bypass clarification is incorporated above; this is not human G2 approval.

## Human approval and repair verification — 2026-10-03

The owner explicitly approved applying the concrete proposal and running its named sandbox
checks. The source diff matches the proposed two-file repair; no material behavior was added
beyond it. Regression preparation added schema-valid decoded-canary negatives and live/offline
actual-candidate/disclosed-reduced-match boundary parity. Final independent read-only review
found no blockers. It supplements, rather than substitutes for, the owner's G2 approval.

All twelve original failures now pass without skips/xfails. Final manifest:
`af80952ae4f8f5ebbaceaf7290cfb3698ab87d407ac88a2734f5d327fec03eb1` (86 paths).
Focused: 84 passed; full: 429 passed, four browser tests deselected, 92.04% coverage;
Chromium: four passed; format/lint/strict types, offline build/archive parity and fresh core-only
installed CLI checks passed. See the [dated verification record](PHASE_6_VERIFICATION.md#approved-c07-liveoffline-repair--2026-10-03)
for commands, times, archive hashes and isolation limits. Initial new-test setup/CLI mistakes and
one regex-style lint issue were corrected before the final checks; product code needed no
adjustment from the approved proposal. No host scenario/test, dependency or CI change occurred.

Recorded-result reuse bypasses fresh checks as disclosed. Rule bytes/version, indirect behavior,
policy/gateway/adapters and hash algorithms are unchanged. This closes this repair, not complete
G0, platform/manual checks, human-dispatched exact-commit CI or final owner acceptance; it does
not authorize merge or Phase 6B runtime.

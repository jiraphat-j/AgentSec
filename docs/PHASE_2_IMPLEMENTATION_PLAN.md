# Phase 2 implementation plan — Runtime Security Controls

Status: implementation candidate prepared 2026-09-08; mandatory security review and execution
checks pending. Phase 1 remote CI evidence remains unverified.

## 1. Starting point and verification

- Phase 1 is merged through [PR #1](https://github.com/jiraphat-j/AgentSec/pull/1).
- Fetched `origin/main` at `57d0504d6fab1cae11420482b0213f6a7dcc4170`; its tree matches
  the Phase 1 implementation commit `6abc04c`.
- This planning branch is `phase-2-runtime-controls`, created from that merged commit.
- Previously recorded local verification: 36 tests passed, 92% coverage, clean Ruff and
  strict MyPy, successful wheel installation/demo, and no known dependency vulnerabilities
  reported by the audit at that time. Phase 2 execution checks await mandatory security review.
- Remote Windows/Linux verification is **unverified**, not known to have failed or never run.
  Both unauthenticated and connected GitHub Actions API reads returned 404 during planning.
  Obtain a run URL and verify both jobs and the tested commit before closing this checkpoint.
  If no qualifying run exists, run the existing manual workflow against merged `main`.

Read [AGENTS.md](../AGENTS.md) and its linked guidance, then [README](../README.md),
[Project Brief](../PROJECT_BRIEF.md), [Roadmap](../ROADMAP.md), [MVP Scope](../MVP_SCOPE.md),
[Threat Model](../THREAT_MODEL.md), [Decisions](../DECISIONS.md), [contracts](CONTRACTS.md),
and accepted [ADRs](adr/). The architecture draft's sections 9–10 are context, not accepted
policy schemas or score weights. No installed specialized skill directly fits this local
Python planning task; repository guidance supplies the workflow. Reassess skills at implementation.

## 2. Product result and scope

Run the same deterministic scenario under two profiles and explain the different outcomes:

```text
Same packaged malicious document and mock-agent behavior
  -> Tool Gateway: mandatory lab safety validation
     -> vulnerable: allow fake-secret read and lab POST -> simulated impact + critical incident
     -> strict: deny fake-secret read -> chain stops + evidence-backed prevention report
```

Deliver two profiles, explicit resource/destination rules, versioned policy decisions,
an explainable risk-score prototype, deterministic approval simulation, and JSON/Markdown
comparison reports. Preserve Python 3.13, SQLite, packaged JSON, and the socket-free adapters.
The Phase 1 command retains vulnerable behavior by default for compatibility.

The roadmap's domain rules mean exact simulated destination checks here: no DNS, real HTTP,
domain resolver, glob expansion, or additional host/virtual paths are needed. Both profiles
retain exactly `workspace/.env` and `lab://exfiltration-sink` as the outer capability boundary.

Deferred: UI/API, real LLMs, new attack scenarios, new tools, general policy DSL/YAML loading,
production authentication, live approval services, generic detection authoring, replay,
benchmark rates, and Phase 4 incident/metric infrastructure. No new dependency is expected.

## 3. Existing code and intended changes

| Existing surface | Current behavior | Phase 2 change |
|---|---|---|
| `gateway.py` | Safety checks and vulnerable policy are combined | Retain validation in the gateway; call a separate deterministic policy evaluator before dispatch |
| `runner.py` | Always constructs the vulnerable gateway | Accept trusted run options and inject profile, context, and simulated approval behavior |
| `mock_agent.py` | Stops after a denied or unsuccessful read | Preserve this behavior; do not force an HTTP request after a strict denial |
| `models.py`, `events.py` | Strict 0.1 envelopes; generic event payloads | Add typed policy/risk/approval contracts and explicit version handling |
| `detection.py` | `ASL-CORR-001` matches the completed simulated chain | Preserve matching semantics; derive prevention separately from policy evidence |
| `reporting.py` | Describes outcomes mainly from `detected` | Separate detection, prevention, simulated impact, and incomplete evidence |
| `cli.py` | Single `run` command | Add profile options and a bounded two-run comparison command |

Proposed new modules: `policy.py`, `risk.py`, `approvals.py`, and `comparison.py`.
Keep these small; no empty packages or general framework scaffolding.

## 4. Proposed policy contract

These implementation defaults are recorded in accepted ADR-005. Architecture acceptance does
not establish security review or permission to execute the candidate.

### Mandatory safety before configurable defense

Each request follows: record request -> enforce action/argument/resource limits -> evaluate
defense policy -> resolve simulated approval if needed -> persist final decision -> dispatch.
Safety denial cannot be overridden by a profile, score, approval, or scenario field. Failure
to validate/evaluate/persist a required decision must prevent adapter dispatch and fail the run.

| Request after schema validation | Vulnerable | Strict |
|---|---|---|
| Exact seeded fake-secret read | Allow | Deny: `secret_read_blocked` |
| Exact lab POST containing the seeded raw canary | Allow | Deny: `canary_transfer_blocked` |
| Exact lab POST without the canary | Allow | Require simulated approval |
| Unknown tool, unsafe path/destination, malformed/oversized arguments, exhausted action budget | Mandatory deny | Mandatory deny |

The strict main scenario stops at the read. Test the outbound rule directly through the
gateway with a synthetic canary; do not change the main scenario to bypass the denied read.
Use the existing raw-canary matching semantics for the prototype and document that it does
not establish general taint tracking or encoded-secret detection.

Policy inputs come from a validated request plus immutable controller-owned context:
run/trace/call identities, untrusted document provenance, resource classification, profile,
and policy version. Document markers, requested arguments, and scenario JSON cannot choose
their own trust, score, policy decision, approval result, or resource classification.
Reject unknown profile/version names; never silently fall back to vulnerable.

### Risk prototype

Proposed `risk-v1`: add 20 for untrusted document context, 60 for classified secret access,
40 for lab POST, and 60 for matching canary content in that POST; clamp the sum to 0–100.
Bands: 0–39 low, 40–79 elevated, 80–100 high. Persist factor codes, weights, score, band,
and scoring version. The same request/context scores identically across profiles.

In strict mode, explicit secret-read/canary-transfer denials take precedence; remaining
high scores deny, elevated scores require approval, and low scores allow. The current
closed tool set may not exercise every band end to end; test thresholds as pure functions.
Vulnerable mode records risk but allows safety-valid calls to preserve the baseline.
For invalid requests risk is unavailable, not zero. Approval does not subtract risk or
override hard rules. Weights are educational heuristics, not calibrated attack probabilities.

### Approval simulation

Use a trusted, synchronous simulator with `deny` as default and explicit `approve` for
otherwise eligible requests. Resolve immediately; no waiting, stdin prompt, durable queue,
human identity, or external service. This is product simulation, not actual human review.

Bind a response to the current run, trace, call, and policy version. Consume it once for that
call; reject mismatched, stale, missing, or malformed responses without dispatch. A selected
simulation mode may produce fresh responses for subsequent eligible calls, but a response
must never be reused. No approval is requested after a mandatory or strict hard denial.

### Evidence and versioning

Preserve the normal allowed sequence and the meaning of `tool.executed` as dispatch:

```text
tool.requested -> policy.evaluated -> policy.allowed -> tool.executed -> effect event
tool.requested -> policy.evaluated -> policy.denied
tool.requested -> policy.evaluated -> policy.approval_required
  -> approval.simulated -> policy.allowed or policy.denied -> effect only if allowed
```

For each evaluable call, record policy ID/version, profile, rule ID, decision, stable reason
code, enforcement layer (`safety` or `defense`), and risk details. Use the same call identity
throughout. Persist only bounded, typed, safe summaries; never raw bodies or raw invalid inputs.
For safety denials, record the selected profile but make clear that defense was not evaluated.

Propose event/report schema 0.2 for newly generated Phase 2 artifacts. Keep scenario schema
0.1, since policy choices remain controller options. Preserve reading original 0.1 events
with explicit version dispatch and fixtures; unknown versions fail clearly. Do not rewrite
old SQLite evidence or infer prevention for old artifacts lacking the necessary metadata.
Update any hardcoded version in `EventCollector` along with the models. No SQLite table
migration is expected because the version column and JSON payload already exist.

## 5. Outcomes, CLI, and comparison

Detection remains the existing correlation result. Add a separate prevention result with
`blocked`, blocking stage (`secret_access` or `outbound_transfer`), reason, and evidence IDs.
For the documented attack, derive prevention from ordered untrusted-context/request/defense-denial
evidence, matching run/trace/call and classified target, with no effect for the denied call.
A failed run, an arbitrary safety rejection, or simply `detected=false` is not proof of prevention.

Determine simulated impact from matching-canary sink evidence independently of the detector.
Missing correlation evidence must not hide an observed sink effect. Keep fields separate if a
future run contains both an earlier impact and a later block. For this fixed scenario, report
the expected completed outcomes as `simulated_impact`, `prevented`, or `no_correlated_chain`;
incomplete/contradictory evidence must be labeled explicitly, never treated as prevention.

Candidate commands (implementation prepared; execution awaits security review):

```text
agentsec run indirect-injection-secret-exfiltration --profile vulnerable --output-dir artifacts
agentsec run indirect-injection-secret-exfiltration --profile strict --output-dir artifacts
agentsec compare indirect-injection-secret-exfiltration --output-dir artifacts
```

Expose `--approval-simulation deny|approve` for strict runs, default `deny`. Reject the flag
with vulnerable mode rather than implying it changes baseline behavior. The fixed strict
malicious scenario remains denied under either simulation choice. The comparison command
uses exactly vulnerable and strict with default approval denial; no arbitrary profile list.

Create a fresh comparison directory with two independent child run directories, each retaining
`events.sqlite3`, `report.json`, and `report.md`, plus `comparison.json` and `comparison.md`.
The same scenario/fixture and policy versions must be recorded, with distinct run/trace IDs,
fresh adapters, and individual evidence cutoffs. Run children sequentially for reproducibility.

Build the comparison from canonical SQLite evidence, not stdout or expected fixture outcomes.
Include comparison identity, child IDs and relative artifact links, versions, decisions,
risk factors, approval results, detection, simulated impact, prevention, and evidence references
qualified by child run. Show the exact point at which execution diverges. Do not compute
attack-success or false-positive rates from two deterministic examples.

Keep exit 0 for completed artifacts even when an attack is detected or blocked; 2 for invalid
input and 1 for runtime/artifact failure. A comparison is successful only when both child runs
and both comparison reports complete. On failure preserve available child evidence, omit a
successful comparison result, and emit a safe failure summary identifying the affected child.
Respect existing limits per run and the 1 MiB limit per report; bound the comparison to two runs.

## 6. Work packages

```text
P2-00 Verify baseline -> P2-01 Contracts -> P2-02 Policy and risk -> P2-03 Approval and runner
                                                               -> P2-04 Reporting/comparison
                                                               -> P2-05 Verification and demo
```

These are local work IDs, not existing GitHub issues. This work does not request parallel
agents. Publish Map/Child issues only when issue creation is authorized.

### P2-00 — Close the baseline checkpoint

Record the Phase 1 CI run URL, tested SHA, and Windows/Linux job outcomes. Investigate any
failure before release. This is a Phase 2 completion and release gate, not a gate on preparing
the local implementation candidate. The candidate was prepared while CI visibility was
unavailable; do not mark A15 or Phase 2 complete until the remote evidence is recorded.

### P2-01 — Contracts and decisions

Review ADR-005 with profile precedence, score rules, approval semantics, versioning,
and comparison contracts. `docs/CONTRACTS.md` and `THREAT_MODEL.md` cover forged
policy context, approval reuse, fail-open evaluation, and false prevention claims. Add fixtures
for allowed, safety-denied, defense-denied, approved, rejected, and unavailable approval paths,
plus legacy 0.1 compatibility and new 0.2 reports. Confirm scope against this plan before coding.

### P2-02 — Separate policy evaluation and risk

Implement typed immutable policy inputs/outputs and closed profile selection. Extract existing
safety checks carefully without weakening them. Add pure risk evaluation, stable rule IDs,
versioned reason codes, and gateway decision telemetry. Test both profiles against the full
existing safety matrix, strict fake-read and canary-POST denials, threshold boundaries, and
policy/telemetry failures. Denied calls must never invoke adapters.

### P2-03 — Simulated approval and run options

Implement response binding and immediate resolution, inject controller-owned options, and add
CLI profile selection. Retain mock stop-on-denial behavior. Test forged metadata, missing or
reused responses, approval rejection, and approval of a safe non-canary lab POST. Exercise those
approval paths through a gateway/controller integration harness without adding another public
attack scenario. Verify approval cannot authorize a fake-secret read or unsafe destination.

### P2-04 — Prevention and defense comparison

Add evidence-based prevention and impact derivation, schema 0.2 reports, comparison orchestration,
and JSON/Markdown outputs. Preserve `ASL-CORR-001` semantics. Add installed CLI tests for vulnerable,
strict, and compare, plus benign and missing-canary controls under both profiles. Cover child
failure, report-write failure, cross-run evidence, legacy versions, redaction, and incomplete
evidence. Keep critical incidents limited to existing correlated matches.

### P2-05 — Verification and CV demonstration

After the applicable security review, run Ruff formatting/lint, strict MyPy, the full test
suite, and meaningful new contract/security tests. Build/install a wheel in a clean environment
and run the comparison outside the source checkout. Verify Windows and Linux through the manual
workflow and record run URLs/SHA. Run dependency auditing if dependencies change and retain
the existing CI audit. No dependency upgrade is implied by this documentation plan.

Update README with implemented commands and a short two-profile demo; add redacted example
comparison reports. Update roadmap status only after the exit criteria below pass. Any workflow
rename or trigger change is an explicit implementation change; preserve manual execution unless
the owner separately changes that policy.

## 7. Acceptance checklist

| ID | Required evidence | Package |
|---|---|---|
| A01 | Existing default command still produces the complete vulnerable chain and critical incident | 02–04 |
| A02 | Strict malicious run denies the read before `file.read`; no subsequent POST or canary sink effect | 02–04 |
| A03 | Direct strict canary POST is denied before adapter dispatch | 02 |
| A04 | Every profile denies all existing unsafe paths, destinations, tools, schemas, and limits | 02–03 |
| A05 | Allow, deny, and approval paths have correlated versioned decisions with reasons | 02–03 |
| A06 | Risk factors and scores are deterministic, bounded, profile-independent, and labeled heuristic | 02 |
| A07 | Safe lab approval works; missing, rejected, forged, stale, or reused approval cannot dispatch | 03 |
| A08 | Approval never overrides mandatory safety or strict hard denials | 03 |
| A09 | Both profiles produce accurate reports; detection, impact, prevention stage, and failure are distinct and comparison claims use their corresponding evidence | 04 |
| A10 | Comparison uses identical scenario inputs, isolated children, and resolvable SQLite evidence | 04 |
| A11 | Benign controls are not labeled prevented; missing-canary vulnerable control has no critical match | 04 |
| A12 | Failures, inconsistent decisions, dispatch after denial, missing evidence, or one successful child cannot masquerade as successful prevention/comparison | 02–04 |
| A13 | All paths remain socket/DNS-free, bounded, redacted, and isolated across runs | 02–05 |
| A14 | Original 0.1 evidence remains readable; 0.2 examples validate; unknown versions fail clearly | 01, 04 |
| A15 | Clean installed CLI demo, lint/types/tests, required review, and Windows/Linux CI evidence pass | 05 |

## 8. Review and handoff

The implementation diff and test definitions are prepared in this branch. Use the
[Phase 2 security review checklist](PHASE_2_SECURITY_REVIEW.md) before executing them. The earlier
Phase 1 sign-off covers that implementation; it is not evidence of review of this Phase 2 diff.
Label this handoff
`Security Sensitive: Requires Mandatory Human Review`. Simulated approval events are never a
substitute for actual repository review.

There is no unresolved product choice blocking this plan. The accepted defaults keep Phase 2
within the roadmap; different block points, score weights, or approval scope can be revised
during contract review. The outstanding operational item is visibility into remote CI results.
License selection remains a separate owner decision and is not expanded by this phase.

Suggested implementation handoff:

> Read AGENTS.md, docs/PHASE_2_IMPLEMENTATION_PLAN.md, and the referenced contracts and security
> guidance. Implement P2-00 through P2-05 in dependency order, preserving the vulnerable default,
> immutable safety boundary, and existing tests. Record ADR-005 before dependent code. Prepare
> applicable sensitive changes and tests for explicit human review before execution. Verify
> A01–A15 and report the actual test results, CI run evidence, remaining limitations, and review
> status. Do not claim real-model robustness or real network prevention from this simulation.

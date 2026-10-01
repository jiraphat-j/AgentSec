# Phase 6A security review

Latest C07 state (2026-10-01): **Targeted repair owner-reviewed and approved;
sandbox quality/regression/browser/build/installed CLI checks passed.** See [C07 review](PHASE_G0_C07_REVIEW.md).
Earlier approvals/results below do not establish review or execution of this changed diff.

Status: **C11 repair owner-approved; C02 test execution was owner-authorized after assistant
review, and focused, full non-browser, installed-package, and Playwright checks passed in a
networkless sandbox. Final owner full-diff review and acceptance remain open.**

## Reviewed scope

- Closed schema 0.2 direct-prompt scenario and packaged fixtures only.
- Controller-generated `agent.context.prompt_added` metadata only; no prompt body is persisted.
- Existing virtual file adapter and `lab://exfiltration-sink`; no socket, DNS, subprocess, host-path,
  dependency, or policy-permission change.
- `risk-v2` accurately labels direct prompt context. `policy-v1` strict hard-denial behavior remains
  unchanged.
- Closed `ASL-CORR-003` live/declarative correlations and safe dashboard projection fields.

## Authorization and evidence

The owner authorized Phase 6A attack-scenario tests only inside a sandbox. Runtime tests and
installed CLI runs used a networkless bubblewrap namespace with the repository mounted read-only;
the package build used a disposable overlay. Setup downloads and the dependency audit had no
repository mount. On 2026-09-27 the owner separately authorized trying the dashboard browser checks
outside the sandbox. Two synthetic dashboard tests passed on Windows with a page-request guard
allowing only 127.0.0.1. Browser-process egress was not OS-blocked; no attack scenario ran on the
host. The [verification record](PHASE_6_VERIFICATION.md) lists both sets of results. This narrow
authorization does not extend to unrestricted host scenario execution or integration.

On 2026-09-27 the owner directed the full sensitive G2 rerun to an isolated sandbox. The focused
and full suites, quality checks, build, installed-wheel flows, and dependency audit passed there.
However, a forged manifest-loaded `agent.context.prompt_added` event with arbitrary `prompt_id`
text passed validation and reached the dashboard API. A genuine packaged direct run stayed
redacted. C11 remains open; fix and human review are required before acceptance.

## C11 repair reviewed by owner

- `encode_safe_projection` rejects projected `prompt_added` events unless their prompt ID is one
  of the three packaged fixture IDs and source, trust, and delivery channel exactly match the
  Phase 6A contract. It also rejects an invalid direct `run.started` fixture. This covers
  manifest-loaded sources and directly constructed catalogs through the existing fixed 503 API
  error, without adding a listener, egress path, dependency, or writable dashboard action.
- New regression tests cover forged prompt fields, direct fixture IDs, source immutability, fixed
  API errors, and valid closed metadata. At submission for owner review, only formatting, lint,
  typing, and diff checks had run on this changed snapshot.
- This is projection validation, not proof that arbitrary imported event-envelope strings are
  authentic or harmless. That residual boundary remains for final acceptance review.

On 2026-09-28 the owner approved this concrete repair and the sandbox-only G2 rerun. The focused
dashboard suite passed 28 tests; the full non-browser suite passed 150 tests with 90.23% coverage
and one skipped browser test. The offline wheel/sdist build and installed CLI smoke passed. The
direct-prompt browser DOM/request check remains open, as do exact-commit CI and final acceptance.

On 2026-09-29 the owner requested Playwright. Three dashboard browser tests passed inside a
networkless WSL2 bubblewrap namespace, including a new direct-prompt DOM redaction and loopback
request check. A bounded server-readiness wait was added to the browser test after an observed
startup race; production source was unchanged. Chromium required omitting the incompatible
per-process virtual-address limit; the WSL VM memory ceiling and other sandbox bounds remained.
Playwright and its browser were staged outside the repository, and the staged Python packages
passed `pip-audit`. Manual accessibility, exact-commit CI, and final full-diff review remain open.

## Mandatory reviewer checks

1. Confirm ToolGateway changes do not relax path, destination, size, tool-count, or policy checks.
2. Confirm raw prompt, marker, fake canary, and tool body cannot enter persisted events, reports,
   dashboard projections, logs, or errors.
3. Confirm direct fixtures cannot select adapters, profiles, destinations, output paths, or imports.
4. Review the final diff, browser sandbox limitation, and remaining manual accessibility evidence
   before final acceptance.

**⚠️ Security Sensitive: Requires Mandatory Human Review.**

## New C02 resource-loader review request, 2026-09-29

The loader now limits scenario JSON to 16 KiB and reads scenario/document/prompt bytes only up to
their cap plus one byte before UTF-8 decoding. Scenario JSON rejects duplicate keys and non-finite
values, and embedded scenario IDs must match the exact packaged ID requested. Regression cases
use fake packaged resources; they have not been executed. Review the compatibility effect on the
legacy document/scenario path, packaged resource opening in wheel and sdist, fixed error behavior,
and whether malformed or substituted resources fail closed. Only Ruff format/lint, strict mypy,
and diff checks had passed before runtime execution. The preceding G2 results were not inherited;
the owner separately authorized this execution on 2026-09-30. The renewed sandbox results and
remaining C02 caveat are in the [verification record](PHASE_6_VERIFICATION.md).

## C07 prepared repair review request, 2026-10-01

The direct live detector and offline rule have a prepared diff requiring exact virtual secret
resource and canonical context/read/sink components. Direct fixtures include the resource;
sixteen unexecuted regressions cover negatives, positives, interleaving and indirect compatibility.
Rule version 1 is retained provisionally as a documented C07 correction, not a finalized
compatibility decision. Review stricter imported-evidence matching and changed rule content/
fingerprint, or require coordinated version updates before execution. No gateway, policy, adapter,
risk, hashing algorithm, tool, socket/process permission, schema, dependency, old-suite or CI change.

Ruff format/lint, isolated strict MyPy (55 files), diff and JSON structure checks passed. No
changed-runtime command ran. The request to proceed without owner review is not recorded as
satisfying the mandatory concrete-diff human-review gate. A human reviewer must inspect the
files and prepared manifest in the C07 record and sign off before the named sandbox tests run.

The owner subsequently confirmed they reviewed this repair and approved it on 2026-10-01.
The source/test manifest was verified unchanged before execution. This approves the named
sandbox-only C07/regression/package/browser checks and the disclosed version-1 correction;
it does not authorize publication, CI dispatch, further sensitive changes or phase acceptance.

Following approval, the focused sixteen C07 tests passed; the final suite passed 288 tests at
91.36% coverage and four Chromium checks passed separately. Only the expected full-ruleset golden
vector required alignment after the first regression run; sensitive code remained the reviewed
snapshot. The legacy rule/suite/snapshot vectors stayed unchanged. Quality/build/clean installed
CLI checks passed in the documented networkless namespace. Remaining G0/G3/G4 criteria and final
full-diff review are not accepted by this result; see the latest verification section.

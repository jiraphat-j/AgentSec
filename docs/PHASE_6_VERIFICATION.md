# Phase 6A verification record

Status: **The owner-approved dashboard repair and subsequent test-only evidence batch passed
sandbox verification: 373 non-browser tests, four Chromium checks, 91.95% coverage,
quality/build and installed-package checks.
G0, other residual cases, manual accessibility, exact-commit CI and final review remain open.**

G0 Phase 5 deferral and G1 Phase 6A design approval were provided by the owner on 2026-09-22.
On 2026-09-24 the owner authorized G2 test execution only inside a sandbox. On 2026-09-27 the owner
separately authorized trying the previously blocked browser checks outside that sandbox. No attack
scenario tests ran on the host. Final human review of the complete diff remains pending.

## Tested worktree and isolation

- Base HEAD: `5f6de2d93e15fc8c22a8ed5690c037ad6b85e43c`; changes remain uncommitted.
- Source/test manifest SHA-256: `bfec298e35191aede907217f985fb8fdd2dec4c8d18f2f06e0c63eb9f23fc64d`.
  This covers 77 sorted tracked and untracked files under `src`, `tests`, and `pyproject.toml`,
  hashing each path and file content. It identifies the tested code snapshot, not a Git commit.
- Platform: WSL2 Ubuntu 26.04, CPython 3.13.15.
- Runtime tests, lint, typing, build, and installed CLI used bubblewrap `--unshare-all` with no
  external network, bounded wall/CPU/memory/process resources, and tmpfs output. Source tests
  mounted the repository read-only; the build used a disposable writable overlay. Setup downloads
  and the dependency audit used a separate networked sandbox with no repository mount.

## Local results, 2026-09-24

- Focused G2 regressions: `python -m pytest -p no:cacheprovider -q` on the two affected modules
  with the five review-case names selected: **5 passed**.
- Affected modules: `python -m pytest -p no:cacheprovider -q
  tests/test_detection_and_reporting.py tests/test_incidents_and_evaluation.py`: **33 passed**.
- Full non-browser suite: `python -m pytest -p no:cacheprovider --cov=agentsec
  --cov-report=term-missing --cov-fail-under=90`: **143 passed, 1 skipped**, 90.19% coverage.
  The skip was the optional browser module before Playwright was staged.
- `python -m ruff format --check .`: **98 files formatted**; `python -m ruff check .`: **passed**.
- `python -m mypy`: **passed, 50 source files**.
- `python -m build --no-isolation --outdir /sandbox/dist /work -q`: **wheel and sdist built**
  inside a disposable source overlay; all eight new Phase 6A resources are present in both.
- Installed-wheel CLI smoke without a source mount: vulnerable direct scenario reported
  `simulated_impact`, `detected=true`; strict direct scenario reported `prevented=true`.
- `python -m pip_audit --path /sandbox/smoke-venv/lib/python3.13/site-packages`: **no known
  vulnerabilities** in installed runtime dependencies. The local `agentsec-lab` package itself
  was skipped because it is not published on PyPI.
- Dashboard browser command `python -m pytest -p no:cacheprovider -q -m dashboard_e2e
  tests/e2e/test_dashboard.py`: **2 setup errors**. Chromium exited with SIGTRAP inside the
  networkless sandbox after its missing shared libraries were staged; no page assertions ran.

## Host browser result, 2026-09-27

- Windows, CPython 3.13.15, existing `.venv` and cached Chromium; no download or dependency change.
- `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q -m dashboard_e2e
  tests/e2e/test_dashboard.py --maxfail=1`: **2 passed in 8.02s** outside bubblewrap.
- The tests serve synthetic in-memory dashboard records on `127.0.0.1`; a new Playwright page-route
  guard aborts requests to non-loopback URLs. It is not an OS-level browser egress block.
- Browser test file SHA-256: `FD46266C6F4691E41D02A9D0260B6F2285E966AEB906769643042D49C7787CFA`.

## G2 preflight and open C11 check, 2026-09-27

- The owner reiterated G2 approval. The prior sandbox-only attack-scenario boundary is being
  clarified; no attack scenario was run on the host in this pass.
- Windows static checks: Ruff format **98 files formatted**, Ruff lint **passed**, and strict mypy
  **passed for 50 source files**.
- A synthetic `safe_event` check showed that arbitrary text in a forged direct prompt `prompt_id`
  survives the dashboard projection. C11 redaction remains open pending validation and review.
- A requested Windows-host non-browser suite run was rejected by safety review because the prior
  sandbox-only condition was not clearly lifted. That suite command did not execute.

## Sandboxed G2 rerun, 2026-09-27

- The owner directed sensitive G2 tests to a sandbox. Dependency setup used a separate networked
  bubblewrap namespace with no repository mount. Runtime tests used `--unshare-all`, a read-only
  repository mount, tmpfs output, and wall/CPU/memory/file-descriptor limits.
- Tested base HEAD: `5f6de2d93e15fc8c22a8ed5690c037ad6b85e43c`; source/test manifest SHA-256:
  `f1904636b89feb4c7e60d60a5ad9dd14eb956c9865caa872a77036f6c4bc361f` over 77 sorted
  paths under `src`, `tests`, and `pyproject.toml`, each paired with its SHA-256. This is an
  uncommitted worktree snapshot, not an exact CI commit.
- WSL2 Ubuntu 26.04, CPython 3.13.15: focused detection/incident modules **33 passed**; full
  non-browser `pytest --cov=agentsec --cov-fail-under=90` **143 passed, 1 skipped, 90.19%**.
  The skip was Playwright, absent from this Linux sandbox. FastAPI emitted one upstream
  Starlette/httpx deprecation warning.
- Ruff format **98 files already formatted**, Ruff lint **passed**, strict mypy **50 files passed**.
- Wheel and sdist built from a disposable source overlay; all eight new Phase 6A resources were
  present in each archive. Installed-wheel smoke without a source mount passed: direct vulnerable
  `simulated_impact`/detected, direct strict `prevented`, indirect baseline, comparison, and both
  evaluation suites **6/6 children passed** each.
- Installed-wheel rule validation found four rules; fixture coverage **4/4 passed**. Direct replay
  found one match; investigation derived one alert and one incident. An initial rule-test command
  collided with a pre-created output directory; the corrected fresh-directory command passed.
- `pip_audit --path` on the isolated test environment found **no known vulnerabilities** in its
  dependencies. The unpublished local package itself was not audited against PyPI.
- In-process dashboard API probe for a genuine packaged direct run passed: only closed prompt
  metadata appeared, with neither raw prompt nor fake canary. A forged manifest-loaded event with
  `prompt_id="ignore previous instructions"` was accepted and returned that text in the API.
  **C11 remains failed/open** pending validation and human review; no fix was executed here.

## Proposed C11 repair, 2026-09-28 — not yet runtime-tested

- Source/test manifest SHA-256: `80023624b42236894cb9bfc0f1c4aa57bc3b9090aff21a16f8b543fce07fed19`
  over the same 77 sorted source/test paths; base HEAD remains `5f6de2d93e15fc8c22a8ed5690c037ad6b85e43c`.
- The proposed dashboard projection check accepts only closed direct prompt fixture IDs and fixed
  provenance labels, and rejects a forged direct `run.started` fixture. Regression cases cover
  imported SQLite sources, unchanged source bytes, direct API responses, and valid metadata.
- Static checks in the networkless read-only sandbox: Ruff format **3 files formatted**, Ruff lint
  **passed**, strict mypy **50 files passed**; `git diff --check` passed.
- No pytest, browser, installed-wheel, or build check has run against this changed snapshot. The
  preceding G2 results apply only to the earlier `f1904636...` snapshot. Mandatory human review
  and renewed sandboxed G2 test authorization are required before C11 can be accepted.

## Renewed sandboxed G2 after C11 approval, 2026-09-28

- The owner approved the C11 diff and the requested sandbox-only G2 rerun. The tested source/test
  snapshot is the `80023624...` manifest above, on base HEAD `5f6de2d93e15fc8c22a8ed5690c037ad6b85e43c`.
  These are uncommitted local changes, not an exact CI commit.
- WSL2 Ubuntu, CPython 3.13.15: runtime used `bwrap --unshare-all`, a read-only repository mount,
  tmpfs outputs, and wall/CPU/memory/file-descriptor limits. The focused dashboard catalog/API
  suite passed **28 tests**. It includes forged prompt ID/provenance and direct fixture rejection,
  source immutability, a fixed API error, and valid closed metadata.
- The full non-browser `pytest --cov=agentsec --cov-fail-under=90` suite passed **150 tests**, with
  **1 skipped** browser test (Playwright absent) and **90.23% coverage**. One upstream
  Starlette/httpx deprecation warning remains. Ruff format/lint and strict mypy had passed on this
  same source/test snapshot before approval; they were not rerun in this pass.
- An offline, no-isolation wheel/sdist build from a disposable source copy passed inside the
  networkless sandbox. Both archives contained all eight new Phase 6A resources. The wheel was
  installed to a tmpfs target, then its CLI was exercised from `/tmp`: direct vulnerable
  **simulated impact/detected**, direct strict **prevented**, indirect vulnerable baseline, and
  both evaluation suites **6/6 children passed**. The repository remained mounted read-only for
  this smoke check but was not on the CLI import path; this is not a no-source-mount claim.
- No package dependency changed in the C11 repair; the prior sandbox dependency audit remains the
  applicable dependency result. The C11 regression is now green in API/catalog tests, but the
  direct-prompt browser DOM/request check remains unverified in this Linux sandbox. The test run
  did not change the repository worktree. No host attack scenario test was run.

## Sandboxed Playwright browser verification, 2026-09-29

- The owner requested Playwright for the remaining browser check. Test-only Playwright 1.63.0,
  pytest-playwright 0.9.0, and Chromium 153.0.8010.12 were staged in a task-owned directory by a
  networked setup sandbox with **no repository mount**. Playwright selected its Ubuntu 24.04
  fallback build on WSL2 Ubuntu 26.04. Three missing Chromium libraries were downloaded from the
  Ubuntu package archive and extracted there, not installed on the host. `pip-audit --path` on the
  staged Python packages found **no known vulnerabilities**; that audit does not cover Chromium or
  the Ubuntu library archives.
- Browser runtime used `bwrap --unshare-all`: no external network, repository and test tooling
  read-only, tmpfs output, cleared inherited environment, and wall/CPU/file-descriptor limits.
  Chromium exited with `SIGTRAP` under tested process virtual-address limits, including 32 GiB,
  but launched without that limit. The browser run therefore relied on the WSL VM's approximately
  7.7 GiB memory ceiling rather than a per-process `RLIMIT_AS`; this is a weaker memory bound than
  the preceding non-browser run. No attack scenario ran in the browser or on the Windows host.
- The first browser navigation twice raced Uvicorn startup. A bounded server-readiness wait was
  added to the browser test; no production source changed. The final networkless command
  `python -m pytest -p no:cacheprovider -q -m dashboard_e2e tests/e2e/test_dashboard.py` passed
  **3 tests in 9.36 s**. The new direct-prompt test confirms safe fixture/provenance metadata in
  the DOM, excludes raw prompt, marker, and fake canary from rendered content, and observes only
  loopback requests; the existing page-route guard aborts non-loopback requests. Ruff format/lint
  and strict mypy passed after the test edit (**50 files**).
- The browser test file SHA-256 is
  `E76A1C2299E1605A77185276B7F11F4687CEA7773C8422D025C8AAA7B7B9C9C7`. The earlier
  `80023624...` manifest predates this **test-only** change; production source remained unchanged.
  This is local uncommitted evidence, not exact-commit CI or manual accessibility signoff.

## WSL swap follow-up, 2026-09-29

- The owner approved increasing WSL swap from 2 GiB to 4 GiB. No WSL distribution was running
  before the global `%UserProfile%\.wslconfig` file was created with only `[wsl2]` and `swap=4GB`.
  Ubuntu startup then reported **4.0 GiB swap, 0 used**. This disk-backed setting was applied after
  the browser and non-browser G2 results above; those tests were not rerun because of it.

## C01–C13 evidence audit, 2026-09-29

This is a mapping of **observed local evidence**, not a claim that any entire acceptance row has
passed. Non-browser results apply to the `80023624...` source/test snapshot above; the three
Playwright results apply after the test-only browser edit identified by its `E76A1C...` file hash.
There is no exact commit for either snapshot. Historical failures above remain part of the record;
the later C11 fix and browser pass supersede them only for the named checks.

| ID | Evidence observed | Still required for acceptance |
|---|---|---|
| C01 | Indirect installed CLI smoke, `core-lab-v1` 6/6, historical indirect report assertion and Phase 4 fingerprint tests passed in the sandbox. | Phase 5's open prerequisites need an enumerated owner-approved deferral (with impact/follow-up) or completion; its verification file still says no deferral recorded. Confirm old-suite fingerprint and exact compatibility at final revision. |
| C02 | Packaged direct and indirect scenarios loaded in the earlier sandbox; Pydantic models close known fields/fixtures; installed CLI accepted both. | A new bounded/duplicate-key/identity loader repair and malformed-resource regressions are proposed below, but have **not** run. Review the diff and rerun sandboxed tests before crediting C02. |
| C03 | Installed direct vulnerable/strict runs produced simulated impact/detection and prevention; indirect repeated-run and comparison isolation tests passed. | Add direct-profile event/store identity assertions and direct repeated, consecutive, concurrent, and comparison isolation checks. |
| C04 | `direct-injection-v1` completed its six closed children with expected outcomes in installed smoke. | Add dedicated direct benign and non-matching-canary event-order, zero-tool/incident, and exact-outcome E2E assertions rather than relying only on suite expectations. |
| C05 | Direct run asserts a closed `prompt_added` payload; API/catalog and Playwright projection regressions reject forged metadata or omit raw prompt/canary. | Scan decoded direct SQLite, reports, incidents, logs, and error paths for raw prompt/marker/canary/body, including failure cases and prompt-before-tool ordering. |
| C06 | Direct risk-v2 factor test and indirect risk-v1/policy regressions passed; strict installed direct run prevented. | Complete direct policy matrix, forged-context and approval-path checks, plus historical risk artifact parsing. |
| C07 | Packaged positive/negative ASL-CORR-003 fixtures passed rule validation; direct replay/investigation produced one match/alert/incident. | Add direct-specific wrong trust/channel/path, missing/reordered event, cross-run/trace, interleaving, limit-exhaustion, and live/offline parity assertions. |
| C08 | Direct installed vulnerable/strict results and shared report/comparison semantic tests passed. | Add golden direct vulnerable/strict/benign/control report and comparison assertions, including no incorrect document-origin language. |
| C09 | Direct installed investigation produced one incident; shared replay read-only and evidence-link tests passed. | Check direct incident stage/reference resolution and forged/missing/cutoff/fingerprint cases, source hashes, and direct detector-only runtime spies. |
| C10 | Installed `direct-injection-v1` and `core-lab-v1` each completed 6/6; shared metric/failure tests passed. | Assert the direct suite's exact matrix, fractions, exclusions, pairs, counts, repetitions, timing limits, and unchanged core-suite fingerprint in dedicated tests. |
| C11 | C11 fix was owner-reviewed; 28 focused tests passed, and three sandboxed browser tests passed including a direct DOM redaction/loopback-request check. | The browser direct case uses a synthetic in-memory event, not a manifest-loaded direct artifact. Complete loader-to-browser parity/source-hash and broader hostile-content checks; manual accessibility is separate. |
| C12 | Networkless sandbox; shared gateway/socket/DNS/deadline/boundary tests and installed direct run passed. | Complete direct subprocess/host-file spies, at/over resource bounds, forced adapter/store/report failures, cleanup, concurrent isolation, and platform-specific path cases. |
| C13 | Offline wheel/sdist contained all eight new resources; installed direct/indirect CLI smoke passed; 150 non-browser tests passed at 90.23% coverage, three browser tests passed, Ruff/MyPy passed, and audited Python dependencies had no known vulnerabilities. | Verify a final single snapshot after any repairs, then obtain human-dispatched Windows/Ubuntu CI on the exact reviewed commit. The audit did not cover Chromium or staged Ubuntu library archives. |

G0 remains documentary-incomplete: the owner approved Phase 5 deferral in conversation on
2026-09-22, but [Phase 5 verification](PHASE_5_VERIFICATION.md) does not enumerate or record those
deferrals and still marks them open. Do not infer that all Phase 5 risks were accepted. G3 remains
open because the matrix above contains untested cases; G4 requires final full-diff owner review,
manual accessibility evidence, exact-commit Windows/Ubuntu CI, and explicit integration decisions.

## Proposed C02 loader repair — before renewed G2

After the evidence audit, `src/agentsec/resource_loader.py` was changed to read scenario,
document, and prompt resources with a fixed `limit + 1` byte cap before UTF-8 decoding; scenario
JSON now rejects duplicate keys and non-finite values, and its validated embedded ID must match
the requested packaged ID. `MAX_SCENARIO_BYTES` is 16 KiB. New cases in
`tests/test_contracts_and_events.py` cover both scenario IDs, unknown IDs, invalid/oversized UTF-8,
malformed/duplicate/non-finite JSON, substituted identity, invalid schema/field/type, direct
channel/fixture, and prompt size/encoding. This changes the trusted resource-loading boundary and
the legacy document read path; it needs concrete human review before runtime execution.

Only non-runtime checks ran on this new diff: Ruff format **3 files formatted**, Ruff lint
**passed**, strict mypy **50 files passed**, and `git diff --check` **passed**. The earlier
`80023624...` test manifest and `E76A1C...` browser-file hash do **not** identify this newer
snapshot. At this point no pytest, scenario, browser, build, or installed-wheel command had run
since this repair. The prior green G2 results could not be applied to this changed loader.

## Renewed sandboxed G2 for C02, 2026-09-30

After an assistant review, the owner authorized C02 test execution; this is not final owner
full-diff signoff. This approval was applied only to the existing networkless WSL2 bubblewrap
sandbox, not the Windows host. The tested source/test
snapshot has base HEAD `5f6de2d93e15fc8c22a8ed5690c037ad6b85e43c` and manifest SHA-256
`22c362093444847c9df2c6e7c5f284d27bf0f31a83ff6832cef64e5821e0a0b1` over 77 sorted
tracked and non-ignored untracked `src`, `tests`, and `pyproject.toml` paths, each paired with its
file SHA-256 and joined by LF. It is not a Git commit. The C02 test-file SHA-256 is
`053f16143ea6a12521bc1041a1eeb9a9174574a57d42a1a184810a1630556d47`.

- The initial focused `tests/test_contracts_and_events.py` run passed **16 tests** but surfaced
  two pytest warnings caused by empty test-message matchers. Test-only follow-up removed those
  warnings, asserted exact packaged path selection, and added invalid/oversized legacy-document
  cases; no production source changed after the initial focused run.
- Final focused module: **18 passed**, no warning. Full non-browser
  `pytest -p no:cacheprovider --cov=agentsec --cov-report=term-missing --cov-fail-under=90 -q`:
  **157 passed, 1 skipped, 90.39% coverage**. The skip was the optional Playwright module absent
  from that Python environment; one upstream Starlette/httpx deprecation warning remained.
- Ruff format **3 files formatted**, Ruff lint **passed**, strict mypy **50 files passed**, and
  `git diff --check` **passed** on the final test snapshot.
- Offline wheel and sdist were built from a disposable source copy; both included all eight new
  Phase 6A resources. An installed-wheel CLI run from `/tmp` passed direct vulnerable
  **simulated impact/detected**, direct strict **prevented**, and indirect vulnerable baseline;
  both evaluation suites passed **6/6 children**. This validates the new binary packaged-resource
  `open()` path in an installed wheel. The source repository was mounted read-only but not on the
  CLI import path.
- Three Playwright dashboard tests passed on the final snapshot in the same networkless sandbox.
  A first browser attempt did not run page assertions because a process-count limit prevented
  Chromium/Playwright setup. The successful retry removed that limit while retaining read-only
  repo/tool mounts, tmpfs output, cleared environment, and wall/CPU/file-descriptor limits. As
  in the prior browser run, there was no per-process virtual-address limit; the WSL VM memory
  ceiling and 4 GiB disk-backed swap were the remaining memory bounds. DBus warnings did not
  affect the three passing assertions.

C02 now has passing local malformed-resource, legacy-compatibility, and installed-package evidence.
The new tests still do not independently assert the exact `limit + 1` argument passed to the
resource stream, though the source does so. This and the other C01–C13 gaps above remain for G3;
no exact-commit CI or final owner acceptance is claimed. No dependency was changed, so the prior
isolated Python dependency audit remains the latest audit; it did not cover Chromium or staged
Ubuntu library archives.

At the time of these local verification runs, no commit, push, PR, merge, or release had been
performed. The retained wheel and sdist are in the task-owned `phase6a-test-env/dist` directory
outside the repository. Subsequent integration actions must be evaluated against their own exact
commit and CI evidence; these local results do not by themselves close G3 or G4.

## Phase 6B G0 focused evidence batch, 2026-09-30

The owner approved the prepared test-only G0 batch for **networkless sandbox execution**, not a
blanket Phase 5/6A deferral, Phase 6B implementation, host execution, CI dispatch, or final
acceptance. A new isolated worktree is based on merged-main revision
`9649fc5fe0e580e7f736c7e6247e731e98521310`. There are no product-source changes. The sole
new test file, `tests/test_phase6a_g0_prepared.py`, has SHA-256
`56530e28eca61ea9bb047f2168aa3b61cdc61bd196e2344a04bee19d23bec959` at execution.

The prior Python 3.13 environment was not available in this worktree. Setup staged uv 0.12.21,
CPython 3.13.15, pytest 9.1.1 and Pydantic 2.13.5 in a separate network-capable bubblewrap
namespace **without a repository mount**. Ubuntu's system Python lacked `ensurepip`; initial
PyPI lookup failed because `/etc/resolv.conf` points to an unmounted WSL resolver file. Mounting
only that resolver file read-only fixed setup DNS. The final dependency-install setup command
cleared inherited environment variables; the earlier uv/Python staging commands did not. No
scenario or test ran during setup.

The runtime used WSL2 Ubuntu and `bwrap --unshare-all` with no external network, a read-only
worktree at `/work`, a read-only staged environment at `/sandbox`, no general host drive/home
mount, cleared environment, `PYTHONDONTWRITEBYTECODE=1`, disabled pytest cache/plugin autoload,
and tmpfs `/tmp` for output. Only `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/passwd`, and `/etc/group`
were additionally exposed read-only, plus sandbox `/dev` and `/proc`. The preflight verified that
the staged Python 3.13.15 and test file were readable inside the namespace and the host C: drive
was not mounted. The test shell set CPU 60 s, virtual memory 1 GiB per process, process count
128, file descriptors 256, file size 64 MiB, and wall deadline 120 s. The inner command was:

```text
python -m pytest -p no:cacheprovider -q tests/test_phase6a_g0_prepared.py
```

Observed result: **12 passed in 2.62 s**, no skips. The batch adds partial evidence for C05
(direct vulnerable/strict SQLite and report byte scans, provenance order, forced failure), C07
(positive and seven negative live/offline rule parity variants), and C12 (socket/DNS/subprocess
spies under both profiles). Ruff format/lint and full-project strict MyPy passed on the prepared
test snapshot before execution. It does **not** cover the other C05/C07/C12 cases listed above,
the Phase 5 open rows, manual accessibility, or exact-commit Windows/Ubuntu CI. G0 and final
Phase 6A acceptance remain open; no commit, push, PR, merge or release is authorized by this run.

## Expanded Phase 6B G0 evidence, 2026-10-01

The owner approved continuing the G0 evidence-completion work and its sandbox-only execution.
This reuses the existing approval, not a new Phase 6B runtime authorization or a deferral.
The isolated worktree remains based on merged revision
`9649fc5fe0e580e7f736c7e6247e731e98521310`. Product source, packaged fixtures, dependencies,
and CI configuration are unchanged. Three new test modules and one browser-test addition
provide additional evidence; all changes remain uncommitted.

### Exact tested snapshot

Source/test manifest SHA-256 is
`1470545f5b093ff69e1aa206ecf137a0998f4f0b1d0484b868d9f193f3673b76` over 80 sorted
tracked and non-ignored untracked paths under `src`, `tests`, and `pyproject.toml`. Each record
is `path`, one space, and the lowercase file SHA-256; records are joined with LF, without a
trailing LF. This identifies an uncommitted snapshot, not an exact-commit CI result.

| Test file | SHA-256 |
|---|---|
| `tests/test_phase6a_g0_prepared.py` | `56530e28eca61ea9bb047f2168aa3b61cdc61bd196e2344a04bee19d23bec959` |
| `tests/test_dashboard_g0_boundaries.py` | `323205b49bfed91fe4fc66cc1b8193d7f3cd6a29d12faa0e4dc6a91806a2c47e` |
| `tests/test_phase6a_g0_matrix.py` | `ca29a90a5c9f078e8266747d34d98074c63cab35fb7d9dacf4708fb56439a4ad` |
| `tests/e2e/test_dashboard.py` | `1904decbca93b12acf813b200d1605ffb66ac2c30c31c7bc5087105a5cddd133` |

### Added assertions and their limits

- C02: all four public scenario/document/prompt resource-loading paths independently assert
  one binary `read(cap + 1)` call and stream closure, at the configured byte ceiling and above it.
- C03/C04/C08: the complete three-fixture/two-profile direct matrix checks exact outcomes,
  tool/incident counts, provenance order, event identities/sequences, decoded report redaction,
  and direct-origin wording. Consecutive, concurrent and comparison runs check run/trace/report
  separation; comparison outcomes and wording are checked, not a complete golden report.
- C06: both approval simulations cannot override strict secret-read denial; the direct context
  origin and risk-v2 score 80 are asserted. This is not the full forged-policy/legacy-reader matrix.
- C07: missing/reordered/cross-run/cross-trace/interleaved-noise cases add live/offline parity.
  An offline candidate cap of three accepts the positive chain; two fails explicitly. This uses
  a reduced cap, not a 10,000-candidate capacity or live-detector exhaustion demonstration.
- C09: direct investigation cannot invoke runtime adapters, leaves source bytes unchanged, and
  resolves incident/stage/timeline evidence identities and fingerprints. Decoded incident JSON
  and Markdown exclude the marker/canary. Forged/missing/cutoff cases remain separate.
- C10/C01: two direct-suite repetitions check 12 distinct children, six complete pairs, every
  metric numerator/denominator, impact-pair prevention 2/2, no failures/exclusions, and the
  unchanged core-suite fingerprint. Failure/exclusion and timing paths are not fully direct-specific.
- C11 and Phase 5 P5-02: a genuine manifest-loaded direct source/report reaches the API and DOM
  with exact metadata parity. A separate hostile SQLite source includes inert HTML/script/SVG,
  image/JavaScript URLs, Markdown and control characters. The browser checks text-only rendering,
  no injected nodes/script effects/navigation/popups/page errors, exact-loopback-origin requests,
  no raw prompt/marker/canary in the checked output/logs, and unchanged source hashes. A separate
  loader regression rejects a Unicode-escaped canary after SQLite JSON decoding. These are
  named cases, not a proof over every artifact kind or malicious encoding.
- C12 and Phase 5 P5-03: new dashboard tests assert actual manifest 64 KiB, entry 256, source 64,
  rule 64 KiB, report 1 MiB, response 1 MiB, query 2 KiB, page-size 200 ceilings and rejection above
  them. Aggregate input/event/projection tests use reduced caps; startup uses a simulated clock.
  Linux file/parent symlinks and an identity swap before open are rejected. Eight concurrent ASGI
  requests succeed, a ninth is rejected, and capacity recovers. This is not Windows reparse
  evidence, a full source-mutation matrix, or a large-ceiling memory/performance demonstration.

### Final commands and observed results

The commands below ran in the networkless namespace with cache/plugin autoload disabled;
coverage and optional browser plugins were explicitly enabled where needed.

```text
python -m ruff format --check --no-cache .
python -m ruff check --no-cache .
python -m mypy --no-incremental --cache-dir /tmp/mypy src tests
COVERAGE_FILE=/tmp/.coverage python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q
python -m pytest -p no:cacheprovider -p pytest_playwright.pytest_playwright -p pytest_base_url.plugin -o addopts= --strict-markers -m dashboard_e2e --browser chromium -q tests/e2e/test_dashboard.py
python -m build --no-isolation --outdir /tmp/dist
```

- Ruff: **100 files already formatted; lint passed**. Strict MyPy: **53 source files passed**.
- Final non-browser run: **213 passed, 4 browser tests deselected, 91.00% coverage in 25.62 s**
  (3,321 statements, 299 missed), above the enforced 90% gate. One upstream Starlette/httpx
  deprecation remains. The earlier fixture ResourceWarning was fixed by closing SQLite properly.
- Final Chromium run: **4 passed in 7.35 s**, no skips. This includes the new manifest-loaded
  hostile-content test, not just the earlier synthetic in-memory browser cases.
- Wheel and sdist built from a disposable `/tmp/build-source` copy. Both independently contained
  all eight Phase 6A resources and three dashboard assets. Wheel SHA-256:
  `7ccc84bca0110372023dbad2de2081b2891218ae177099ba868bc09d8fc1d434`; sdist SHA-256:
  `2463d8a8cd6200cb827436e2530515c50842224f5605f1a9de7f8ed408550003`.
- A fresh core-only `/tmp/smoke` environment installed this exact wheel offline from staged
  dependency wheels. Imports resolved to its site-packages, not `/work`; `PYTHONPATH` was unset.
  FastAPI was absent, version metadata was 0.4.0, and the dashboard returned exit 2 with its
  extra-install hint. Direct vulnerable/strict and indirect vulnerable CLI runs passed; direct
  and core suites each passed **6/6**. Installed comparison and investigation passed; investigation
  derived one alert/incident and left the source hash unchanged.
- `python -m pip_audit --progress-spinner off`, in a separate network-capable namespace with
  **no repository mount**, found **no known vulnerabilities** in staged Python dependencies after
  adding setuptools 84.0.0. This does not audit Chromium, Ubuntu library archives or project code.
- `git diff --check` passed; `git diff --exit-code -- src pyproject.toml` confirmed no product change.

### Execution boundary and failed attempts

Runtime isolation remained WSL2 Ubuntu 26.04 bubblewrap `--unshare-all`, cleared environment,
read-only `/work` and `/sandbox`, tmpfs output, no general host home/drive mount and no external
network. Non-browser tests used CPU 90 s, virtual address space 1 GiB/process, 128 processes,
256 file descriptors, 64 MiB/file and wall deadline 180 s. Chromium used CPU 180 s, 512 file
descriptors, 64 MiB/file and wall deadline 240 s, without per-process memory/process-count caps;
the WSL VM memory ceiling (about 7.4 GiB observed) and 4 GiB swap remain the memory bounds.
Playwright/Chromium headless shell versions were 1.63.0/153.0.8010.12. Additional staged browser
libraries were extracted into the task environment, not installed on the host.

The first offline uv installation exhausted the 1 GiB virtual-address limit after package builds
passed. Its retry used a 4 GiB installer virtual-address limit and one installation thread;
scenario/CLI Python retained the 1 GiB limit. A smoke command initially assumed a nonexistent
`--version` option; it was corrected to read installed package metadata. Initial new-test failures
were fixture issues (error matcher and an attempted update of an append-only event store); the
fixtures were corrected without changing product code or weakening the boundary assertions.

Only package/CLI smoke runs additionally exposed a dedicated task-owned `/results` mount writable;
the repository remained read-only. Retained artifacts are in
`/home/godji/agentsec-g0-env.045vOJ/results` inside Ubuntu; all other test/build working output was
temporary. No real credentials were used; attack inputs and canaries remain synthetic and inert.

### G0 disposition after this batch

This materially extends local evidence but does **not** close G0 or Phase 5/6A acceptance.
Remaining technical work includes full artifact-kind/encoded/error/log redaction coverage,
direct host-file/path spies and forced adapter/store/report failures/cleanup, forged context and
legacy risk readers, wrong path/source correlation negatives, direct investigation forged/missing/
cutoff cases, full suite failure/exclusion/timing cases, and the full dashboard mutation/resource
matrix. Windows junction/reparse checks, manual keyboard/narrow-width/real 200% zoom/focus/contrast
review, and human-dispatched Windows/Ubuntu verification plus Chromium CI on one final reviewed
commit are also outstanding. Final owner security/acceptance review and any itemized deferrals
must be recorded separately. No commit, push, PR, merge, release or CI dispatch occurred in this batch.

## Further G0 failure/policy checks and C07 finding, 2026-10-01

After the owner approved careful continuation, two test-only modules were added. The final full
non-browser run returned **272 passed, eight failed, four browser tests deselected in 20.80 s**,
with **91.33% coverage** and the 90% threshold enforced. All **59** new failure/host-I/O/policy
checks passed. The eight failures demonstrate both engines accepting a wrong recorded read
resource and altered component labels; the wrong-path negative is an explicit C07 acceptance gap.
Exact component-provenance requirements and rule-version compatibility need review. No tests
were skipped, xfailed or weakened to hide this result; pytest exited 1.

The tested manifest SHA-256 is
`8da375580cc49b907b296bdf29f31de16f05e5e83af2d59aef62658f8f1699c6` over 82 paths, using the
same LF path/hash convention above, against unchanged base `9649fc5fe0e580e7f736c7e6247e731e98521310`.
Ruff format/lint passed (102 files), strict MyPy passed (55 source files), and diff checks passed.
No product source, packaged resource, dependency or CI change was made. Runtime stayed inside
the same bounded networkless sandbox; Windows was used only for static formatting/linting.
Package/browser/audit results above were not rerun and are not a passing final-snapshot gate.

[C07 review record](PHASE_G0_C07_REVIEW.md) contains the exact command/results/hashes, cause,
synthetic-only impact, named passing cases, their limitations and a bounded proposed repair.
The workflow stops before executing a product repair or starting Phase 6B. The next owner action
is to authorize preparing that targeted repair for review and resolve its provenance/version
contract; the prior test approval does not silently authorize it. G0 remains open and the latest
verification gate is **failed**, not merely pending CI or manual acceptance.

## Prepared C07 repair — static checks only, 2026-10-01

The owner requested proceeding without their review. A targeted direct detector/rule/fixture
repair and sixteen regression cases were prepared; mandatory concrete-diff human review was
not bypassed. No changed runtime, pytest, browser, build or installed CLI command ran. Draft
predicates require canonical components and the exact virtual secret path; historical indirect
behavior and gateway/policy/risk/adapter/hash/dependency/CI sources are unchanged. Rule version
1 is a provisional bug-fix compatibility proposal requiring review, with stricter imported-evidence
matching and changed rule fingerprint disclosed in [C07 review](PHASE_G0_C07_REVIEW.md).

Prepared manifest: **82 paths**, SHA-256
`5f6b1d077ba0a3cd589be0554e58556adfb4eebbb78f0c86bdf7d32940f4c446`.
Ruff format/lint, isolated strict MyPy (55 files), PowerShell JSON structure and diff checks passed.
Windows MyPy first returned an internal error; the isolated static retry passed. Earlier
test results/hashes belong to earlier snapshots, not this repair. No publication/CI dispatch or
Phase 6B implementation occurred. Changed-runtime verification and G0 acceptance remain pending.

## Owner-reviewed C07 sandbox verification — 2026-10-01

The owner explicitly confirmed review and approved the concrete repair after receiving the G2
location and C07 review link. The prepared manifest was recomputed unchanged before execution.
The approval covers the canonical resource/component predicates and the disclosed version-1
correction; CONTRACTS and ADR-009 now record that compatibility decision. It is not full-phase
acceptance or permission to publish, dispatch CI or start Phase 6B runtime implementation.

Base HEAD remains `9649fc5fe0e580e7f736c7e6247e731e98521310`; changes are uncommitted.
The first focused run passed **16 tests in 3.68 s** on the approved prepared manifest.
The first full run returned **287 passed, one failed, four deselected, 91.36% coverage in 22.87 s**:
the only failure was the full ruleset golden fingerprint, which necessarily changed with the
approved predicate correction. The golden value was updated, leaving the separate legacy-rules,
snapshot and core-suite vectors unchanged. No product code or sensitive behavior changed after
approval. Ruff then caught mixed line endings from that edit; formatting normalized the test
file before the final rerun. Neither failure is counted as passing evidence.

Final source/test manifest: **82 paths**, SHA-256
`9202764ddf721b0257c3954e8802ede26aaca3aeb2c5b40a2b8414c9c55bc489`.
Manifest convention is sorted unique tracked/non-ignored untracked `src`, `tests` and
`pyproject.toml` paths, each `path + space + lowercase content SHA-256`, LF-separated without
trailing LF, then SHA-256 of UTF-8 bytes. Only the fingerprint-vector test differs from the
approved prepared source/test manifest; its SHA-256 is
`a4bf074c5d875b204563d9f08d7da744e0e991afb5b96b9eb605d4f290805f37`.

### Final commands and observed results

```text
python -m pytest -p no:cacheprovider -q tests/test_phase6a_g0_correlation_review.py --tb=short
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --no-incremental --cache-dir /tmp/mypy src tests
COVERAGE_FILE=/tmp/.coverage python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
python -m pytest -p no:cacheprovider -p pytest_playwright.pytest_playwright -p pytest_base_url.plugin -o addopts= --strict-markers -m dashboard_e2e --browser chromium -q tests/e2e/test_dashboard.py
python -m build --no-isolation --outdir /results/c07-20261001/dist
```

- Ruff format/lint passed; strict MyPy passed for **55 source files**.
- Final non-browser suite: **288 passed, four browser tests deselected in 21.43 s**,
  **91.36% coverage** (3,322 statements, 287 missed). One upstream Starlette/httpx deprecation
  warning remains. All sixteen C07 cases and 59 failure/policy cases are included and passed.
- Chromium: **four passed in 6.05 s**, no skips, including genuine manifest-loaded direct
  evidence, hostile inert text, browser request guards, redaction and unchanged source hashes.
- Offline wheel/sdist build used a disposable `/tmp/build-source` copy of `src`, `pyproject.toml`
  and `README.md`. Archive checks verified all eight Phase 6A resources byte-for-byte against
  the checkout and all three dashboard assets in each archive.
  Wheel SHA-256: `e261a885fe0295a58cb99447c753acd85b5af5138af4ac3981d9d91d841b1bfc`;
  sdist SHA-256: `31ce22230f54b9e56582d695802ac24887326d25d39f606f9f120ec739fa33d9`.
- A fresh core-only environment installed that wheel offline from staged dependency wheels.
  From `/tmp`, with **no repository mount or PYTHONPATH**, imports resolved to
  `/results/c07-20261001/smoke/lib/python3.13/site-packages`, metadata version was 0.4.0 and
  FastAPI was absent. Installed CLI checks passed: direct vulnerable simulated impact/detection,
  direct strict prevention, indirect vulnerable compatibility, direct comparison, both suites
  **6/6**, rule fixtures **4/4**, replay **one match**, investigation **one alert/one incident**,
  and missing-dashboard-extra fixed hint/exit 2. Investigation left source bytes unchanged.
- New logical ruleset fingerprint:
  `a8289edfc931edd0e43ddafd069345b1e82be949c08d4c83b8aeb01e7c8f4133`;
  old value `5e876f4f814e4674f3f1859bc667bd469b972023b0785585268b63cf274179e5`.
  The legacy-only rule fingerprint remains
  `5b15e8bec52b1520975af8701de6e87801251ab64e85165c79d6b5f723d36be8`.
  Identity/version preservation does not imply unchanged predicates or imported-evidence results.
- No dependencies changed or downloaded. The earlier staged Python dependency audit remains
  historical evidence; it was not rerun and does not audit Chromium, OS libraries or product code.

### Isolation and remaining gates

WSL2 Ubuntu 26.04, CPython 3.13.15; bubblewrap `--unshare-all`, cleared environment,
read-only task runtime/repository, no general host-home/drive mount, tmpfs working output.
Focused checks used CPU 90 s/wall 180 s; final combined quality/regression checks used CPU
120 s/wall 240 s. Both retained 1 GiB virtual-address, 128-process, 256-descriptor and
64 MiB/file limits. Browser checks retained CPU 180 s/wall 240 s, 512 descriptors and
64 MiB/file; Chromium's incompatible per-process address/process caps remained omitted,
with the existing WSL memory/swap ceiling instead. Build/installer used 4 GiB address,
CPU 120 s/wall 240 s; installed scenario/CLI checks returned to 1 GiB, CPU 90 s/wall 180 s.
Only build/package/CLI exposed task-owned results writable. Retained archives and CLI artifacts
are under Ubuntu `/home/godji/agentsec-g0-env.045vOJ/results/c07-20261001`; other test output
was disposable. Windows ran only static formatting/read-only checks, never scenarios/tests.

The demonstrated C07 wrong/missing-path and component-label defect is repaired, not deferred.
Broader correlation enumeration/resource-limit parity, other residual redaction/incident/
evaluation/dashboard cases, manual accessibility, Windows junction/reparse checks, exact-reviewed-
commit Windows/Ubuntu CI and final full-diff acceptance remain open. These passing checks do not
close G0/G3/G4 or freeze Phase 6B G1. No commit, push, PR, merge, CI dispatch or release occurred.

### Commit and push authorization

After reviewing the results, the owner approved committing and pushing this verified G0/C07
batch on 2026-10-01. Local Phase 6B planning and agent-workflow edits are excluded. CI dispatch,
PR creation, merge and phase acceptance remain separate steps.

## G0 direct evidence continuation — 2026-10-02

PR #8 merged as `0c3f151177d94b97c12548a5410b840afb1a4c22`; the owner asked to continue.
Work uses the existing isolated worktree on `codex/g0-evidence-completion` at that merge.
No Actions run was found for either the PR head or merge during the read-only GitHub check.
The primary checkout's Phase 6B planning and agent-workflow edits remain separate and untouched.

`tests/test_direct_evidence_boundaries.py` adds direct-specific incident/evaluation checks.
On the test-only snapshot, focused execution returned **34 passed, four failed in 7.20 s**;
the full non-browser suite returned **322 passed, four failed, four browser tests deselected in
31.06 s**, **91.66% coverage** (3,322 statements, 277 missed). Coverage passed but pytest exited
1: this is not a green acceptance gate. Ruff format/lint and strict MyPy (56 source files) passed.
One upstream Starlette/httpx deprecation warning remains. Product/resources/CI were unchanged.

Passing additions cover missing/wrong incident references, nested-alert and timeline alterations,
early cutoffs, failed/incomplete direct lifecycles, exact snapshot/reference cutoffs, seven invalid
historical-link/clock cases, local versus global evaluation failures, skipped-child accounting,
metric exclusions/zero denominators/incomplete pairs, synthetic exception redaction, assertion
failure exit 2 without exclusion, and the actual 300-second deadline at/over boundary. The latter
uses a cooperative fake clock, not a wall-time or preemptive-timeout claim.

The four failures are two defects under both profiles:

- A genuine direct investigation cannot load in the dashboard. Its strict timeline metadata has
  `event_type: agent.context.prompt_added` but no event payload; the recursive prompt validator
  wrongly requires the full prompt payload there. The positive fails before any tampering.
- The linked-investigation verification helper accepts a cutoff one sequence beyond the source's
  final event. It fingerprints the filtered captured snapshot but never checks the declared cutoff
  equals that snapshot's actual final sequence. This was isolated below the failing projection;
  it is not a claim that the full public loader accepted the artifact.

The first test layout hit the same positive-load defect in eighteen parameter cases (18 failed,
18 passed in 9.00 s). The public positive was separated into two explicit tests and linkage checks
were isolated against the genuine captured source; no failure was skipped or marked xfail.

Executed test-only manifest: **83 paths**, SHA-256
`68fb0365261b92e0bd2a4e8523bced33f4949ff16b10ccae7edd818b0a6c8170`;
test module SHA-256 `7903e112e3ef83cf804cf1484397b27905029fa43dc40517e3c06bdb4e3628ab`.
Use the manifest convention defined in the preceding C07 section.

Commands inside the same networkless WSL2 bubblewrap boundary:

```text
python -m pytest -p no:cacheprovider -q tests/test_direct_evidence_boundaries.py --tb=line
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --no-incremental --cache-dir /tmp/mypy src tests
COVERAGE_FILE=/tmp/.coverage python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=line
```

Cleared environment, read-only task/repository mounts, no host home/drive or external network,
tmpfs output, 1 GiB address limit, 128 processes, 256 descriptors, 64 MiB/file. Focused checks
used CPU 90 s/wall 180 s; the combined quality/full check used CPU 120 s/wall 240 s. No host
scenario execution, new dependencies, browser/build/audit rerun, CI dispatch or publication.

### Prepared dashboard repair — not runtime-tested

The minimal diff permits a no-payload prompt timeline entry only after strict `TimelineEntry`
validation; actual event payloads keep the existing exact closed prompt-field checks. Linked
investigations also require the declared cutoff to resolve to the captured snapshot's last
sequence. Five additional malformed-shape/payload regressions are prepared, bringing the module
to **43 cases**, all unexecuted on this changed product snapshot. See the concrete
[G2 review](PHASE_6_SECURITY_REVIEW.md#g0-dashboard-repair-review--2026-10-02).

Prepared manifest: **83 paths**, SHA-256
`8342ed5f7ca6c13038f2073f2565cad5a8930bf7a4f9952c692a866789ac9866`;
catalog SHA-256 `762f31cf5e4e868538080ac6ed0746459346d91e5df9359a70c57c9657716722`;
test module SHA-256 `8950c584779f261971f8d5ef22b01b0e7600c5c03d78ed50b5793be5ac3e93df`.
Only static formatting/lint/types and diff checks apply to this new snapshot. Earlier runtime
results do not establish its correctness. New G2 review is required before executing it.
Other G0 cases, manual accessibility, cross-platform CI and Phase 6B G1 remain open; nothing
was committed or pushed in this continuation.

## Approved dashboard repair verification — 2026-10-02

The owner approved the concrete dashboard review and named sandbox checks. Before execution,
the prepared source/test manifest was recomputed unchanged:
`8342ed5f7ca6c13038f2073f2565cad5a8930bf7a4f9952c692a866789ac9866` (**83 paths**).
Base is `0c3f151177d94b97c12548a5410b840afb1a4c22`; changes remain uncommitted on
`codex/g0-evidence-completion`. No product or test edits were needed during this rerun.

Results on that exact snapshot:

- New 43-case module plus existing dashboard catalog/API tests: **71 passed in 8.26 s**.
- Full non-browser suite: **331 passed, four browser tests deselected in 31.29 s**,
  **91.65% coverage** (3,329 statements, 278 missed). The four pre-repair failures are resolved.
- Existing Chromium suite: **four passed in 6.02 s**, no skips.
- Ruff format/lint passed; strict MyPy passed for **56 source files**. One upstream
  Starlette/httpx deprecation warning remains.
- Offline wheel/sdist build passed from a disposable copy of `src`, `tests`, README and
  pyproject. Both archives contain all eight Phase 6A resources, three dashboard assets and
  the repaired catalog; changed catalog/resource bytes match the checkout. The sdist includes
  the new regression module. Wheel SHA-256:
  `45cf8c71ddf85f1cdee2bff93a616dcc14054981fd4f4a9dcddb912b5b7038ce`;
  sdist SHA-256: `ac3fcfb3054f9200dd052f43efb71df28f32a29e9ddca5984696bf5bc1608de7`.
- The exact wheel installed offline to a fresh core-only environment; FastAPI was absent and
  package metadata was 0.4.0. With **no repository mount or PYTHONPATH**, installed direct
  vulnerable/strict CLI runs and investigations passed. The installed catalog accepted each
  genuine linked investigation, rejected its altered late cutoff, and preserved source hashes.
  Indirect compatibility, comparison, both **6/6** suites, rule fixtures **4/4**, replay and
  missing-dashboard-extra hint/exit 2 also passed. The ruleset fingerprint is unchanged.

Commands reuse the previous section's quality/full suite and the existing Chromium command.
Focused command was:

```text
python -m pytest -p no:cacheprovider -q tests/test_direct_evidence_boundaries.py tests/test_dashboard_catalog.py tests/test_dashboard_api.py --tb=short
python -m build --no-isolation --outdir /results/dashboard-20261002/dist
```

Isolation stayed networkless bubblewrap with cleared environment, read-only repository/task
runtime and tmpfs working output. Focused/CLI checks retained CPU 90 s, wall 180 s, 1 GiB address,
128 processes, 256 descriptors and 64 MiB/file; combined static/full checks used CPU 120 s/wall
240 s. Browser bounds stayed CPU 180 s/wall 240 s, 512 descriptors and 64 MiB/file, with the
existing WSL memory/swap limits instead of Chromium-incompatible per-process address/count caps.
Build/install used a 4 GiB address limit, CPU 120 s/wall 240 s and one installer thread. Only
build/install/CLI exposed task-owned results writable. Retained archives and synthetic CLI
artifacts are under Ubuntu `/home/godji/agentsec-g0-env.045vOJ/results/dashboard-20261002`.
No host scenario execution or new dependency/download occurred. The earlier Python dependency
audit remains historical; it was not repeated and does not audit Chromium, OS libraries or code.

The two demonstrated defects are fixed, not deferred. Passing evidence does not close broader
redaction/resource/incident/evaluation matrices, correlation enumeration parity, manual
accessibility, Windows junction/reparse checks, exact-commit Windows/Ubuntu CI or final acceptance.
No CI dispatch, commit, push, PR, merge or Phase 6B implementation occurred in this rerun.

## Continued artifact and aggregate-limit evidence — 2026-10-02

The owner authorized committing/pushing the reviewed repair and continuing the workflow with
a sub-agent reviewer. The repair was committed and pushed as
`df084a0203042b9494e6140e5fe456e5a8decfa6` (`Fix dashboard investigation validation`) on
`codex/g0-evidence-completion`. The independent read-only review found no actionable blocker;
it supplements the preceding concrete owner G2 approval, not a replacement human sign-off.
An attempted draft PR creation returned GitHub integration HTTP 403; no PR was created.

The next batch changes tests and evidence documentation only. Product source, resources,
dependency contracts and CI configuration remain identical to the approved repair. It adds:

- Fourteen public-loader/CLI checks: seven genuine JSON artifact kinds, each contaminated in
  one permitted string field using either literal or JSON-Unicode-escaped synthetic canary.
  Every case first loads the genuine artifact, independently validates the contaminated schema,
  proves JSON decoding reveals the canary, and requires rejection without listener startup,
  output disclosure or input mutation. These are representative fields/encodings, not an
  all-field or arbitrary-secret scan. The contaminated fixtures intentionally contain a fake
  canary in task-local temporary files; no real credential is used.
- Six supported API detail routes each pass a clean 200 control before returning fixed 503 for
  a contaminated in-memory artifact. Captured output/logs and response/security headers are
  checked. A separate replay detail-route 404 is route-contract evidence, not an API redaction
  scan; replay is covered by the public-loader/CLI matrix.
- Eighteen additional investigation cases exercise the public loader alongside independent
  linkage-helper checks, with a genuine public positive before each mutation under both direct
  profiles. The direct evidence module now has 61 cases.
- Three actual dashboard aggregate-bound checks without patching constants: 256 MiB selected
  input, 100,000 retained events, and 64 MiB retained projections. Repeated selected paths/run
  identities exercise per-entry accounting, not that many distinct physical files, unique events
  or runs. Input uses one 64 MiB padded canonical SQLite source plus 192 one-MiB JSON entries;
  events use ten selections of one 10,000-event source; projections use 64 selections of one
  schema-valid one-MiB report. Extra valid entries trigger each specific limit. Event overflow is
  exactly one event; byte/projection overflow is an extra valid small report, not one byte.
  Source bytes/hashes and selected report bytes remain unchanged after accepted/rejected loads.

The reviewer suggested clean API controls, separating replay 404 evidence, and source hash
checks; those improvements were applied before the final rerun. Initial static checks caught
four import/list lint issues and two test-only type errors in the new cap tests; they were fixed
before runtime execution of those tests. No product repair was needed.

Final source/test manifest: **84 paths**, SHA-256
`7a07a8a978cf9431a06c0949ddaa4c0ab8f46858ddb5e74c92a8d6c3f074c2f1`.
Results on this snapshot:

- Ruff format/lint passed; strict MyPy passed for 57 source files.
- Focused three-module batch: **102 passed in 17.55 s**.
- Full non-browser suite: **373 passed, four browser tests deselected in 40.01 s**,
  **91.95% coverage** (3,329 statements, 268 missed). One upstream Starlette/httpx warning remains.
- Unchanged Chromium suite: **four passed in 5.83 s**, no skips.
- Offline wheel/sdist build passed. Every packaged source/resource byte matches the checkout;
  sdist includes all three changed regression modules. Wheel SHA-256:
  `a5d02b001634648d62853fdd2cd78ce6cbbb1f5096a8fa0bf02fa5717d39fcf4`;
  sdist SHA-256: `ae6b2dc8cd336f51328f1ba6bbe33023059cf88ed8061f259a28450d6e637860`.
- The exact wheel installed offline into a fresh core-only environment (FastAPI absent,
  metadata 0.4.0). With no repository mount/PYTHONPATH, both direct profile CLI flows,
  investigations and replay passed; genuine linked investigations load, late cutoffs reject,
  and source hashes remain unchanged. Indirect compatibility, comparison, both 6/6 suites,
  rule fixtures 4/4, missing-dashboard hint/exit 2 and unchanged ruleset fingerprint passed.

Focused command:

```text
python -m pytest -p no:cacheprovider -q tests/test_dashboard_artifact_redaction.py tests/test_direct_evidence_boundaries.py tests/test_dashboard_g0_boundaries.py --tb=short
```

Quality/coverage, Chromium and installed smoke reuse the commands and isolation in the preceding
section. All runtime execution stayed in networkless bubblewrap; no host scenario ran. Combined
checks used CPU 120 s, wall 240 s, 1 GiB address limit, 128 processes, 256 descriptors and
64 MiB/file; Chromium retained its existing WSL memory/swap and CPU/wall/descriptor bounds.
Build/install retained the 4 GiB address bound and existing staged dependency wheels only.
Archives, core environment and synthetic CLI results are retained under Ubuntu
`/home/godji/agentsec-g0-env.045vOJ/results/g0-artifact-20261002`.
No downloads, dependency changes, audit rerun, CI dispatch, merge or Phase 6B runtime change.

This closes the demonstrated representative artifact and actual aggregate-accounting cases,
not the complete G0 inventory. Broader hostile-content/field/failure/mutation and resource-work
matrices, Windows reparse tests, manual accessibility, human-dispatched exact-commit CI and final
owner acceptance remain separate open gates. Delegated review does not waive those gates.

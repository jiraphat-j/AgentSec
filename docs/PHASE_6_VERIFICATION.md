# Phase 6A verification record

Status: **Actions run 37628097651 passed all four Windows/Ubuntu verification and browser jobs on
full SHA `6aa9735ad273d9c2b93ee6943df8bdb814a1a7f2` (PR #10, open) on 2026-10-07.
All 22 public response-byte cases passed on both platforms; Windows reparse cases remain passing.
The twelve reproduced live/offline discrepancies are repaired; earlier failures and CI-pending
statements are historical. Itemized G0 disposition, unusual cmd metacharacter temp-root residual,
remaining boundary evidence, manual accessibility, Phase 6B G1 and final owner review remain open.**

Latest local update (2026-10-10): the owner approved the concrete HEAD routing repair for
networkless sandbox execution. All 45 focused cases and 535 full nonbrowser tests pass;
coverage is 92.13%. Final formatting, lint and strict MyPy pass. The original HEAD failure is
fixed on this tested snapshot. New-head CI, Host-port wording and remaining G0 gates
remain open; earlier green CI does not cover this batch.

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

## Later C07 parity reproduction — unresolved, 2026-10-02

The verified dashboard batch was pushed as `df084a0203042b9494e6140e5fe456e5a8decfa6`; the
verified test-only artifact/bounds batch as `eec09e9e0bf5dd3dcb29f5ad567269190cd010e1` on
`codex/g0-evidence-completion`. An independent sub-agent reviewed both with no blockers.

Continuing the remaining C07 matrix against unchanged product code confirmed twelve failures:
eight earlier nonmatching candidates hide a later valid direct chain, absent read/sink digests
produce a live false match, and three unsupported-version variants match live but not offline.
The [dated C07 review](PHASE_G0_C07_REVIEW.md#additional-liveoffline-parity-findings--2026-10-02)
records exact assumptions, impact limits, reproduction commands and the next repair proposal.
These are evidence-interpretation discrepancies, not demonstrated host access or secret leakage.

Focused eighteen-case module: **six passed, twelve failed in 3.84 s**. Full: **379 passed,
twelve failed, four browser tests deselected in 42.76 s**, **91.98% coverage**; exit 1.
Format/lint/types passed (58 files). Six passing additions cover offline missing-join rejection,
exact/reversed two-chain enumeration, actual candidate ceiling/overflow and disclosed reduced
match ceiling/overflow. The current failed acceptance snapshot has **85 paths**, SHA-256
`1c09b53a70b77ee7d5aebe302c9e50a08b0735469da104249a0238275af43c08`.

Execution retained the preceding networkless CPU/wall/memory/process/file bounds. No new product,
resource, dependency or CI change was made. Package/browser checks were not rerun for this
failing expanded matrix and remain evidence for the earlier passing snapshot. The new reproduction
module and finding records are uncommitted and not pushed; there is no PR, merge or CI dispatch.
Prepare a targeted direct-only repair for concrete human G2 review before any changed sensitive
execution. The skill/workflow human-review gate is not replaced by delegated review or blanket
continuation approval. G0 and Phase 6B implementation remain open.

### Review-only repair proposal after blocked preparation

On the owner's continuation request, auto-review rejected applying the new detector/resource
loading patch without concrete human G2 approval. Read-only Git checks confirmed both source
files are unchanged. A documentation-only code proposal and named sandbox verification plan
are prepared in the existing [C07 record](PHASE_G0_C07_REVIEW.md#concrete-repair-proposal-for-g2--review-only-2026-10-02).
No new test, scenario, browser, build or installed CLI ran; the 85-path failed reproduction
manifest and its 379 passed/twelve failed results above remain current. Proposal review is not
implementation verification; no source manifest for an applied repair exists yet.

## Approved C07 live/offline repair — 2026-10-03

The owner explicitly approved the concrete proposal and named sandbox checks after reading the
review request. The applied detector/resource-loader diff matches that proposal; independent
read-only review found no blockers after strengthening schema-valid canary negatives and live
limit-boundary parity. Delegated review remains supplemental to that human G2 approval.

Base HEAD: `eec09e9e0bf5dd3dcb29f5ad567269190cd010e1`. Tested source/test manifest: **86 paths**,
SHA-256 `af80952ae4f8f5ebbaceaf7290cfb3698ab87d407ac88a2734f5d327fec03eb1`, using the existing
sorted path/content convention. This is local uncommitted-snapshot evidence, not exact-commit CI.

Fresh direct evaluation now uses the fixed bounded packaged rule, completes enumeration before
selecting the first dedup-key match, rejects absent join digests/unsupported versions and fails
explicitly on input/work exhaustion. Closed configuration/resource failures do not fall back.
Recorded-result reuse and missing alert/incident recovery still bypass fresh checks; tests and
contracts disclose that distinction. Indirect first-candidate behavior, rule bytes/version,
fingerprint algorithms, policy/gateway/adapters, dependencies and CI remain unchanged.

Final checks inside the existing networkless WSL2 Ubuntu/CPython 3.13.15 sandbox:

- Ruff format/check and strict MyPy: passed, **59 files**.
- Focused loading/parity/original C07/historical detection modules: **84 passed in 9.41 s**.
- Full non-browser suite: **429 passed, four browser tests deselected in 47.67 s**;
  **92.04% coverage**, 3,356 statements/267 missed. One upstream Starlette/httpx warning remains.
- Existing Chromium suite: **four passed in 6.03 s**, no skips.
- Offline wheel/sdist build: passed. Every packaged source/resource byte matches the checkout;
  sdist contains both new direct regression modules byte-for-byte.
- Fresh offline core-only wheel install, no repository mount/PYTHONPATH and FastAPI absent:
  all three direct fixtures under both profiles, direct/indirect CLI under both profiles,
  comparisons, replay, investigation, linked catalog positives/late-cutoff negatives,
  source database hash preservation, both suites (6/6 children), all four rules and
  missing-dashboard dependency hint passed. No dashboard listener was started by this smoke.

Commands reuse the concrete proposal's quality/focused/coverage/Chromium commands, adding
`tests/test_direct_rule_loading.py` to the focused list. Build/install smoke used task-owned
`g2_verify.py` (SHA-256 `d1c54d6261190ab20091c094b2971f8b8d00f945a581e3367b6f4e8b7359e3c8`):
`python /checks.py build`, then fresh installed `python /checks.py smoke`. Build uses disposable
tmpfs copies of source/tests/package metadata, not a writable checkout. Archives/core install/CLI
artifacts are retained under Ubuntu
`/home/godji/agentsec-g0-env.045vOJ/results/c07-repair-20261003-final`.

- Wheel SHA-256: `52763975518430dca0dbbcd351777ab149bf6e5ca1a091902ff6382591a94692`.
- Sdist SHA-256: `ec8979aff7929ef7c226d05a2da162bfcc70a6bb0b741535647fe2e33f5b5a72`.

All runtime checks used bubblewrap `--unshare-all`, cleared environment, read-only source and
tmpfs. Static/full: CPU 120 s/wall 240 s/address 1 GiB/processes 128/descriptors 256/64 MiB per
file; browser: CPU 180 s/wall 240 s/descriptors 512/64 MiB per file and existing WSL memory/swap
bounds. Build/install: address 4 GiB/CPU 120 s/wall 240 s; installed smoke: address 1 GiB/CPU 90 s/
wall 180 s, otherwise the same process/descriptor/file bounds. Only task results were writable
for build/install/smoke. No host scenarios/tests, downloads, dependency changes, audit rerun,
CI dispatch, merge, release or Phase 6B runtime occurred. Static formatting briefly used a
writable checkout mount, targeting only edited Python files; it did not run project code.

This closes the twelve demonstrated discrepancies and the named repair checks, not complete G0.
Broader hostile-content/field/failure/mutation/resource-work matrices, Windows junction/reparse
checks, manual accessibility, human-dispatched exact-reviewed-commit CI and final owner full-diff
acceptance remain open. Historical 379/twelve-failed results above are superseded, not erased.

## Post-merge G0 capture-boundary batch — 2026-10-03

The owner reported merging PR #9 and asked to continue. GitHub confirmed merge
`c165b3d203998585193711e67895e64bf4321258`; fetched `origin/main` matched. The existing clean
managed worktree was reused on `codex/g0-dashboard-evidence`, preserving unrelated primary
checkout edits. Public Actions queries for reviewed head `507e1fd585bc11040ab7df1af41795eb4e63d555`
and merge returned zero runs. Neither merge nor local results establishes exact-commit CI.

The next batch adds only `tests/test_dashboard_capture_boundaries.py` plus evidence records.
Production source/resources, browser tests, dependencies and CI remain byte-for-byte unchanged
from that merge. The [Phase 5 record](PHASE_5_VERIFICATION.md#capture-boundary-continuation-after-pr-9--2026-10-03)
maps the seventeen public-loader/descriptor/SQLite-cleanup/snapshot cases and explicit limits.
This is continued G0 evidence completion under the existing sandbox-only authorization, not
Phase 6B G1/G2 approval or a new sensitive runtime repair.

Final source/test manifest: **87 paths**, SHA-256
`3a261dfb7f7472cb271867f872542d0bbddb30fb2c1df0249ba159f10547e983`.
New module SHA-256: `aebc5e74b552e5d148bc7e789455f35e70c23d7d426ab7293fdf76a6b572bad8`.
Use the existing sorted path/content manifest convention; this is local snapshot evidence.

The new focused command is:

```text
python -m pytest -p no:cacheprovider -q tests/test_dashboard_capture_boundaries.py --tb=short
```

Quality/full regression reuse the preceding section's commands. All execution remains inside
the cleared-environment networkless WSL2 bubblewrap sandbox, read-only checkout/tmpfs outputs:
CPU 120 s/wall 240 s/address 1 GiB/processes 128/descriptors 256/64 MiB per file. Static formatting
targeted only the new module through a temporary writable mount; no product code ran in that
step. No host tests/scenarios, downloads, dependency changes, audit, listener/browser/build/
installed rerun, CI dispatch, merge or Phase 6B runtime occurred in this continuation. Earlier
package/four-browser results remain historical evidence for the merged product snapshot; they
do not demonstrate inclusion of this new test module in a fresh sdist.

Final results on that 87-path snapshot: **17 focused passed in 2.78 s**, **446 non-browser
passed, four browser tests deselected in 60.98 s**, **92.13% coverage** (3,356 statements/264
missed). Ruff format/lint and strict MyPy passed (60 files). One upstream Starlette/httpx warning
remains. Initial strict typing identified two imported-alias accesses in the new test module;
explicit imports resolved them before the final run. Independent review requested timestamp-
isolated inode controls and Unix-only open-file annotations; both were added, and final review
reported no blockers. No production defect or sensitive source change was found in this batch.

Broader G0 hostile/field/error/resource/concurrency cases, Windows reparse evidence, manual
accessibility, human-dispatched exact-reviewed-commit CI and final owner acceptance remain open.

## Windows CI test fixes — 2026-10-03

The owner approved applying and pushing these fixes on `codex/g0-dashboard-evidence`, the
existing PR #10 branch. Human-dispatched [Actions run 37096511551](https://github.com/jiraphat-j/AgentSec/actions/runs/37096511551)
tested `70e36c69d5557fe38710e112c3e74cd4b91680c3`: Ubuntu verification and both Chromium jobs
passed; Windows verification failed with **1 failed, 436 passed, 7 skipped, 4 deselected,
4 errors and one warning**. Windows build/audit were skipped after the test failure.

Two oversized resource cases generated byte-filled pytest IDs exceeding Windows' 32,767-character
environment-value limit. Their setup and teardown raised while assigning `PYTEST_CURRENT_TEST`,
before the rejection assertions could run. Both resource decorators now use `invalid-utf8` and
`oversized` IDs; payloads and assertions are unchanged. The linked direct-investigation positive
also exceeded the real five-second scenario deadline. Its evidence-fixture helper now injects a
fixed monotonic clock through the existing runner API. Production clocks and limits are unchanged;
separate 5.0/5.001-second tests still check completion and safe deadline failure under both profiles.

Tested base: `70e36c69d5557fe38710e112c3e74cd4b91680c3`. Final source/test manifest: **87 paths**,
SHA-256 `339d27a794108795044867b0dc85f21341f8a7f2f588075d07d30567919bcd79`, using the existing
sorted path/content convention. This identifies the local snapshot, not a Windows CI result.

Commands inside the established sandbox:

```text
python -m pytest -p no:cacheprovider --collect-only -q tests/test_contracts_and_events.py -k rejects_invalid_or_oversized_text
python -m pytest -p no:cacheprovider -q tests/test_contracts_and_events.py tests/test_direct_evidence_boundaries.py tests/test_phase6a_g0_failures.py::test_direct_deadline_at_and_over_bound_has_safe_finalization --tb=short
python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --no-incremental --cache-dir /tmp/mypy src tests
```

All four resource node IDs collected with short labels. Focused checks: **83 passed in 9.39 s**.
Full non-browser: **446 passed, four browser tests deselected in 51.00 s**, **92.13% coverage**
(3,356 statements/264 missed), one upstream Starlette/httpx warning. Format/lint and strict MyPy
(60 files) passed. Initial format check found mixed line endings from the patch; Ruff normalized
only the edited test files before the full run. Supplemental read-only review found no blockers.

Runtime remained inside networkless WSL2 Ubuntu/CPython 3.13.15 bubblewrap with cleared environment,
read-only checkout and tmpfs outputs: CPU 120 s/wall 240 s/address 1 GiB/processes 128/descriptors
256/64 MiB per file. Formatting alone used a temporary writable mount without executing project
code. No host tests/scenarios, downloads, browser/build/install/audit rerun, CI dispatch, merge or
Phase 6B runtime occurred. Source, dependencies, CI and browser tests are unchanged. Windows repair
confirmation requires a fresh human-dispatched run on the pushed head. Other G0 gates remain open.

## Windows timing fixture follow-up — 2026-10-06

The owner's next human-dispatched [Actions run 37429535768](https://github.com/jiraphat-j/AgentSec/actions/runs/37429535768)
tested `51ad4bba22e2863dcb9be030ebf867c44f8a949f`. Ubuntu verification and both browser jobs
passed. Windows format/lint/type passed, then tests reported **3 failed, 436 passed, 7 skipped,
4 deselected, one warning**. Build/audit were skipped. The earlier oversized pytest IDs now ran
without environment-value errors.

The failed suite expectation test returned `status=partial`, `children=5/6`, and CLI exit 1 rather
than the expected completed assertion failure and exit 2. Two other fixture runs raised
`ScenarioDeadlineExceeded` before reaching their overwrite and historical timing assertions.
The three tests now inject a fixed monotonic clock through the existing runner/evaluation
dependency; the CLI test patches only its `EvaluationService` construction. Test payloads,
expectations and production limits are unchanged. Dedicated scenario and evaluation deadline
boundary tests still use controlled at/over-limit clocks.

Tested base: `51ad4bba22e2863dcb9be030ebf867c44f8a949f`. Local source/test manifest: **87 paths**,
SHA-256 `129ad6bec9eedde06c6e0eb323509cfed46f0d4c94d8e2a80b13e85907945684` under the sorted
path/content convention. In the established cleared-environment, networkless WSL2 Ubuntu/CPython
3.13.15 bubblewrap sandbox, the three repaired cases plus eight dedicated deadline cases passed
(**11 passed in 3.77 s**). The full non-browser suite passed **446 tests, four browser tests
deselected in 63.04 s**, with **92.13% coverage** (3,356 statements/264 missed) and the existing
Starlette/httpx warning. Ruff format/lint and strict MyPy passed for 60 files. Ruff normalized
the two edited files' line endings before the final check; that formatter did not execute code.

The focused command selected those three failing node IDs and these existing boundary cases:
`test_direct_deadline_at_and_over_bound_has_safe_finalization`,
`test_direct_suite_deadline_at_and_over_actual_bound`,
`test_deadline_failure_records_no_successful_report`, and
`test_evaluation_deadline_accounts_for_every_not_run_child`. Full/quality commands and sandbox
bounds match the preceding section. No host scenario execution, browser/build/install/audit rerun,
CI dispatch or merge occurred. Windows confirmation and the other G0 gates remain open.

## Green CI and prepared Windows reparse evidence — 2026-10-06

[Actions run 37431200546](https://github.com/jiraphat-j/AgentSec/actions/runs/37431200546)
tested `ba9b9f1307affb88c617fc36e1a6cf4a4fd2c160`. The Ubuntu and Windows `verify` jobs and
both `dashboard-browser` jobs completed successfully, including build/audit in both verify jobs.
PR #10 remains open. This confirms the previous timing-fixture fix on that head; it does not
retroactively validate earlier merged revisions or close the remaining G0 acceptance matrix.

The next batch prepares only `tests/test_dashboard_g0_boundaries.py` Windows cases and evidence
records. The positive case accepts a regular selected file. The negatives select a file symlink
and a parent junction to synthetic targets outside the manifest root but inside `tmp_path`;
they assert link/reparse rejection, unchanged target bytes and link-node cleanup. Junction setup
uses `subprocess.run` with fixed `cmd /d /c mklink /J` arguments, a ten-second bound, captured
output, and no `shell=True`. Setup failures remain failures rather than skips. Linux explicitly
skips these Windows-only cases. The [security review](PHASE_6_SECURITY_REVIEW.md#windows-reparse-test-proposal--2026-10-06)
contains the human gate for this new command invocation.

Prepared base HEAD: `ba9b9f1307affb88c617fc36e1a6cf4a4fd2c160`. The source/test manifest has
87 paths, SHA-256 `f627f25fde272337d920b33dd509d98ca848710a7b449062c70e9ff3724a999c` under the
same sorted path/content convention. Static preflight passed: Ruff format (60 files), Ruff lint,
strict MyPy (60 files), and `git diff --check`. The owner authorized the concrete test diff on
2026-10-06. In the isolated networkless Linux sandbox, the focused G0 boundary file passed
with 20 passed and 3 Windows-only skips. The full nonbrowser suite passed with 446 passed,
3 skips, 4 browser deselections, one upstream Starlette/httpx deprecation warning and 92.13%
coverage. Neither run invoked `cmd` or tested Windows reparse behavior. No new scenario,
browser, build, installed-package check or CI run has executed on this diff. The owner must
dispatch Actions on the new PR head; record all four job results before crediting Windows evidence.
Windows reparse, broader hostile/resource matrices, manual accessibility and final owner acceptance
remain open until that evidence is observed.

## Gemini high delegation trial — 2026-10-06

The owner requested a second `agy` trial to reduce Codex usage while retaining quality and
potentially improving turnaround. PR #10 was still open at
`4db44b7e8c203c7c9ce6d44d796570b75abf325c`; a read-only Actions query found no manual run on
that SHA at the time of this trial. This batch prepares documentation, not Phase 6B runtime.

The delegated task reviewed the three Windows catalog tests and drafted the remaining human
C11/C12 walkthrough from supplied dashboard HTML/CSS/JavaScript and test/resolver snippets.
The first call used `gemini-3.1-pro-high`, `--effort high`, `--mode plan`, `--sandbox`, JSON
output and a 180-second print timeout. The supplied bundle was 29,889 characters. Prompts
required advisory output only, with no additional file reads, editing, commands or tests.
No test execution was requested or reported by `agy`; the CLI's `--sandbox` flag was not used
as evidence of the repository's networkless WSL isolation.

| CLI report | Duration (s) | Input tokens | Output tokens | Thinking tokens | Total tokens |
|---|---:|---:|---:|---:|---:|
| Earlier Flash Low proposal, separate smaller task | 7.54 | 14,180 | 736 | Not recorded | 14,916 |
| Initial Pro High response, one turn | 155.49 | 24,284 | 20,439 | 18,874 | 44,723 |
| Resumed conversation after Flash High correction, two turns | 353.74 | 76,425 | 28,131 | 25,678 | 104,556 |

These are CLI-reported fields. The resumed response reports two conversation turns; do not add
its counters to the first response or treat its duration as an independently timed correction
call. Thinking tokens are shown separately as reported, not added to the total. A rejected
attempt to combine `gemini-3.1-pro-high` with medium effort reported zero tokens; the correction
used `gemini-3.8-flash-high` with high effort instead.

Codex checked the caller and UI source, rejected the unresolved-manifest-root finding (the
caller already resolves the manifest), and corrected the draft's reflow, state coverage,
labels, report-only behavior and C11/C12 classification. The Windows symlink privilege note
describes a setup limitation; setup failures must still fail visibly. The unusual temporary-path
command parsing concern is retained in the [security review](PHASE_6_SECURITY_REVIEW.md#gemini-review-follow-up--2026-10-06),
without applying the unverified quoting suggestion or invoking Windows commands.

The reviewed draft is now the [prepared human walkthrough](PHASE_5_VERIFICATION.md#human-accessibility-walkthrough--prepared-2026-10-06).
All its results are PENDING; missing fixtures must be BLOCKED. This trial produced a useful
document but needed correction. Different task sizes and unavailable comparable Codex token
counts prevent a token-savings or speedup claim. No product performance changed. Runtime and
tests are unchanged from `4db44b7`; documentation links and `git diff --check` are the applicable
checks. Windows evidence, manual checks, other G0 rows and owner acceptance remain open.

## Windows reparse CI confirmation — 2026-10-06

Verified public evidence: [GitHub Actions run 37439310170](https://github.com/jiraphat-j/AgentSec/actions/runs/37439310170) (`workflow_dispatch`, attempt 1, success); tested full SHA `7ab1b1c556e3a00649b826018cffa98f6935d961`; PR #10 open (not merged). Tested source and tests are unchanged since `4db44b7`. Historical pending statements are superseded, not erased.

### Four-job CI matrix

| Job | Job ID | Status | Pytest duration | Details |
|---|---|---|---|---|
| `verify (windows-latest)` | 112188820811 | Success | 113.70s | 442 passed, 7 Linux/Unix-only skips, 4 browser deselected, 1 upstream Starlette/httpx warning, 92.13% coverage. Ruff format (108 files), Ruff lint, MyPy (60 files), wheel/sdist build, Python audit (no known vulnerabilities) all pass. |
| `verify (ubuntu-latest)` | 112188821045 | Success | 29.75s | 446 passed, 3 Windows-only skips, 4 deselected, 1 upstream warning, 92.13% coverage. Ruff format (108 files), Ruff lint, MyPy (60 files), wheel/sdist build, Python audit (no known vulnerabilities) all pass. |
| `dashboard-browser (windows-latest)` | 112188821176 | Success | 5.34s | 4 passed |
| `dashboard-browser (ubuntu-latest)` | 112188821023 | Success | 5.57s | 4 passed |

### Windows reparse test log confirmation

Windows test log execution: `tests/test_dashboard_g0_boundaries.py .............ss........`

- Only skips in module are 2 Linux cases.
- All 3 Windows cases therefore passed:
  1. Regular selected file acceptance
  2. File symlink rejection
  3. Parent junction rejection
- Unchanged synthetic target bytes and link cleanup confirmed.

### Exact evidence limitations and open gates

- **Credit boundary**: Credit only named NTFS cases P5 C04 / P5-03 (the 3 named Windows cases); does not credit all reparse tags, filesystem races, or resource exhaustion.
- **Unresolved residuals**: Unusual `cmd` metacharacter temp-root residual remains unresolved.
- **Testing matrix gaps**: Broader hostile, field, error, resource, and mutation matrix remains open.
- **Accessibility**: Manual keyboard navigation, narrow width, real 200% zoom, focus, contrast, and screen-reader testing remain open.
- **Governance / Gate state**:
  - Do not mark phases or G0 complete.
  - Final owner full-diff acceptance, itemized G0 disposition, and Phase 6B G1 remain open.
  - Run evidence applies to tested SHA `7ab1b1c556e3a00649b826018cffa98f6935d961`, not future doc commits or merge; no new host tests or CI dispatch.
- **Related Phase 5 record**: [PHASE_5_VERIFICATION.md#windows-reparse-ci-confirmation--2026-10-06](PHASE_5_VERIFICATION.md#windows-reparse-ci-confirmation--2026-10-06).

### Delegation and documentation verification

agy implemented the approved status/evidence excerpts in a staging folder and returned a
self-review; Codex reviewed the saved changes against the public run and job logs, corrected
the table heading to identify pytest durations rather than whole-job durations, and applied
only the accepted sections while preserving historical records. Exact-file read/write grants
were owner-approved and removed after the task; existing settings and trusted workspaces were
preserved. No permission bypass, repository trust grant, host test, scenario execution or new
CI dispatch was used. `git diff --check` and the new relative-link/heading checks passed;
only the two verification documents changed. Runtime/tests/CI files remain unchanged from
the tested revision, so this documentation-only batch did not rerun runtime checks.

The initial full-document attempt timed out, the smaller retry was denied a file-read permission,
and the first approved edit turn timed out with a partial Phase 5 edit. Those attempts are not
successful evidence updates. The resumed repair completed both files and self-review. Its CLI
reported two conversation turns and 171,458 total tokens; that cumulative value must not be
added to the prior 50,031-token partial report from the same conversation. These reports do not
establish billed usage, Codex savings, or a speedup.

## Next G0 batch: nested response projection tests — prepared 2026-10-06

Status: implemented, locally verified and confirmed by Windows/Ubuntu CI on 2026-10-07;
owner acceptance remains open. See the dated completion and CI records below. Existing artifact-redaction tests exercise
whole-artifact detail rejection; the API tests exercise successful nested pages and child
lookups, but do not provide the dedicated unsafe nested-page/child-route matrix below.
This is additional P5 C08/P5-02 and P6A C11 evidence, not completion of either row.

Delegate only `tests/test_dashboard_nested_projection.py` to agy for implementation and
self-review in a staging folder, with Codex reviewing and applying the accepted diff and
performing final verification. The earlier file-access approval covered only two staged
verification documents. On 2026-10-06 the owner additionally gave standing approval for scoped,
non-sensitive agy delegation/access after Codex verifies the scope. That covers this single
staged test file, not broad repository trust, shell permissions or a waiver of sensitive G2
review. Supply only relevant public source/test context; no dependency installation or sensitive
implementation. Remove the temporary exact-file grants after the task.

Planned observable checks (22 parameterized cases):

- Nine paginated routes: investigation alerts/incidents/rule-evaluations, evaluation
  children/metrics/pairs/confusion-counts/timing, and report-only run timeline. Test each with
  a packaged synthetic canary and separately forged closed prompt metadata in a nested value.
- Two individual child routes: investigation alert and incident, with both unsafe variants.
- For every case, first demonstrate the equivalent safe response, then require HTTP 503 and
  the exact `unsafe_projection_rejected` error for the selected unsafe response. Check security
  headers and absence of the synthetic unsafe value from response, captured output and logs.
- For paginated routes, safe neighboring pages must retain exact offsets/limits/counts and
  values before and after the rejected page. Repeated failures must not exhaust request capacity.
  Confirm the in-memory input catalog remains unchanged throughout.

Use directly constructed synthetic catalogs and in-process `TestClient`, not a real listener,
scenario execution, live credential, host resource, shell or external request. These checks
exercise API response guards after in-memory construction; they do not establish public-loader
schema/provenance validity, browser DOM behavior or manual accessibility.

Codex verification will use the existing networkless resource-bounded sandbox: focused new
tests with existing API/artifact-redaction regressions, full nonbrowser tests, Ruff format/lint
and strict MyPy. Existing sandbox-only G0 authorization covers unchanged-product checks;
any demonstrated sensitive product repair stops for a concrete human review before execution.
Record actual commands, snapshot identity and outcomes after verification. No new runtime
execution, CI dispatch, publication or Phase 6B implementation is claimed by this plan.

### Bounded delegation attempt — 2026-10-06

The initial agy call and one resumed retry both reached their 180-second print timeout
without saving test code or returning a self-review. The staged file remained an 85-byte
docstring stub; no test file was applied to the repository and no project tests were run.
An empty response with CLI status `SUCCESS` is not implementation or verification evidence.

Both calls used `gemini-3.8-flash-high`, high effort, `accept-edits`, terminal sandbox mode
and only two exact-file read/write grants. The log confirmed those grants loaded but did
not establish why the task stalled. No broader permission or bypass was attempted. The
temporary grants were removed, and the original settings values were verified unchanged.

Conversation `6d219198-0c94-4599-ba3a-baeb3c4fe4c7` reported 30,722 cumulative total tokens
across two turns, including the earlier 15,404-token report; do not add those reports
together. This unsuccessful attempt provides no savings or speedup claim. The planned
22-case batch remains unimplemented, pending an agy configuration diagnosis or an
owner-selected implementation fallback.

### Implementation and independent sandbox verification — 2026-10-07

The owner selected agy rather than Codex implementation. Read-only diagnosis found that the
earlier conversation reached a file-read tool, then stalled without an edit. Startup sign-in
warnings were followed by successful silent authentication; they do not establish a persistent
authentication failure. A fresh no-tool response succeeded, then a bounded file-tool probe
read and saved a harmless comment in the same approved staging file. A fresh implementation
conversation subsequently saved the complete module and returned a self-review. The successful
retry used live `stream-json` output and omitted `--disable-slash-commands`; this sequence does
not prove which difference, if any, caused recovery.

Codex inspected the saved implementation against the public API and projection guard, corrected
one import-order issue missed by agy's self-review, and applied only
`tests/test_dashboard_nested_projection.py`. The 22 collected cases cover the planned nine
paginated routes and two child routes with both unsafe variants, exact safe controls and
neighbors, ten fixed-response rejections per case, security headers, captured-output/log leak
checks, and unchanged in-memory catalog data. This is response-guard evidence using synthetic
directly constructed catalogs, not public-loader/schema/provenance or browser evidence.

Temporary exact-file permissions were removed after delegation. Original settings values and
trusted workspaces were verified unchanged. agy used only file inspection/edit tools; it did
not run checks. No broad trust, shell grant, permission bypass, live secret, listener, dependency
installation, sensitive runtime change, publication or CI dispatch was introduced.

#### Tested local snapshot and isolation

- Base full SHA: `7ab1b1c556e3a00649b826018cffa98f6935d961` on
  `codex/g0-dashboard-evidence` (PR #10), plus the then-uncommitted new test file.
- New test file SHA-256:
  `92bfffa146d9414a87876bece2e6929db5782055a2f0418cb3409c6b8976f538`.
- Tracked source, pre-existing tests, dependencies and CI configuration are unchanged from
  that base. Two verification documents are also modified; they are not executable inputs.
- Existing WSL Ubuntu sandbox, Python 3.13.15; `bwrap --unshare-all --clearenv`, read-only
  `/work` repository and `/sandbox` existing dependency environment, private temporary
  filesystem, no host home, credentials or network namespace access.
- Each check used the existing wrapper: `timeout -k 5 240`, `prlimit --cpu=120
  --as=1073741824 --nproc=128 --nofile=256 --fsize=67108864`. Python bytecode/cache writes
  disabled or directed into private `/tmp`; pytest plugin autoload disabled.

Commands below ran inside that sandbox from `/work` (not on the Windows host):

```text
/sandbox/venv/bin/python -m pytest -p no:cacheprovider -q --tb=short tests/test_dashboard_nested_projection.py tests/test_dashboard_api.py tests/test_dashboard_artifact_redaction.py
/sandbox/venv/bin/python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
/sandbox/venv/bin/python -m ruff format --check --no-cache src tests
/sandbox/venv/bin/python -m ruff check --no-cache src tests
/sandbox/venv/bin/python -m mypy --cache-dir /tmp/mypy_cache
```

| Check | Observed result |
|---|---|
| Focused API/redaction regressions, including new matrix | 53 passed, 1 upstream warning, 5.11s |
| Full nonbrowser suite | 468 passed, 3 Windows-only skips, 4 browser deselected, 1 upstream warning, 40.94s |
| Coverage | 92.13%; required 90% passed |
| Ruff format / lint | 61 files already formatted / all checks passed |
| Strict MyPy | No issues in 61 source files |
| Diff whitespace | `git diff --check` passed |

The warning is the existing upstream Starlette/httpx deprecation. The three skips are the
NTFS regular-file, selected-file-link and parent-junction cases, previously exercised by the
recorded Windows CI on the base SHA; this Linux run is not fresh Windows evidence. No new
browser/build/audit checks were required by this test-only change and none are claimed.

#### Delegation usage and remaining gates

CLI-reported totals for separate conversations (not billing or Codex usage):

| Attempt | Conversation | Total tokens |
|---|---|---|
| Earlier two timed-out turns, cumulative | `6d219198-0c94-4599-ba3a-baeb3c4fe4c7` | 30,722 |
| No-tool health check | `a47005ff-5aa8-466d-b8b7-c44322c28cc9` | 13,987 |
| File-tool diagnostic | `59b59f75-1bed-42b7-93e2-ae88ed7f316f` | 45,668 |
| Successful implementation and self-review | `109d5499-8154-464a-b447-f9b3e143fed0` | 102,177 |

The successful implementation reported 177.95s, 74,482 input tokens, 27,695 output tokens
(including 21,849 thinking tokens), and 36,751 cache-read tokens. Do not add thinking tokens
to output or infer billed usage from these fields. The separate conversation totals sum to
192,554, including diagnostics and failed attempts; no matched Codex-only benchmark exists
for this batch, so no savings or speedup is claimed.

The owner authorized committing and pushing this verified batch on 2026-10-07. After the new
head is published, the owner must dispatch
Actions and record each Windows/Ubuntu verify and browser job at its full SHA. Manual keyboard,
real 200% zoom, focus, contrast, screen-reader checks, remaining hostile/resource/mutation
matrices, the `cmd` metacharacter temp-root residual, itemized G0 disposition and final owner
acceptance remain open. This batch does not close G0 or authorize Phase 6B runtime/G1 work.

## Nested response CI confirmation — 2026-10-07

Verified [Actions run 37566851220](https://github.com/jiraphat-j/AgentSec/actions/runs/37566851220):
owner `workflow_dispatch`, attempt 1, completed successfully on full SHA
`453bc1c91c3e33a53ba946d1ae0f9ea763b2bd68`. PR #10 remains open and not merged.
The tested commit includes the new test file from the recorded local snapshot; the preceding
CI-pending statements are superseded for this exact SHA, not erased or extended to future heads.

| Job | Job ID | Result | Pytest duration |
|---|---|---|---|
| `verify (windows-latest)` | 112616423306 | 464 passed, 7 platform skips, 4 browser deselected, 1 upstream warning; 92.13% coverage | 147.23s |
| `verify (ubuntu-latest)` | 112616423326 | 468 passed, 3 platform skips, 4 browser deselected, 1 upstream warning; 92.13% coverage | 27.86s |
| `dashboard-browser (windows-latest)` | 112616423124 | 4 passed | 5.37s |
| `dashboard-browser (ubuntu-latest)` | 112616423334 | 4 passed | 5.49s |

Both verification logs show `test_dashboard_nested_projection.py ......................`:
all 22 new cases executed without skips on both platforms. Windows again ran the three named
NTFS cases; its boundary module shows `.............ss........`, with only the two Linux symlink
cases skipped there. Ubuntu skips the three Windows-only NTFS cases. The remaining Windows
skips are existing Unix descriptor/capture symlink cases. The nonbrowser warning is the existing
upstream Starlette/httpx deprecation, not a failed test.

Each verification job also passed Ruff formatting (109 files), lint, strict MyPy (61 source
files), wheel/sdist build and Python dependency audit (no known vulnerabilities found).
Codex checked the public run metadata, four job conclusions and logs; no new tests, listener,
CI dispatch, runtime modification or merge was performed while recording this evidence.

Credit remains limited to the named test cases. Final owner full-diff acceptance, remaining
hostile/field/error/resource/mutation evidence, unusual `cmd` metacharacter temp-root residual,
human keyboard/zoom/focus/contrast/screen-reader walkthrough, itemized G0 disposition and Phase
6B G1 remain open. A passing CI matrix does not close G0 or authorize Phase 6B implementation.

## Next G0 batch: public nested response-byte limits — prepared 2026-10-07

Status: implemented, locally verified and confirmed by Windows/Ubuntu CI below;
final owner acceptance remains open.

The owner requested continued G0 evidence completion. Existing exact/over response-byte tests
call the private JSON helper; the public nested-route matrix checks redaction, not byte limits.
Delegate only a new staged `tests/test_dashboard_response_limits.py` to agy, under the existing
standing approval for verified non-sensitive scope and exact-file access. No source/dependency,
socket, command-execution, hashing or policy changes are included.

Planned checks: nine paginated routes and two child routes, each with ASCII and multibyte UTF-8
text (22 cases). Construct synthetic in-memory catalogs; independently calculate compact JSON
UTF-8 response bytes. Exactly 1 MiB must return the complete expected JSON without truncation;
one additional ASCII byte must return HTTP 503 and the fixed `response_limit_exceeded` error.
Assert security headers, safe neighbors with exact pagination/child IDs, recovery after repeated
rejection, error/output/log omission of the large synthetic field and unchanged catalog data.
Do not reduce the production bound, call private helpers, run a listener, or load host artifacts.

Codex reviews the saved diff before focused/full nonbrowser, Ruff and strict MyPy checks in the
existing networkless resource-bounded sandbox. Any needed sensitive product repair stops for
concrete human review. This is partial P5 C10/P5-03 response-boundary evidence, not complete
large-artifact retrievability, schema-valid loader, concurrency, hostile-content, accessibility
or G0 acceptance. Preserve the uncommitted CI-record updates; no publication or CI dispatch.

### Public response-byte verification — 2026-10-07

agy implemented the staged test file and self-reviewed it. The initial 180-second call timed
out without an edit; one resumed 300-second call saved the module and returned its review.
Codex found missing context-managed client cleanup and incorrect imports, returned those
narrow repairs to agy, and reviewed the resulting saved code before applying it. agy used only
file tools, not commands or checks. Temporary exact-file grants were removed; original settings
and trusted workspaces were verified unchanged. No broad trust or permission bypass was used.

The 22 new cases independently measure compact JSON UTF-8 bytes through nine public paginated
routes and two child routes, each with ASCII and multibyte text. All return exact, untruncated
content at the actual 1 MiB response limit and fixed HTTP 503 `response_limit_exceeded` errors
at one byte over. Safe neighbors, pagination/IDs, headers, repeated-rejection recovery, omitted
large-field markers in errors/output/logs and unchanged catalog data passed. No private encoding
helper or reduced cap is used. These are synthetic in-memory response tests, not loader/schema,
all-large-artifact retrievability, concurrency, browser or human accessibility evidence.

Tested snapshot: base `453bc1c91c3e33a53ba946d1ae0f9ea763b2bd68` plus the new uncommitted
`tests/test_dashboard_response_limits.py`. Final test-file SHA-256:
`8ef4d8bc83d2cbbf10532e10d9e59bddf08cd514fe62e8e954158cb909e8fc5c`.
Tracked runtime, pre-existing tests, dependencies and CI are unchanged. Earlier uncommitted
CI-record updates in these two verification documents are preserved.

Checks ran in the same networkless WSL Ubuntu sandbox described in the preceding
[local snapshot/isolation record](#tested-local-snapshot-and-isolation), with Python 3.13.15,
read-only repository/environment mounts, private temporary files, 240-second wall/120-second
CPU bounds, 1 GiB address-space limit and existing process/file-size/descriptor limits.

```text
/sandbox/venv/bin/python -m pytest -p no:cacheprovider -q --tb=short tests/test_dashboard_response_limits.py tests/test_dashboard_nested_projection.py tests/test_dashboard_api.py tests/test_dashboard_g0_boundaries.py
/sandbox/venv/bin/python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
/sandbox/venv/bin/python -m ruff format --check --no-cache src tests
/sandbox/venv/bin/python -m ruff check --no-cache src tests
/sandbox/venv/bin/python -m mypy --cache-dir /tmp/mypy_cache
```

| Check | Observed result |
|---|---|
| Focused public-route/resource regressions | 74 passed, 3 Windows-only skips, 1 upstream warning; 10.15s |
| Final full nonbrowser suite | 490 passed, 3 Windows-only skips, 4 browser deselected, 1 upstream warning; 44.11s |
| Coverage | 92.13%, exceeding required 90% |
| Final Ruff format / lint | 62 files already formatted / all checks passed |
| Final strict MyPy | No issues in 62 source files |

The first format/lint checks found a 101-column assertion. Codex applied only its mechanical
line wrap after focused tests finished; the final full suite and all quality checks above
include that wrap. Skips are the three NTFS cases; the warning is the existing Starlette/httpx
deprecation. No browser, build, audit, host test or CI dispatch was run for this test-only batch.

agy conversation `88aa8a82-d216-42e1-b958-cdf913b660e2` reports 166,078 cumulative total tokens
over three turns (125,714 input, 40,364 output, including 33,359 thinking; 204,376 cache-read),
and a cumulative CLI duration of 528.78s. Do not add the earlier 16,893 or 139,705 cumulative
reports, or add thinking to output. These figures are not billed usage; no matched Codex-only
benchmark exists, so no savings or speedup is claimed.

The owner authorized committing and pushing this batch with the preceding CI-record updates.
New-head Windows/Ubuntu CI,
owner full-diff acceptance, remaining G0 matrices, the `cmd` temporary-path residual and human
walkthrough remain open. Repository inspection found a manifest template and transient browser
fixtures, not a retained reviewed multi-page manual fixture set; no dashboard was started.
Prepare and review those fixtures before crediting manual checks. Phase 6B remains gated by
itemized G0 disposition and its G1 design decision.

## Public response-byte CI confirmation — 2026-10-07

Codex verified the public metadata, four job conclusions and logs for owner-dispatched
[Actions run 37628097651](https://github.com/jiraphat-j/AgentSec/actions/runs/37628097651),
attempt 1, completed successfully on full SHA `6aa9735ad273d9c2b93ee6943df8bdb814a1a7f2`.
PR #10 remains open and not merged. Earlier CI-pending statements are superseded for this
exact commit, not extended to future heads or untested acceptance criteria.

| Job | Job ID | Result | Pytest duration |
|---|---|---|---|
| `verify (windows-latest)` | 112815003301 | 486 passed, 7 platform skips, 4 browser deselected, 1 upstream warning; 92.13% coverage | 150.53s |
| `verify (ubuntu-latest)` | 112815003477 | 490 passed, 3 platform skips, 4 browser deselected, 1 upstream warning; 92.13% coverage | 33.92s |
| `dashboard-browser (windows-latest)` | 112815003021 | 4 passed | 6.59s |
| `dashboard-browser (ubuntu-latest)` | 112815003388 | 4 passed | 4.24s |

Both verification logs show all 22 cases in `test_dashboard_response_limits.py` passed without
skips. Windows boundary evidence again includes the three NTFS cases; Ubuntu skips those
Windows-only cases. Windows skips seven existing Unix descriptor/symlink cases. The warning
is the existing upstream Starlette/httpx deprecation, not a test failure.
Both verification jobs also passed Ruff formatting (110 files), lint, strict MyPy (62 source
files), wheel/sdist build and dependency audit (no known vulnerabilities found).

Recording these results involved no test execution, listener, CI dispatch, runtime change or
merge. These documentation updates remain uncommitted. Final owner full-diff acceptance,
remaining hostile/field/error/resource/mutation matrices, the unusual `cmd` temporary-path
residual, human keyboard/zoom/focus/contrast/screen-reader walkthrough, itemized G0 disposition
and Phase 6B G1 remain open. Green CI does not close G0 or authorize Phase 6B implementation.

## A1 request-boundary verification — 2026-10-10

Status: **Test implementation saved and independently verified; A1 acceptance fails on HEAD.
Not ready for publication or G0 closure.** Earlier green CI applies only to its recorded commit.

The owner explicitly approved sending A1 internal interfaces and synthetic test specifications
to Google Antigravity/Gemini, and allowed a longer generation window. Codex delegated only the
staged `tests/test_dashboard_acceptance_matrix.py`, with no test execution or product edits.
The 900-second print window completed rather than timing out. agy implemented and self-reviewed
the file using file tools only. Codex reviewed its actual saved code and returned narrow repairs:
the positive detail control must compare the full `{summary, data}` envelope; the catalog
snapshot must use `tuple[CatalogRecord, ...]`; catalog output must match the exact expected page.
agy saved those repairs. Codex then applied the file and only Ruff's mechanical assertion layout.
No skip, xfail, alternate-shape fallback or product-boundary change was added.

All 17 cases use a schema-valid synthetic failed `RuleTestReport` under pytest's temporary
directory, validated through the public loader. Each has a successful detail GET control with
exact summary/data equality. Probes cover configured and wrong-port Origin, absent/none/
same-origin/same-site Fetch Metadata, HEAD, OPTIONS preflight, PUT/PATCH/DELETE, disabled docs/
OpenAPI, raw-file paths and encoded static traversal. Before probe-status assertions, tests
check fixed security headers, unchanged artifact/manifest bytes and whole-catalog snapshots.
Rejected/raw responses omit the synthetic marker; preflight grants no CORS allow headers.
Host hostname validation is not an exact Host-port check; that policy ambiguity remains separate.

### Tested snapshot and commands

- Base: `6aa9735ad273d9c2b93ee6943df8bdb814a1a7f2`, branch `codex/g0-dashboard-evidence`,
  plus the new uncommitted test file. Existing verification-record edits are preserved.
- Final test SHA-256: `e41f692e7515d0ae8117e97b496fe88c3f76ea8d8feddf3d8db34ce4f15b1cce`.
- Runtime, pre-existing tests, dependencies and CI configuration are unchanged from that base.
- Existing WSL Ubuntu environment `/home/godji/agentsec-g0-env.045vOJ`, Python 3.13.15;
  `bwrap --unshare-all --clearenv`, read-only `/work` and `/sandbox`, private `/tmp`, no host
  home/credential mounts or network access. Existing limits: 240s wall, 120s CPU, 1 GiB address
  space, 128 processes, 256 descriptors and 64 MiB file size. No host scenario tests or listener.

Commands ran from `/work` with `/sandbox/venv/bin/python` inside that wrapper:

```text
python -m pytest -p no:cacheprovider -q --tb=short tests/test_dashboard_acceptance_matrix.py
python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --cache-dir /tmp/mypy_cache
```

| Check | Observed result |
|---|---|
| Focused A1 | 16 passed, 1 failed, 1 upstream warning; 2.44s |
| Full nonbrowser, including final formatting | 506 passed, 1 failed, 3 NTFS skips, 4 browser deselected, 1 upstream warning; 92.13% coverage; 57.22s |
| Final Ruff format/lint | Pass; 63 files formatted, no lint findings |
| Strict MyPy | Pass; 63 source files |

The initial format check found two assertion-layout differences; the final checks and full
suite include only those mechanical corrections. The warning is the existing upstream
Starlette/httpx deprecation. No browser, build, dependency audit or fresh CI was run for A1.

### Open HEAD disposition and delegation record

Both pytest runs fail only `test_dashboard_a1_request_boundary[head-catalog]`: expected 200,
observed 405. Its valid GET control, security headers and source/catalog immutability checks
passed before that assertion. The middleware permits GET/HEAD, but the catalog route is
registered using `@app.get`; source inspection supports a missing HEAD route, not a data leak
or new host-execution surface. ADR-008 says the dashboard exposes GET/HEAD only; the prepared
A1 contract expects a successful HEAD response. Keep this failed criterion visible until the
owner approves a reviewed routing repair or explicitly clarifies/disposes of that expectation.
Agy self-review and the owner's temporary delegation authority are not human review of a
concrete HTTP-adapter repair. No product repair was implemented or executed.

Conversation `fb43a95a-f789-4201-b2a8-50df768de087`, model `gemini-3.8-flash-high`, high effort:
final CLI report 262,407 cumulative total tokens over two turns (214,758 input, 47,649 output
including 38,537 thinking; 237,461 cache-read), cumulative reported duration 365.60s. Do not
sum earlier cumulative reports, count thinking twice or infer billed cost/Codex savings.
Temporary exact-file permission configuration was removed; original settings and existing
trusted-workspace values were verified unchanged. Two normal read-only shell launches failed
in MXC startup while enumerating `D:`; approved scoped reads succeeded afterward. No drive
inspection/repair, host test or relaxation of the WSL test isolation occurred.

A1 is partial, not accepted. A2–A8, the Windows command-root decision, manual accessibility,
installed-package disposition, final owner acceptance and Phase 6B G1 remain open. The test
and verification records remain uncommitted; no push, CI dispatch, PR mutation or merge.

## A1 HEAD repair prepared — 2026-10-10

**⚠️ Security Sensitive: Requires Mandatory Human Review. Historical preparation record;
the owner subsequently approved networkless execution, recorded below.**

The owner authorized continuing until the commit/push handoff. Codex prepared and reviewed
the concrete routing repair below. Under ADR-008 and the repository security guide, approval
to continue preparation does not replace human sign-off on this HTTP-adapter diff before
execution. No pytest, listener or browser was run against the modified adapter. This sensitive
repair stays with Codex, outside agy's approved non-sensitive implementation scope.

### Concrete runtime diff for sign-off

Only `src/agentsec/dashboard_api.py` changes at runtime: replace the twelve existing
`@app.get(...)` decorators with the following registrations, in their existing order:

```python
@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/assets/styles.css", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/assets/app.js", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/api/v1/catalog", methods=["GET", "HEAD"])
@app.api_route("/api/v1/{collection}", methods=["GET", "HEAD"])
@app.api_route("/api/v1/{collection}/{item_id}", methods=["GET", "HEAD"])
@app.api_route("/api/v1/runs/{item_id}/events", methods=["GET", "HEAD"])
@app.api_route("/api/v1/runs/{item_id}/events/{event_id}", methods=["GET", "HEAD"])
@app.api_route("/api/v1/runs/{item_id}/timeline", methods=["GET", "HEAD"])
@app.api_route("/api/v1/investigations/{item_id}/alerts/{alert_id}", methods=["GET", "HEAD"])
@app.api_route(
    "/api/v1/investigations/{item_id}/incidents/{incident_id}", methods=["GET", "HEAD"]
)
@app.api_route("/api/v1/{collection}/{item_id}/{nested_collection}", methods=["GET", "HEAD"])
```

This is a list of replacement decorators, not a runnable module. The actual source diff
retains all handlers, route order, hidden-asset schema flags and response implementations.
The method gate, Host/Origin/Fetch Metadata checks, query validation, concurrency accounting,
file/path restrictions, projection/response limits and security headers are unchanged.
No new route path, dependency, file access, socket, subprocess, external HTTP client or write
operation is introduced. HEAD uses the existing GET handler, so it still performs the bounded
read/projection work; this is not a new cheaper metadata-only endpoint. Empty response bodies
and matching status/headers are acceptance assertions, not yet observed results for this patch.

Prepared snapshot on `codex/g0-dashboard-evidence`, base
`6aa9735ad273d9c2b93ee6943df8bdb814a1a7f2`, plus preserved uncommitted evidence edits:

- Adapter SHA-256 (CRLF bytes): `35e2e151f969764f15bbbf8a437c0aa2f5482acd95cf3ff6f36f6158b1aed86e`.
- Test SHA-256: `a6ec43b3864a3046f7f60ab24429b50bdadcbdd40bb55c9b38b4a55673bf45d8`.

### Prepared regressions and static checks

The original 17 A1 cases, including the failing HEAD assertion, remain without skip/xfail.
Codex added 28 GET/HEAD comparison cases using the same synthetic temporary catalog:
all twelve route patterns, correct Origin and same-origin Fetch Metadata, rejected foreign/
wrong-port Origin, same-site/cross-site Fetch Metadata, foreign Host, unknown/duplicate query
keys, excessive page size, disabled docs/OpenAPI/raw-file paths and encoded traversal.
Each compares expected status, all response headers and content length, requires an empty
HEAD body and fixed security headers, rejects CORS allow headers, and checks unchanged source
bytes and whole-catalog data. Each first validates a successful full-detail GET control.
Six route cases use genuine 404 missing-record controls; these prove intended error routing,
not successful HEAD retrieval of run/investigation records. Those happy-path fixture rows
remain distinct from this bounded repair and are not claimed complete.

Only static commands ran in the previously documented networkless WSL/bwrap environment:

```text
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --cache-dir /tmp/mypy_cache
git diff --check
```

Final results: formatting passed (63 files), lint passed, MyPy passed (63 source files),
and diff whitespace check passed. The initial formatter check requested a wrapped decorator
and consistent existing CRLF endings; both mechanical corrections are included. Git's
documentation LF-to-CRLF notices are not test failures. The test file is still untracked,
so ordinary `git diff --stat` omits its additions.

After concrete human sign-off, run the 45 focused cases and full nonbrowser coverage suite
with the same networkless wrapper, followed by static checks on the final snapshot. Record
actual results and any repairs; do not carry forward the earlier green CI to this new code.
Commit/push requires separate owner authorization. G0 closure, new-head Windows/Ubuntu CI,
manual accessibility, remaining A2–A8 evidence and Phase 6B G1 are still open.

## A1 HEAD repair verification — 2026-10-10

The owner replied **"approve"** to the concrete HTTP-adapter diff and networkless sandbox
execution request. This satisfies the execution sign-off for the prepared repair, not commit,
push, CI dispatch or merge authority. Codex verified the approved adapter and test SHA-256
values above before and after execution; neither file changed and no repair was needed.

The original 17 A1 cases and 28 additional GET/HEAD cases all passed. HEAD now reaches the
existing handlers, returns the expected status and headers with an empty body, and preserves
artifact/manifest bytes and whole-catalog data. Negative Host/Origin/Fetch Metadata/query
checks still reject requests; unsupported methods remain rejected and disabled paths remain
unavailable. Six route-pattern controls intentionally exercise missing-record 404 responses,
not successful HEAD retrieval of run/investigation records.

Commands used `/sandbox/venv/bin/python` from `/work` in the same WSL Ubuntu/bwrap wrapper:
no network, read-only repository/environment, private temporary storage, no host home or
credential mounts, and unchanged 240s wall/120s CPU/1 GiB address-space/128-process/
256-descriptor/64 MiB file-size limits. No host scenario test, listener or browser was started.

```text
python -m pytest -p no:cacheprovider -q --tb=short tests/test_dashboard_acceptance_matrix.py
python -m pytest -p no:cacheprovider -p pytest_cov.plugin --cov=agentsec --cov-report=term --cov-fail-under=90 -q --tb=short
python -m ruff format --check --no-cache src tests
python -m ruff check --no-cache src tests
python -m mypy --cache-dir /tmp/mypy_cache
```

| Check | Observed result |
|---|---|
| Focused A1/HEAD | 45 passed, 1 existing upstream warning; 2.78s |
| Full nonbrowser | 535 passed, 3 NTFS skips, 4 browser deselected, 1 existing upstream warning; 92.13% coverage; 56.81s |
| Final Ruff format | Pass; 63 files already formatted |
| Final Ruff lint | Pass |
| Final strict MyPy | Pass; 63 source files |

The three skips remain Windows-only regular-file/symlink/junction evidence; this Linux run
does not replace new-head Windows CI. The warning remains the upstream Starlette/httpx
deprecation; no dependency change or warning suppression was introduced.

The initial parallel final static-check reruns stalled without output, as did a read-only
Linux process-name query. Codex identified and stopped only its own WSL clients, leaving
the shared VM and unrelated processes untouched. All three static checks then passed in
sequential hidden invocations with an additional 30-second host-side deadline for each client
process tree. The sandbox configuration was unchanged. No VM restart, storage/memory setting
change or broader process termination was performed; the underlying stall cause is not proven.

This supersedes the earlier HEAD failure and pending-execution statements for the exact
approved snapshot only. The batch is ready for the owner's commit/push decision, not G0
closure or Phase 6B implementation. Host hostname versus exact Host-port wording still needs
owner disposition; no stricter Host-port policy was silently introduced. Remaining A2–A8,
manual accessibility, installed-package disposition, final owner acceptance and new-head
Windows/Ubuntu CI remain open. No build, fresh dependency audit, browser run, external model
call, commit, push, CI dispatch, PR mutation or merge occurred in this verification step.

### Publication approval — 2026-10-10

The owner explicitly approved committing and pushing this verified batch to PR #10.
The publication scope is only `src/agentsec/dashboard_api.py`,
`tests/test_dashboard_acceptance_matrix.py`, and the Phase 5/6 verification records.
Unrelated primary-workspace planning/workflow edits are excluded. Immediately before
publication, public PR metadata confirmed PR #10 open on `codex/g0-dashboard-evidence`,
with remote head `6aa9735ad273d9c2b93ee6943df8bdb814a1a7f2`. Only inactive sample hooks
were present. The workflow remains `workflow_dispatch` only: owner-dispatched new-head CI
and final merge review are still required. Commit/push approval does not authorize either.

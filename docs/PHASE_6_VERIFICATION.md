# Phase 6A verification record

Status: **C02 loader repair passed focused, full non-browser, installed-package, and Playwright
checks in a networkless sandbox on an uncommitted snapshot. C01–C13 acceptance, manual
accessibility, exact-commit CI, and final review remain open.**

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

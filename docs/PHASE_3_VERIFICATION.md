# Phase 3 verification record

Date: 2026-09-09

Branch: `phase-3-detection-engineering`

Base revision: `31156ed463a065734b3419c0b3796635b6732dde`

## Scope verified

- Strict JSON rule schema 1.0 with bounded typed predicates and field allowlist
- Single-event, ordered-sequence, and same-run/same-trace correlation evaluation
- Deterministic evidence identities, match ordering, and deduplication
- Exact positive and negative fixture coverage for all three packaged rules
- Read-only/query-only SQLite replay without agent, gateway, adapter, socket, or DNS activity
- Bounded JSON/Markdown rule-test and replay reports with raw-canary rejection
- Event schema 0.1/0.2 compatibility and rejection of unsupported versions
- Existing Phase 1 and Phase 2 run, strict-profile, approval, comparison, and report behavior

## Local evidence

Environment: Windows, Python 3.13.15.

| Check | Result |
|---|---|
| `python -m ruff format --check .` | Passed; 64 files already formatted |
| `python -m ruff check .` | Passed |
| `python -m mypy` | Passed; 33 source files |
| `python -m pytest --cov=agentsec --cov-report=term-missing` | Passed; 90 tests, 91% total coverage |
| `python -m build` | Passed; sdist and wheel `0.3.0` built |
| `python -m pip_audit` | No known dependency vulnerabilities; unpublished local package skipped |
| Isolated wheel install on Python 3.13 | Passed |
| Installed `rules validate` | Passed; 3 rules |
| Installed `rules test` | Passed; 3/3 rule coverage and 6/6 fixture assertions |
| Installed vulnerable scenario plus `replay` | Passed; source completed and 2 matches reported |

The source-unchanged, missing-source, malformed-source, lifecycle-conflict, no-network,
no-adapter, redaction, overwrite, and size-limit properties are asserted by automated tests.
Synthetic fixture coverage is contract coverage, not production accuracy or a false-positive rate.
Replay processing time is local evaluator duration, not MTTD or MTTR.

## Remaining delivery gates

- Run and record the manual GitHub Actions matrix on both Windows and Linux for the final commit.
- Obtain normal code review for the Phase 3 rule and replay implementation.
- The branch also carries required formatting/type/test corrections for the merged Phase 2
  baseline. Production changes in `gateway.py`, `policy.py`, and `approvals.py` are formatting-only,
  but those files are security-sensitive under repository policy and must be included explicitly in
  human review before merge.

Phase 3 is therefore a locally verified implementation candidate, not a completed or remotely
verified release.

# AgentSec Lab evaluation example

This illustrative `core-lab-v1` Phase 4 result contains one repetition of three closed fixtures
under both policy profiles: six completed child runs and no expectation failures.

| Profile | Attack success | Attack-run detection | Impact detection | Prevention | Benign false positive |
|---|---:|---:|---:|---:|---:|
| vulnerable | 1/2 | 2/2 | 1/1 | 0/2 | 0/1 |
| strict | 0/2 | 2/2 | unavailable (0/0) | 2/2 | 0/1 |

The missing-canary fixture is an attack control, not benign. It reads and attempts to transfer the
fake secret but cannot reach matching-canary simulated impact. The strict profile's declarative
control-observation rule counts under the documented run-level alert policy.

The report retains each child SQLite store, original reports, and derived investigation. It also
records paired profile outcomes, TP/FN/FP/TN counts, per-rule run counts, incident categories,
exclusions, and separate recorded legacy timing. Repetition checks deterministic stability; these
synthetic fractions are not production detection accuracy.

The vulnerable malicious child reaches impact and its strict counterpart prevents it. Thus the
separately named prevention rate restricted to complete vulnerable-impact pairs is 1/1; the
all-attack strict prevention rate remains 2/2.

# Metrics

Real numbers measured 2026-09-10 after the feature-complete demo run
(`endpointaegis demo`, offline fixtures, DRY-RUN enforced).

## Hardening score separation

| Profile | Score | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| good (hardened) | **92/100** | 0 | 0 | 2 | 1 |
| bad (vulnerable) | **31/100** | 6 | 14 | 10 | 1 |

Gap: **61 points**. Contract target: 92 vs 31 (met exactly).

## Flags per category (demo, bad profile)

- services: 3 findings (3 critical/high)
- patch: 11 findings (6 critical/high)
- sockets: 5 findings (4 critical/high)
- users: 6 findings (4 critical/high)
- files: 6 findings (3 critical/high)
- baseline: 0 (drift audit requires a snapshot; see below)

## Drift baseline (T0 = good, T1 = bad)

Files added / removed / modified, services added, users added — all detected;
verdict: CHANGED.

## Reports

- Self-contained HTML report ≈ **4.2 KB**, valid `<!DOCTYPE html>`, embeds score,
  category breakdown, module findings with severity.
- Valid JSON report (machine-readable) and Markdown summary written to `reports/`.

## Tests

- `python -m unittest discover -s tests` → **72 tests, all green**.
- Coverage: scoring (range, penalties, good>85, bad<45), services, patch (version
  comparison, missing variants), sockets (0.0.0.0 flagging), users (UID-0, empty
  pass, passwordless sudo, world-writable homes), files (SUID anomaly, secrets),
  baseline (T0→T1 deltas), reports (HTML well-formed + JSON parseable), CLI
  subprocess exit codes, and read-only enforcement (no writes to fixtures or temp
  dirs).

## Read-only enforcement

`--dry-run` is always the effective mode and CLI-enforced (`config.dry_run = True`
regardless of input). Enforced by `tests/test_readonly.py`: audited fixture trees
byte-identical before/after; temp dir untouched. Demo prints a live read-only check
line (`PASSED`).

_Re-measure after each feature change; never ship a run without updating this file._
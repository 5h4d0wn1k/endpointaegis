# endpointaegis

EDR-lite & host-hardening auditor — 0-100 hardening score, persistence/service/patch/socket audit, drift baseline, HTML+JSON reports. Reads genuine host state **read-only**; never modifies the audited system.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

```bash
python3 -m pip install -e .
endpointaegis --help
endpointaegis --demo            # offline, exit 0 — proof: 92 vs 31 scores
python3 -m unittest discover -s tests
```

## Command reference

```
endpointaegis score    [--profile good|bad]            # 0-100 hardening score
endpointaegis services [--profile ...]                 # service/persistence audit
endpointaegis patch    [--profile ...]                 # missing-patch audit (offline advisory)
endpointaegis sockets  [--profile ...]                 # network listener audit
endpointaegis users    [--profile ...]                 # password/uid/sudo/home audit
endpointaegis files    [--profile ...]                 # SUID/world-writable/secrets scan
endpointaegis baseline [--create] [--profile ...]      # drift baseline snapshot / check
endpointaegis report   [--profile ...]                 # aggregate HTML+JSON+Markdown report
endpointaegis scan     [--profile ...]                 # run all audits, write reports/
endpointaegis demo                                     # good vs bad proof run
```

Every subcommand takes `--dry-run` (ALWAYS the effective mode — audits are read-only by
design and the flag is enforced, never weakened), `--config configs/default.json`
(YAML or JSON), and `--reports-dir`.

Scanning reads **only** fixture host profiles under `tests/fixtures/hosts/`. The `system`
scan (live `/proc`, `/etc/passwd`, installed packages) is **disabled by default** and
only reachable via `--live-system` plus explicit confirmation; it remains strictly
read-only.

## Host profiles (fixtures)

| Profile | Score | Narrative |
|---|---|---|
| `good` | **92/100** | patched for all critical/high advisories, hardened sshd/nginx, no exposed services, strong account hygiene, minor low/medium patch lag |
| `bad`  | **31/100** | outdated packages (openssl, glibc, linux-image …), services on `0.0.0.0`, empty-pass + UID-0 accounts, passwordless sudo, SUID anomalies, leaked private key |

## Architecture

```
endpointaegis/
  cli.py          argparse subcommands, dry-run + live-system gating
  config.py       YAML/JSON config merge (weights, advisories, allowlists)
  scoring.py      Finding/AuditResult, weighted 0-100 score
  scanner.py      run_all_audits orchestration
  reports.py      self-contained HTML + JSON + Markdown reports
  auditors/
    services.py   unit files + autostart/cron           -> services
    patch.py      dpkg/apk-style list vs offline advisory -> patch
    sockets.py    netstat/ss listeners                   -> sockets
    users.py      shadow/passwd/sudoers/home perms       -> users
    files.py      SUID, world-writable, dotfiles, secrets-> files
    baseline.py   T0 snapshot, T1 drift deltas           -> baseline
```

Score = `100 - Σ capped-deductions`, weights in `configs/default.json`; the baseline
component rewards drift monitoring as a hardening factor.

## Live Lab Test Plan

All of the following are offline, run against fixture host profiles under
`tests/fixtures/hosts/`. To replay on a real box you own (and are authorized to test),
run in a lab VM, first.

1. `endpointaegis demo` — expect exit 0, `good` score **92**, `bad` score **31**,
   per-category flag counts, drift deltas (files/services/users changed), two HTML+
   JSON reports written, and a read-only check line `PASSED`.
2. `endpointaegis score --profile good` → exit 0, prints `Score: 92/100`.
3. `endpointaegis score --profile bad` → exit 0, prints `Score: 31/100`.
4. `endpointaegis scan --profile bad` → exit 0, writes `reports/endpointaegis_*.html`
   — open in a browser: score visible, module findings listed.
5. `endpointaegis baseline --create --profile good` → writes `baseline.json`; then
   `endpointaegis baseline --profile bad` after copying the snapshot → drift report
   shows file/service/user deltas.
6. Read-only proof: run tests — `test_readonly.py` asserts no temp/fixture writes.

**Expected proof output:** exit codes of `0` for demo/scan/score; test suite fully
green; `reports/` contains valid, self-contained HTML.

## Metrics

Measured 2026-09-10 after the feature-complete demo run (`endpointaegis demo`):

- **Score separation:** good **92** vs bad **31** (contract target 92 vs 31) — gap 61.
- **Findings flagged (demo):**
  - `good`: 0 critical / 0 high / 2 medium / 1 low (patch lag only)
  - `bad`: 6 critical / 14 high / 10 medium / 1 low
  - per category: services 3, patch 11, sockets 5, users 6, files 6, baseline 0 (drift)
- **Drift delta (T0=good → T1=bad):** files added/removed/modified, services added,
  users added — all flagged, verdict CHANGED.
- **Reports:** self-contained HTML ≈ 4.2 KB, valid JSON, Markdown summary written.
- **Tests:** 75 unit tests via `python -m unittest discover -s tests` — all green.
- **Read-only:** enforced in CLI (`--dry-run` always on), verified by tests and demo
  temp-dir check.

## Development

- Commit identity: `5h4d0wn1k <5h4d0wn1k@users.noreply.github.com>`.
- Feature-by-feature commits; never push; keep the tree clean.
- Never weaken the safety gates or legal notices.
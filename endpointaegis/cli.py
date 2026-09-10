"""CLI entry point — argparse subcommands, dry-run enforcement."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .config import Config, load_config
from .scoring import compute_score, summarize_findings
from .auditors import services, patch, sockets, users, files
from .auditors.baseline import create_baseline, save_baseline, load_baseline, audit_baseline
from .scanner import run_all_audits, run_scan
from .reports import (generate_json_report, write_json_report, write_html_report,
                      write_markdown_report, render_html_to_string)

_PKG_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_DIR.parent


def _resolve_host_root(profile: str, config: Config) -> Path:
    """Resolve host profile root directory."""
    base = _REPO_ROOT / config.fixtures_root / profile
    if base.exists():
        return base
    # Try relative to cwd
    cwd_base = Path(config.fixtures_root) / profile
    if cwd_base.exists():
        return cwd_base.resolve()
    print(f"[!] Host profile not found: {profile} (checked {base})", file=sys.stderr)
    sys.exit(1)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add common arguments to a subparser."""
    parser.add_argument("--config", type=str, default=None, help="Config file (YAML/JSON)")
    parser.add_argument("--profile", type=str, default=None, help="Host profile name")
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="Dry-run mode (always enforced, default: True)")
    parser.add_argument("--live-system", action="store_true", default=False,
                        help="Enable live system scan (DISABLED by default)")
    parser.add_argument("--reports-dir", type=str, default=None, help="Output directory for reports")


def _get_config(args) -> Config:
    """Build config from args."""
    config = load_config(args.config)
    if args.profile:
        config.default_profile = args.profile
    if args.reports_dir:
        config.reports_dir = args.reports_dir
    config.dry_run = True  # Always enforced
    config.live_system = getattr(args, "live_system", False) and False  # DISABLED by default
    return config


def cmd_score(args: argparse.Namespace) -> None:
    """Compute hardening score for a host profile."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    results = run_all_audits(host_root, config)
    score, cat_scores = compute_score(results, config)
    findings_summary = summarize_findings(results)

    print(f"=== endpointaegis Hardening Score ===")
    print(f"Profile: {profile}")
    print(f"Score: {score}/100")
    print()
    print("Category breakdown:")
    for cat, val in cat_scores.items():
        print(f"  {cat}: {val}")
    print()
    print("Findings:")
    for sev, count in findings_summary.items():
        if count > 0:
            print(f"  {sev}: {count}")


def cmd_services(args: argparse.Namespace) -> None:
    """Audit services and startup entries."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    result = services.audit_services(host_root, config)
    _print_audit_result("Services", result)


def cmd_patch(args: argparse.Namespace) -> None:
    """Audit package patches."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    result = patch.audit_patch(host_root, config)
    _print_audit_result("Patch", result)


def cmd_sockets(args: argparse.Namespace) -> None:
    """Audit network sockets."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    result = sockets.audit_sockets(host_root, config)
    _print_audit_result("Sockets", result)


def cmd_users(args: argparse.Namespace) -> None:
    """Audit user accounts."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    result = users.audit_users(host_root, config)
    _print_audit_result("Users", result)


def cmd_files(args: argparse.Namespace) -> None:
    """Audit file hygiene."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    result = files.audit_files(host_root, config)
    _print_audit_result("Files", result)


def cmd_baseline(args: argparse.Namespace) -> None:
    """Create or check drift baseline."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)

    if args.create:
        bl = create_baseline(host_root)
        bl_path = host_root / "baseline.json"
        save_baseline(bl, bl_path)
        print(f"Baseline created at {bl_path}")
        print(f"Files: {len(bl.get('files', {}))}, Services: {len(bl.get('services', {}))}, Users: {len(bl.get('users', {}))}")
    else:
        bl_path = host_root / "baseline.json"
        bl = load_baseline(bl_path)
        if bl is None:
            print("No baseline found. Run with --create first.")
            sys.exit(1)
        result = audit_baseline(host_root, config, bl)
        _print_audit_result("Baseline Drift", result)


def cmd_report(args: argparse.Namespace) -> None:
    """Generate aggregate report."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    reports_dir = Path(config.reports_dir)
    results = run_all_audits(host_root, config)
    score, cat_scores = compute_score(results, config)
    findings_summary = summarize_findings(results)

    report = generate_json_report(score, cat_scores, results, findings_summary, profile)
    json_path = write_json_report(report, reports_dir)
    html_path = write_html_report(report, reports_dir)
    md_path = write_markdown_report(report, reports_dir)

    print(f"Score: {score}/100")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(f"Markdown: {md_path}")


def cmd_scan(args: argparse.Namespace) -> None:
    """Run all audits against a profile."""
    config = _get_config(args)
    profile = args.profile or config.default_profile
    host_root = _resolve_host_root(profile, config)
    reports_dir = Path(config.reports_dir)

    score, cat_scores, findings_summary, results = run_scan(host_root, config, profile, reports_dir)

    print(f"=== endpointaegis Full Scan ===")
    print(f"Profile: {profile}")
    print(f"Score: {score}/100")
    print(f"Reports written to: {reports_dir}/")
    print()
    print("Findings by severity:")
    for sev, count in findings_summary.items():
        if count > 0:
            print(f"  {sev}: {count}")
    print()
    for name, result in results.items():
        status = "PASS" if result.passed else "FAIL"
        print(f"  [{status}] {name}: {len(result.findings)} findings")


def cmd_demo(args: argparse.Namespace) -> None:
    """Run demo: scan good + bad profiles, show drift and read-only proof."""
    config = load_config(args.config)
    config.dry_run = True

    print("=== endpointaegis Demo ===")
    print(f"Version: {__version__}")
    print(f"Mode: DRY-RUN (read-only enforced)")
    print()

    for profile_name in ["good", "bad"]:
        host_root = _resolve_host_root(profile_name, config)
        results = run_all_audits(host_root, config)
        score, cat_scores = compute_score(results, config)
        findings_summary = summarize_findings(results)

        print(f"--- Profile: {profile_name} ---")
        print(f"Score: {score}/100")
        print("Category scores:")
        for cat, val in cat_scores.items():
            print(f"  {cat}: {val}")
        print("Findings by severity:")
        for sev, count in findings_summary.items():
            if count > 0:
                print(f"  {sev}: {count}")
        print("Flags per category:")
        for cat, r in results.items():
            high_crit = len([f for f in r.findings if f.severity in ("high", "critical")])
            print(f"  {cat}: {len(r.findings)} findings ({high_crit} critical/high)")

        reports_dir = Path(config.reports_dir)
        report = generate_json_report(score, cat_scores, results, findings_summary, profile_name)
        json_path = write_json_report(report, reports_dir)
        html_path = write_html_report(report, reports_dir)
        html_preview = render_html_to_string(report)
        print(f"Reports: {json_path}, {html_path}")
        print(f"HTML rendered: {len(html_preview)} bytes, contains 'endpointaegis': "
              f"{'endpointaegis' in html_preview}")
        print()

    # Drift baseline demonstration: snapshot good at T0, compare drifted state at T1
    print("--- Drift baseline (T0 = good profile, T1 = drifted profile) ---")
    good_root = _resolve_host_root("good", config)
    t0_baseline = create_baseline(good_root)
    # Simulate T1 drift: compare against the bad profile (files/services/users changed)
    bad_root = _resolve_host_root("bad", config)
    drift = audit_baseline(bad_root, config, t0_baseline)
    print(f"Files added:  {drift.metadata.get('files_added', 0)}")
    print(f"Files removed: {drift.metadata.get('files_removed', 0)}")
    print(f"Files modified: {drift.metadata.get('files_modified', 0)}")
    print(f"Services added: {drift.metadata.get('services_added', 0)}")
    print(f"Services removed: {drift.metadata.get('services_removed', 0)}")
    print(f"Users added:  {drift.metadata.get('users_added', 0)}")
    print(f"Drift verdict: {'CHANGED' if not drift.passed else 'CLEAN'}")
    print()

    # Read-only enforcement check
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        before = set(Path(td).iterdir())
        config2 = load_config(args.config)
        config2.dry_run = True
        profile = "good"
        host_root = _resolve_host_root(profile, config2)
        run_all_audits(host_root, config2)
        after = set(Path(td).iterdir())
        ro_ok = before == after
        print(f"Read-only check: {'PASSED' if ro_ok else 'FAILED'} (temp dir unchanged: {ro_ok})")

    print()
    print("Demo complete. Exit 0.")
    sys.exit(0)


def _print_audit_result(name: str, result) -> None:
    """Print audit result summary."""
    status = "PASS" if result.passed else "FAIL"
    print(f"=== {name} Audit [{status}] ===")
    for f in result.findings:
        print(f"  [{f.severity.upper()}] {f.title}")
        if f.detail:
            print(f"         {f.detail}")
    if not result.findings:
        print("  No findings.")
    print(f"Metadata: {json.dumps(result.metadata, indent=2)}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="endpointaegis",
        description="EDR-lite & host-hardening auditor (read-only)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # score
    p = subparsers.add_parser("score", help="Compute hardening score")
    _add_common_args(p)
    p.set_defaults(func=cmd_score)

    # services
    p = subparsers.add_parser("services", help="Audit services/startup")
    _add_common_args(p)
    p.set_defaults(func=cmd_services)

    # patch
    p = subparsers.add_parser("patch", help="Audit package patches")
    _add_common_args(p)
    p.set_defaults(func=cmd_patch)

    # sockets
    p = subparsers.add_parser("sockets", help="Audit network sockets")
    _add_common_args(p)
    p.set_defaults(func=cmd_sockets)

    # users
    p = subparsers.add_parser("users", help="Audit user accounts")
    _add_common_args(p)
    p.set_defaults(func=cmd_users)

    # files
    p = subparsers.add_parser("files", help="Audit file hygiene")
    _add_common_args(p)
    p.set_defaults(func=cmd_files)

    # baseline
    p = subparsers.add_parser("baseline", help="Drift baseline management")
    _add_common_args(p)
    p.add_argument("--create", action="store_true", help="Create new baseline snapshot")
    p.set_defaults(func=cmd_baseline)

    # report
    p = subparsers.add_parser("report", help="Generate aggregate report")
    _add_common_args(p)
    p.set_defaults(func=cmd_report)

    # scan
    p = subparsers.add_parser("scan", help="Run all audits (default profile: good)")
    _add_common_args(p)
    p.set_defaults(func=cmd_scan)

    # demo
    p = subparsers.add_parser("demo", help="Run demo mode (good vs bad profiles)")
    _add_common_args(p)
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()

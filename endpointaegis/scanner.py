"""Scan orchestrator — runs all auditors against a host profile."""

from __future__ import annotations

from pathlib import Path

from .config import Config
from .scoring import AuditResult, compute_score, summarize_findings
from .auditors import services, patch, sockets, users, files, baseline as baseline_mod
from .reports import generate_json_report, write_json_report, write_html_report, write_markdown_report


def run_all_audits(host_root: Path, config: Config, bl: dict | None = None) -> dict[str, AuditResult]:
    """Run all audit modules against a host profile directory."""
    results: dict[str, AuditResult] = {}
    results["services"] = services.audit_services(host_root, config)
    results["patch"] = patch.audit_patch(host_root, config)
    results["sockets"] = sockets.audit_sockets(host_root, config)
    results["users"] = users.audit_users(host_root, config)
    results["files"] = files.audit_files(host_root, config)
    results["baseline"] = baseline_mod.audit_baseline(host_root, config, baseline=bl)

    # Compute hardening score — these modules contribute to scoring
    score, cat_scores = compute_score(results, config)
    findings_summary = summarize_findings(results)

    return results


def run_scan(host_root: Path, config: Config, profile: str,
             reports_dir: Path, bl: dict | None = None) -> tuple[int, dict, dict, dict]:
    """Full scan: run audits, compute score, generate reports. Returns (score, cat_scores, findings_summary, results)."""
    results = run_all_audits(host_root, config, bl)
    score, cat_scores = compute_score(results, config)
    findings_summary = summarize_findings(results)

    report = generate_json_report(score, cat_scores, results, findings_summary, profile)
    write_json_report(report, reports_dir)
    write_html_report(report, reports_dir)
    write_markdown_report(report, reports_dir)

    return score, cat_scores, findings_summary, results

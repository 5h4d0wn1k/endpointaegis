"""Report generator — HTML + JSON self-contained reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scoring import AuditResult, Finding


def generate_json_report(score: int, category_scores: dict[str, int],
                         results: dict[str, AuditResult], findings_summary: dict[str, int],
                         profile: str) -> dict[str, Any]:
    """Generate JSON report structure."""
    return {
        "tool": "endpointaegis",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "score": score,
        "category_scores": category_scores,
        "findings_summary": findings_summary,
        "modules": {
            name: {
                "passed": r.passed,
                "findings_count": len(r.findings),
                "findings": [
                    {"severity": f.severity, "title": f.title, "detail": f.detail}
                    for f in r.findings
                ],
                "metadata": r.metadata,
            }
            for name, r in results.items()
        },
    }


def write_json_report(report: dict[str, Any], reports_dir: Path) -> Path:
    """Write JSON report to disk."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = reports_dir / f"endpointaegis_{ts}.json"
    path.write_text(json.dumps(report, indent=2))
    return path


def write_html_report(report: dict[str, Any], reports_dir: Path) -> Path:
    """Write self-contained HTML report to disk."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = reports_dir / f"endpointaegis_{ts}.html"
    html = _render_html(report)
    path.write_text(html)
    return path


def render_html_to_string(report: dict[str, Any]) -> str:
    """Render HTML report as string (no file write)."""
    return _render_html(report)


def _render_html(report: dict[str, Any]) -> str:
    """Render self-contained HTML report."""
    score = report["score"]
    profile = report["profile"]
    timestamp = report["timestamp"]
    cat_scores = report.get("category_scores", {})
    findings_summary = report.get("findings_summary", {})
    modules = report.get("modules", {})

    score_color = "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"

    module_rows = ""
    for name, data in modules.items():
        status = "PASS" if data["passed"] else "FAIL"
        status_color = "#22c55e" if data["passed"] else "#ef4444"
        findings_list = ""
        for f in data.get("findings", []):
            sev = f["severity"]
            sev_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
                         "low": "#3b82f6", "info": "#6b7280"}.get(sev, "#6b7280")
            findings_list += f'<div class="finding"><span class="severity" style="background:{sev_color}">{sev}</span> {f["title"]}</div>\n'
        module_rows += f"""
        <div class="module">
            <h3>{name} <span style="color:{status_color}">[{status}]</span></h3>
            {findings_list if findings_list else '<div class="finding info">No findings</div>'}
        </div>"""

    cat_rows = ""
    for cat, val in cat_scores.items():
        cat_rows += f'<div class="cat"><span>{cat}</span><span>{val}</span></div>\n'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>endpointaegis Report — {profile}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }}
.header {{ text-align: center; margin-bottom: 30px; }}
.score-badge {{ display: inline-block; font-size: 48px; font-weight: bold; padding: 20px 40px; border-radius: 12px; background: {score_color}22; color: {score_color}; border: 3px solid {score_color}; margin: 10px; }}
.summary {{ display: flex; gap: 10px; justify-content: center; margin: 20px 0; }}
.summary-item {{ padding: 8px 16px; border-radius: 6px; background: #1e293b; }}
.summary-item span {{ font-weight: bold; }}
.module {{ background: #1e293b; border-radius: 8px; padding: 16px; margin: 10px 0; }}
.module h3 {{ margin: 0 0 10px 0; }}
.finding {{ padding: 4px 8px; margin: 4px 0; border-left: 3px solid #475569; }}
.finding.info {{ border-left-color: #6b7280; }}
.severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; margin-right: 8px; }}
.cat {{ display: flex; justify-content: space-between; padding: 8px; border-bottom: 1px solid #334155; }}
.footer {{ text-align: center; margin-top: 30px; color: #64748b; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
<h1>endpointaegis — Hardening Report</h1>
<div class="score-badge">{score}/100</div>
<p>Profile: <strong>{profile}</strong> | Generated: {timestamp}</p>
</div>
<div class="summary">
<div class="summary-item">Critical: <span style="color:#ef4444">{findings_summary.get('critical', 0)}</span></div>
<div class="summary-item">High: <span style="color:#f97316">{findings_summary.get('high', 0)}</span></div>
<div class="summary-item">Medium: <span style="color:#eab308">{findings_summary.get('medium', 0)}</span></div>
<div class="summary-item">Low: <span style="color:#3b82f6">{findings_summary.get('low', 0)}</span></div>
</div>
<h2>Category Scores</h2>
{cat_rows}
<h2>Module Results</h2>
{module_rows}
<div class="footer">endpointaegis v1.0.0 — read-only host hardening auditor</div>
</body>
</html>"""


def write_markdown_report(report: dict[str, Any], reports_dir: Path) -> Path:
    """Write Markdown summary report."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = reports_dir / f"endpointaegis_{ts}.md"
    score = report["score"]
    profile = report["profile"]
    fs = report.get("findings_summary", {})
    lines = [
        f"# endpointaegis Report — {profile}",
        f"Score: **{score}/100**",
        f"Generated: {report['timestamp']}",
        "",
        "## Findings Summary",
        f"- Critical: {fs.get('critical', 0)}",
        f"- High: {fs.get('high', 0)}",
        f"- Medium: {fs.get('medium', 0)}",
        f"- Low: {fs.get('low', 0)}",
        "",
        "## Category Scores",
    ]
    for cat, val in report.get("category_scores", {}).items():
        lines.append(f"- {cat}: {val}")
    lines.append("")
    lines.append("## Module Details")
    for name, data in report.get("modules", {}).items():
        status = "PASS" if data["passed"] else "FAIL"
        lines.append(f"\n### {name} [{status}]")
        for f in data.get("findings", []):
            lines.append(f"- **{f['severity']}**: {f['title']}")
    path.write_text("\n".join(lines))
    return path

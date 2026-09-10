"""Hardening score calculator — 0-100 from weighted audit findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import Config


@dataclass
class Finding:
    """Single audit finding with severity and category."""

    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    detail: str = ""
    weight: int = 1

    @property
    def penalty(self) -> int:
        return {"critical": 6, "high": 4, "medium": 2, "low": 1, "info": 0}.get(self.severity, 0)


@dataclass
class AuditResult:
    """Result of a single audit module."""

    module: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    passed: bool = True

    def add(self, severity: str, title: str, detail: str = "", weight: int = 1) -> Finding:
        f = Finding(category=self.module, severity=severity, title=title, detail=detail, weight=weight)
        self.findings.append(f)
        if severity in ("critical", "high"):
            self.passed = False
        return f


def compute_score(results: dict[str, AuditResult], config: Config) -> tuple[int, dict[str, int]]:
    """Compute 0-100 hardening score from audit results.

    Returns (score, per_category_scores).
    """
    weights = config.scoring_weights
    total_weight = config.total_weight
    if total_weight == 0:
        return 100, {}

    category_scores: dict[str, int] = {}
    deductions: dict[str, int] = {}

    for module_name, result in results.items():
        cat_weight = weights.get(module_name, 0)
        if cat_weight == 0:
            continue
        cat_penalty = 0
        for f in result.findings:
            cat_penalty += f.penalty * f.weight
        max_penalty = cat_weight
        deduction = min(cat_penalty, max_penalty)
        deductions[module_name] = deduction
        cat_score = max(0, round((1 - deduction / max(max_penalty, 1)) * cat_weight))
        category_scores[module_name] = cat_score

    total_deduction = sum(deductions.values())
    raw_score = max(0, round((1 - total_deduction / max(total_weight, 1)) * 100))
    return min(100, max(0, raw_score)), category_scores


def summarize_findings(results: dict[str, AuditResult]) -> dict[str, int]:
    """Count findings by severity across all modules."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for result in results.values():
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts

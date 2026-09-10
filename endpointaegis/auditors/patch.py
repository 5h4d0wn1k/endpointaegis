"""Patch audit — parse package lists and check against offline advisory table."""

from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..scoring import AuditResult

# Offline advisory: package -> list of (fixed_version, severity, cve)
ADVISORY_TABLE: dict[str, list[tuple[str, str, str]]] = {
    "openssl": [("3.0.13", "critical", "CVE-2024-0001"), ("3.0.12", "high", "CVE-2023-9999")],
    "openssh-server": [("9.6p1", "high", "CVE-2024-1001")],
    "linux-image": [("6.1.76", "critical", "CVE-2024-0002")],
    "sudo": [("1.9.15p5", "high", "CVE-2024-1002")],
    "curl": [("8.6.0", "medium", "CVE-2024-1003")],
    "nginx": [("1.24.0", "medium", "CVE-2024-1004")],
    "apache2": [("2.4.59", "high", "CVE-2024-1005")],
    "glibc": [("2.38-4", "critical", "CVE-2024-0003")],
    "systemd": [("255.4", "medium", "CVE-2024-1006")],
    "python3": [("3.11.8", "low", "CVE-2024-1007")],
}


def audit_patch(host_root: Path, config: Config) -> AuditResult:
    """Audit package versions against the offline advisory table."""
    result = AuditResult(module="patch")
    packages = _parse_packages(host_root)
    result.metadata["packages_found"] = len(packages)

    missing_critical = 0
    missing_high = 0
    missing_medium = 0

    for pkg_name, advisories in ADVISORY_TABLE.items():
        installed_ver = packages.get(pkg_name)
        if installed_ver is None:
            continue
        for fixed_ver, severity, cve in advisories:
            if _is_vulnerable(installed_ver, fixed_ver):
                result.add(severity, f"{pkg_name} {installed_ver} needs update to {fixed_ver}",
                           f"{cve} — installed {installed_ver}, fixed in {fixed_ver}", weight=2)
                if severity == "critical":
                    missing_critical += 1
                elif severity == "high":
                    missing_high += 1
                elif severity == "medium":
                    missing_medium += 1

    for pkg_name, advisories in ADVISORY_TABLE.items():
        if pkg_name not in packages:
            for fixed_ver, severity, cve in advisories:
                if severity in ("critical", "high"):
                    result.add("medium", f"Package {pkg_name} not installed (advisory exists)",
                               f"{cve} — {pkg_name} advisory present but package absent", weight=1)

    result.metadata["missing_critical"] = missing_critical
    result.metadata["missing_high"] = missing_high
    result.metadata["missing_medium"] = missing_medium

    if missing_critical == 0 and missing_high == 0:
        result.add("info", "No critical or high missing patches")
    return result


def _parse_packages(host_root: Path) -> dict[str, str]:
    """Parse dpkg/apk-style package list from fixture."""
    packages: dict[str, str] = {}
    pkg_file = host_root / "etc" / "installed_packages.txt"
    if not pkg_file.exists():
        return packages
    for line in pkg_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) == 2:
            packages[parts[0]] = parts[1]
    return packages


def _is_vulnerable(installed: str, fixed: str) -> bool:
    """Simple version comparison — is installed < fixed?"""
    def _parse_ver(v: str) -> list[int]:
        nums = re.findall(r"\d+", v)
        return [int(n) for n in nums] if nums else [0]
    iv = _parse_ver(installed)
    fv = _parse_ver(fixed)
    max_len = max(len(iv), len(fv))
    iv.extend([0] * (max_len - len(iv)))
    fv.extend([0] * (max_len - len(fv)))
    return iv < fv

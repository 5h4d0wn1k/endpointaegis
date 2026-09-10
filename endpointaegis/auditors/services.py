"""Service/startup audit — parse unit files and autostart entries."""

from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..scoring import AuditResult


def audit_services(host_root: Path, config: Config) -> AuditResult:
    """Audit running services and persistent startup from fixture data."""
    result = AuditResult(module="services")
    unit_files = _find_unit_files(host_root)
    autostart = _find_autostart(host_root)

    for uf in unit_files:
        content = uf.read_text(errors="replace")
        if _is_suspicious_unit(uf.name, content, config):
            result.add("high", f"Suspicious unit file: {uf.name}",
                        f"Unit {uf.name} at {uf} matches suspicious pattern", weight=2)
        if "WantedBy=multi-user.target" in content or "WantedBy=graphical.target" in content:
            result.metadata.setdefault("enabled_units", []).append(uf.name)

    for ae in autostart:
        content = ae.read_text(errors="replace") if ae.is_file() else ""
        if _is_suspicious_autostart(ae.name, content, config):
            result.add("high", f"Suspicious autostart: {ae.name}",
                        f"Autostart entry {ae.name} flagged", weight=2)

    if not unit_files and not autostart:
        result.add("info", "No service/startup entries found in fixture")

    result.metadata["unit_count"] = len(unit_files)
    result.metadata["autostart_count"] = len(autostart)
    return result


def _find_unit_files(host_root: Path) -> list[Path]:
    """Find systemd-like unit files in the fixture."""
    candidates = []
    for search_dir in [
        host_root / "etc" / "systemd" / "system",
        host_root / "usr" / "lib" / "systemd" / "system",
    ]:
        if search_dir.is_dir():
            candidates.extend(search_dir.glob("*.service"))
            candidates.extend(search_dir.glob("*.timer"))
    return candidates


def _find_autostart(host_root: Path) -> list[Path]:
    """Find autostart/cron-like entries in the fixture."""
    candidates = []
    for search_dir in [
        host_root / "etc" / "cron.d",
        host_root / "etc" / "crontab",
        host_root / "var" / "spool" / "cron" / "crontabs",
    ]:
        p = Path(search_dir)
        if p.is_dir():
            candidates.extend(p.iterdir())
        elif p.is_file():
            candidates.append(p)
    return candidates


def _is_suspicious_unit(name: str, content: str, config: Config) -> bool:
    """Check if a unit file looks suspicious."""
    name_lower = name.lower()
    for pattern in config.suspicious_service_patterns:
        if pattern in name_lower:
            return True
    exec_match = re.search(r"ExecStart\s*=\s*(.+)", content)
    if exec_match:
        exec_path = exec_match.group(1).strip().split()[0]
        for pat in config.suspicious_path_patterns:
            if pat in exec_path:
                return True
    return False


def _is_suspicious_autostart(name: str, content: str, config: Config) -> bool:
    """Check if an autostart entry looks suspicious."""
    for pat in config.suspicious_path_patterns:
        if pat in content:
            return True
    if re.search(r"curl\s|wget\s|nc\s|ncat\s|python\s|perl\s|ruby\s", content):
        return True
    return False

"""Drift baseline — snapshot golden profile at T0, detect changes at T1."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..config import Config
from ..scoring import AuditResult


def create_baseline(host_root: Path) -> dict:
    """Create a baseline snapshot of a host profile at T0."""
    snapshot = {
        "files": _snapshot_files(host_root),
        "services": _snapshot_services(host_root),
        "users": _snapshot_users(host_root),
    }
    return snapshot


def audit_baseline(host_root: Path, config: Config, baseline: dict | None = None) -> AuditResult:
    """Compare current state against baseline (T0) and flag drift (T1)."""
    result = AuditResult(module="baseline")

    if baseline is None:
        result.add("info", "No baseline provided — use 'baseline' command to create one")
        return result

    current = {
        "files": _snapshot_files(host_root),
        "services": _snapshot_services(host_root),
        "users": _snapshot_users(host_root),
    }

    # File drift
    base_files = set(baseline.get("files", {}).keys())
    curr_files = set(current["files"].keys())
    added = curr_files - base_files
    removed = base_files - curr_files
    modified = {f for f in (base_files & curr_files)
                if baseline["files"][f] != current["files"][f]}

    for f in sorted(added):
        result.add("high", f"File added since baseline: {f}", weight=2)
    for f in sorted(removed):
        result.add("medium", f"File removed since baseline: {f}", weight=1)
    for f in sorted(modified):
        result.add("high", f"File modified since baseline: {f}", weight=2)

    # Service drift
    base_svcs = set(baseline.get("services", {}).keys())
    curr_svcs = set(current["services"].keys())
    added_svcs = curr_svcs - base_svcs
    removed_svcs = base_svcs - curr_svcs

    for s in sorted(added_svcs):
        result.add("high", f"Service added since baseline: {s}", weight=2)
    for s in sorted(removed_svcs):
        result.add("medium", f"Service removed since baseline: {s}", weight=1)

    # User drift
    base_users = set(baseline.get("users", {}).keys())
    curr_users = set(current["users"].keys())
    added_users = curr_users - base_users

    for u in sorted(added_users):
        result.add("high", f"User added since baseline: {u}", weight=3)

    result.metadata["files_added"] = len(added)
    result.metadata["files_removed"] = len(removed)
    result.metadata["files_modified"] = len(modified)
    result.metadata["services_added"] = len(added_svcs)
    result.metadata["services_removed"] = len(removed_svcs)
    result.metadata["users_added"] = len(added_users)

    if not result.findings:
        result.add("info", "No drift detected since baseline")

    return result


def _snapshot_files(host_root: Path) -> dict[str, str]:
    """Snapshot file hashes for drift detection."""
    files = {}
    for search_dir in [host_root / "etc", host_root / "usr", host_root / "var"]:
        if not search_dir.exists():
            continue
        for fpath in search_dir.rglob("*"):
            if fpath.is_file():
                rel = str(fpath.relative_to(host_root))
                try:
                    h = hashlib.sha256(fpath.read_bytes()).hexdigest()[:16]
                except Exception:
                    h = "unreadable"
                files[rel] = h
    return files


def _snapshot_services(host_root: Path) -> dict[str, str]:
    """Snapshot service state."""
    services = {}
    unit_dir = host_root / "etc" / "systemd" / "system"
    if unit_dir.exists():
        for f in unit_dir.iterdir():
            if f.suffix == ".service":
                try:
                    content = f.read_text(errors="replace")
                    enabled = "WantedBy=" in content
                except Exception:
                    enabled = False
                services[f.name] = "enabled" if enabled else "disabled"
    return services


def _snapshot_users(host_root: Path) -> dict[str, dict]:
    """Snapshot user entries."""
    users = {}
    passwd_file = host_root / "etc" / "passwd"
    if passwd_file.exists():
        for line in passwd_file.read_text().splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3:
                users[parts[0]] = {"uid": parts[2], "shell": parts[6] if len(parts) > 6 else ""}
    return users


def save_baseline(baseline: dict, path: Path) -> None:
    """Save baseline to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2))


def load_baseline(path: Path) -> dict | None:
    """Load baseline from JSON."""
    if not path.exists():
        return None
    return json.loads(path.read_text())

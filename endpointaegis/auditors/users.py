"""User audit — check passwd, shadow, sudoers fixtures."""

from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..scoring import AuditResult


def audit_users(host_root: Path, config: Config) -> AuditResult:
    """Audit user accounts from fixture data."""
    result = AuditResult(module="users")

    shadow_entries = _parse_shadow(host_root)
    passwd_entries = _parse_passwd(host_root)
    sudoers_entries = _parse_sudoers(host_root)

    result.metadata["user_count"] = len(passwd_entries)
    result.metadata["shadow_entries"] = len(shadow_entries)

    # Empty password check
    for entry in shadow_entries:
        pw_field = entry.get("password", "")
        if pw_field in ("!", "!!", "*"):
            continue
        if pw_field == "":
            result.add("critical", f"Empty password for user '{entry['username']}'",
                        f"User {entry['username']} has an empty password hash", weight=3)

    # UID 0 non-root check
    for entry in passwd_entries:
        if entry.get("uid") == 0 and entry.get("username") != "root":
            result.add("critical", f"Non-root UID 0: {entry['username']}",
                        f"User {entry['username']} has UID 0 but is not root", weight=3)

    # Sudoers broad rules
    for line in sudoers_entries:
        if "ALL=(ALL:ALL) ALL" in line or "ALL=(ALL) ALL" in line:
            username = line.split()[0] if line.split() else "unknown"
            if username not in ("root", "#", "Defaults"):
                result.add("high", f"Passwordless sudo for '{username}'",
                           f"Line: {line.strip()}", weight=2)

    # World-writable home directories
    home_dirs = _check_home_perms(host_root)
    for hd in home_dirs:
        result.add("medium", f"World-writable home directory: {hd['path']}",
                   f"Permissions: {hd['perms']}", weight=1)

    if not result.findings:
        result.add("info", "No user-related issues found")

    return result


def _parse_shadow(host_root: Path) -> list[dict]:
    """Parse shadow-like fixture."""
    entries = []
    shadow_file = host_root / "etc" / "shadow"
    if not shadow_file.exists():
        return entries
    for line in shadow_file.read_text().splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 2:
            entries.append({
                "username": parts[0],
                "password": parts[1],
                "last_changed": parts[2] if len(parts) > 2 else "",
            })
    return entries


def _parse_passwd(host_root: Path) -> list[dict]:
    """Parse passwd-like fixture."""
    entries = []
    passwd_file = host_root / "etc" / "passwd"
    if not passwd_file.exists():
        return entries
    for line in passwd_file.read_text().splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 7:
            try:
                uid = int(parts[2])
            except ValueError:
                continue
            entries.append({
                "username": parts[0],
                "uid": uid,
                "gid": int(parts[3]) if parts[3].isdigit() else 0,
                "home": parts[5],
                "shell": parts[6],
            })
    return entries


def _parse_sudoers(host_root: Path) -> list[str]:
    """Parse sudoers-like fixture."""
    lines = []
    sudoers_file = host_root / "etc" / "sudoers"
    if not sudoers_file.exists():
        return lines
    for line in sudoers_file.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def _check_home_perms(host_root: Path) -> list[dict]:
    """Check home directory permissions from fixture."""
    bad = []
    perms_file = host_root / "etc" / "home_perms.txt"
    if not perms_file.exists():
        return bad
    for line in perms_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            perms, path = parts[0], parts[1]
            if perms.endswith("7") or perms.endswith("3") or perms.endswith("777"):
                bad.append({"path": path, "perms": perms})
    return bad

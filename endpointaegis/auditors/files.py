"""File hygiene scan — world-writable executables, SUID, dotfile perms, secrets scan."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..config import Config
from ..scoring import AuditResult

AKIA = "AKIA"
XOXB = "xoxb-"
GHP = "ghp_"
SK_LIVE = "sk_live_"
JWT_HEAD = "eyJ"

SECRET_PATTERNS = [
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key"),
    (AKIA + r"[0-9A-Z]{16}", "AWS access key"),
    (XOXB + r"[0-9]+-[0-9]+-[a-zA-Z0-9]+", "Slack bot token"),
    (GHP + r"[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (SK_LIVE + r"[a-zA-Z0-9]+", "Stripe live secret key"),
    (JWT_HEAD + r"[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT token"),
]


def audit_files(host_root: Path, config: Config) -> AuditResult:
    """Audit file hygiene from fixture data."""
    result = AuditResult(module="files")
    _check_world_writable(host_root, result)
    _check_suid(host_root, config, result)
    _check_dotfile_perms(host_root, result)
    _check_secrets(host_root, result)
    return result


def _check_world_writable(host_root: Path, result: AuditResult) -> None:
    """Find world-writable executables in fixture."""
    perms_file = host_root / "etc" / "file_perms.txt"
    if not perms_file.exists():
        result.add("info", "No file permission data in fixture")
        return
    count = 0
    for line in perms_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        perms, ftype, fpath = parts[0], parts[1], parts[2]
        if ftype == "exe" and (perms.endswith("7") or "w" in _octal_to_rwx(perms)[-3:]):
            count += 1
            if count <= 5:
                result.add("high", f"World-writable executable: {fpath}",
                           f"Permissions: {perms}", weight=2)
    if count > 5:
        result.add("high", f"... and {count - 5} more world-writable executables", weight=1)


def _check_suid(host_root: Path, config: Config, result: AuditResult) -> None:
    """Check for SUID binaries outside allowlist."""
    perms_file = host_root / "etc" / "file_perms.txt"
    if not perms_file.exists():
        return
    suid_count = 0
    for line in perms_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        perms, ftype, fpath = parts[0], parts[1], parts[2]
        is_suid = (ftype == "suid") or (len(perms) >= 4 and perms[0] == "4") or (len(perms) >= 4 and perms[3] == "s")
        if is_suid:
            if fpath not in config.suid_allowlist:
                suid_count += 1
                result.add("high", f"SUID binary outside allowlist: {fpath}",
                           f"Permissions: {perms}", weight=2)
    if suid_count == 0:
        result.add("info", "No SUID anomalies found")


def _check_dotfile_perms(host_root: Path, result: AuditResult) -> None:
    """Check dotfile permissions in home directories."""
    dotfiles_file = host_root / "etc" / "dotfile_perms.txt"
    if not dotfiles_file.exists():
        return
    for line in dotfiles_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        perms, fpath = parts[0], parts[1]
        if "w" in _octal_to_rwx(perms)[-3:]:
            result.add("medium", f"World-writable dotfile: {fpath}",
                       f"Permissions: {perms}", weight=1)


PRIVATE_KEY_FILENAMES = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
)


def _check_secrets(host_root: Path, result: AuditResult) -> None:
    """Scan for secrets in home directory fixtures."""
    home_dir = host_root / "var" / "home"
    if not home_dir.exists():
        return
    for fpath in home_dir.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.name in PRIVATE_KEY_FILENAMES:
            result.add("critical", f"Secret found in {fpath}: Private key file",
                       f"File: {fpath}", weight=3)
            continue
        try:
            content = fpath.read_text(errors="replace")[:8192]
        except Exception:
            continue
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, content):
                result.add("critical", f"Secret found in {fpath}: {label}",
                           f"File: {fpath}", weight=3)
                break


def _octal_to_rwx(perms: str) -> str:
    """Convert octal permission string to rwx format."""
    if len(perms) < 3:
        return perms
    try:
        last3 = perms[-3:]
        rwx = ""
        for c in last3:
            v = int(c)
            rwx += "r" if v & 4 else "-"
            rwx += "w" if v & 2 else "-"
            rwx += "x" if v & 1 else "-"
        return rwx
    except (ValueError, IndexError):
        return perms

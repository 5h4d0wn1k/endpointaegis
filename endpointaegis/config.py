"""Configuration loader — YAML/JSON config files."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

_DEFAULT_CONFIG = {
    "version": "1.0.0",
    "fixtures_root": "tests/fixtures/hosts",
    "default_profile": "good",
    "reports_dir": "reports",
    "scoring_weights": {
        "services": 14,
        "patch": 14,
        "sockets": 14,
        "users": 14,
        "files": 13,
        "baseline": 31,
    },
    "high_risk_ports": [22, 23, 3389, 445, 135, 139, 5900, 6379, 27017, 3306, 5432],
    "suid_allowlist": [
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
        "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd",
        "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    ],
    "suspicious_service_patterns": [
        "update-", "systemd-", "kworker-", "migration-", "watchdog-",
    ],
    "suspicious_path_patterns": ["/tmp/", "/dev/shm/", "/var/tmp/"],
}


@dataclass
class Config:
    """Merged configuration from defaults + file overrides."""

    fixtures_root: str = "tests/fixtures/hosts"
    default_profile: str = "good"
    reports_dir: str = "reports"
    scoring_weights: dict[str, int] = field(default_factory=lambda: dict(_DEFAULT_CONFIG["scoring_weights"]))
    high_risk_ports: list[int] = field(default_factory=lambda: list(_DEFAULT_CONFIG["high_risk_ports"]))
    suid_allowlist: list[str] = field(default_factory=lambda: list(_DEFAULT_CONFIG["suid_allowlist"]))
    suspicious_service_patterns: list[str] = field(default_factory=lambda: list(_DEFAULT_CONFIG["suspicious_service_patterns"]))
    suspicious_path_patterns: list[str] = field(default_factory=lambda: list(_DEFAULT_CONFIG["suspicious_path_patterns"]))
    live_system: bool = False
    dry_run: bool = True

    @property
    def total_weight(self) -> int:
        return sum(self.scoring_weights.values())


def load_config(path: str | Path | None = None) -> Config:
    """Load config from YAML or JSON file, falling back to defaults."""
    cfg = Config()
    if path is None:
        return cfg
    p = Path(path)
    if not p.exists():
        return cfg
    raw: Any
    if p.suffix in (".yaml", ".yml"):
        if not HAS_YAML:
            raise ImportError("PyYAML required for .yaml/.yml config files")
        with open(p) as f:
            raw = yaml.safe_load(f)
    else:
        with open(p) as f:
            raw = json.load(f)
    if not isinstance(raw, dict):
        return cfg
    if "fixtures_root" in raw:
        cfg.fixtures_root = raw["fixtures_root"]
    if "default_profile" in raw:
        cfg.default_profile = raw["default_profile"]
    if "reports_dir" in raw:
        cfg.reports_dir = raw["reports_dir"]
    if "scoring_weights" in raw and isinstance(raw["scoring_weights"], dict):
        cfg.scoring_weights.update(raw["scoring_weights"])
    if "high_risk_ports" in raw:
        cfg.high_risk_ports = raw["high_risk_ports"]
    if "suid_allowlist" in raw:
        cfg.suid_allowlist = raw["suid_allowlist"]
    if "suspicious_service_patterns" in raw:
        cfg.suspicious_service_patterns = raw["suspicious_service_patterns"]
    if "suspicious_path_patterns" in raw:
        cfg.suspicious_path_patterns = raw["suspicious_path_patterns"]
    return cfg

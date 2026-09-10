"""Network/socket audit — parse netstat/ss-like output for listening ports."""

from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..scoring import AuditResult


def audit_sockets(host_root: Path, config: Config) -> AuditResult:
    """Audit network listeners from fixture netstat/ss data."""
    result = AuditResult(module="sockets")
    entries = _parse_netstat(host_root)
    result.metadata["total_listeners"] = len(entries)

    dangerous = []
    for entry in entries:
        bind_addr = entry.get("local_address", "")
        port = entry.get("port", 0)
        proc = entry.get("process", "unknown")

        if bind_addr in ("0.0.0.0", "*", "::") and port in config.high_risk_ports:
            dangerous.append(entry)
            result.add("high",
                        f"High-risk service on 0.0.0.0:{port}",
                        f"Process '{proc}' listening on all interfaces port {port} — "
                        f"exposes service to network", weight=2)
        elif bind_addr in ("0.0.0.0", "*", "::"):
            result.add("medium",
                        f"Service on 0.0.0.0:{port}",
                        f"Process '{proc}' listening on all interfaces port {port}", weight=1)

    result.metadata["dangerous_count"] = len(dangerous)

    if not dangerous and entries:
        result.add("info", "No high-risk exposed services found")
    elif not entries:
        result.add("info", "No network listener data in fixture")

    return result


def _parse_netstat(host_root: Path) -> list[dict]:
    """Parse netstat/ss-like output from fixture."""
    entries = []
    for fname in ("netstat.txt", "ss_output.txt"):
        fpath = host_root / "proc" / fname
        if not fpath.exists():
            continue
        for line in fpath.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("Active") or line.startswith("Proto") or line.startswith("Netid"):
                continue
            parsed = _parse_net_line(line)
            if parsed and parsed.get("state") in ("LISTEN", "LISTENING"):
                entries.append(parsed)
    return entries


def _parse_net_line(line: str) -> dict | None:
    """Parse a single netstat or ss line."""
    parts = line.split()
    if len(parts) < 4:
        return None

    # netstat format: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
    if re.match(r"^(tcp|tcp6|udp|udp6)", parts[0]):
        local = parts[3] if len(parts) > 3 else ""
        state = parts[5] if len(parts) > 5 else ""
        pid_info = parts[6] if len(parts) > 6 else ""

        match = re.match(r"(.+):(\d+)", local)
        if match:
            addr, port = match.group(1), int(match.group(2))
            process = pid_info.split("/")[-1] if "/" in pid_info else "unknown"
            return {"local_address": addr, "port": port, "process": process, "state": state, "raw": line}

    return None

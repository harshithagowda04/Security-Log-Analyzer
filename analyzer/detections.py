"""Configurable, deterministic rules for SSH and Apache events."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import unquote
from .parsers import Event

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
@dataclass
class AnalyzerConfig:
    ssh_fail_threshold: int = 5
    ssh_window_seconds: int = 60
    compromise_correlation_seconds: int = 900
    invalid_user_threshold: int = 4
    http_404_threshold: int = 8
    http_window_seconds: int = 60

@dataclass
class Alert:
    timestamp: object
    source_ip: str
    event_type: str
    severity: str
    details: str

def _sliding_groups(events: list[Event], threshold: int, seconds: int):
    """Return qualifying unique event groups; overlapping windows collapse into one incident."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    groups, start = [], 0
    for end, event in enumerate(ordered):
        while ordered[end].timestamp.timestamp() - ordered[start].timestamp.timestamp() > seconds:
            start += 1
        if end - start + 1 >= threshold:
            group = ordered[start:end + 1]
            if not groups or group[0].timestamp.timestamp() > groups[-1][-1].timestamp.timestamp() + seconds:
                groups.append(group)
            else:
                groups[-1] = sorted({id(x): x for x in groups[-1] + group}.values(), key=lambda e: e.timestamp)
    return groups

def _attack_kind(text: str) -> str | None:
    # Decode a bounded number of times to catch nested encoding without unbounded work.
    value = text[:8192]
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value: break
        value = decoded
    value = value.lower()
    patterns = [
        ("SQL injection", r"(?:'|%27)\s*(?:or|and)\s+['\d]|\bunion\s+(?:all\s+)?select\b|\bsleep\s*\(|\b--\s"),
        ("cross-site scripting (XSS)", r"<\s*script\b|javascript\s*:|onerror\s*=|onload\s*="),
        ("path traversal", r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)"),
    ]
    for name, pattern in patterns:
        if re.search(pattern, value, re.I): return name
    return None

def analyze_events(events: list[Event], config: AnalyzerConfig | None = None) -> list[Alert]:
    cfg = config or AnalyzerConfig()
    by_ip = defaultdict(list)
    for event in events: by_ip[event.source_ip].append(event)
    alerts: list[Alert] = []
    for ip, items in by_ip.items():
        failed = [e for e in items if e.event_type == "ssh_failed"]
        invalid = [e for e in items if e.event_type == "ssh_invalid_user"]
        for group in _sliding_groups(failed, cfg.ssh_fail_threshold, cfg.ssh_window_seconds):
            alerts.append(Alert(group[-1].timestamp, ip, "SSH brute-force", "HIGH",
                                f"{len(group)} failed SSH attempts within {cfg.ssh_window_seconds}s; usernames: {', '.join(sorted({e.username for e in group if e.username})) or 'unknown'}"))
        # Enumeration is counted by distinct invalid-user events for the IP (not per window).
        if len(invalid) >= cfg.invalid_user_threshold:
            alerts.append(Alert(max(e.timestamp for e in invalid), ip, "SSH username enumeration", "MEDIUM",
                                f"{len(invalid)} invalid username attempts; names: {', '.join(sorted({e.username for e in invalid if e.username}))}"))
        qualifying = _sliding_groups(failed, cfg.ssh_fail_threshold, cfg.ssh_window_seconds)
        for success in (e for e in items if e.event_type == "ssh_success"):
            prior_group = next((g for g in reversed(qualifying) if 0 <= (success.timestamp - g[-1].timestamp).total_seconds() <= cfg.compromise_correlation_seconds), None)
            if prior_group:
                alerts.append(Alert(success.timestamp, ip, "Possible SSH compromise", "CRITICAL",
                                    f"Successful login for {success.username or 'unknown'} followed {len(prior_group)} failed attempts within {cfg.ssh_window_seconds}s; success occurred within {cfg.compromise_correlation_seconds}s. Failures: " + "; ".join(e.details for e in prior_group) + f"; success: {success.details}"))
        misses = [e for e in items if e.event_type == "http_request" and e.status == 404]
        for group in _sliding_groups(misses, cfg.http_404_threshold, cfg.http_window_seconds):
            alerts.append(Alert(group[-1].timestamp, ip, "Directory scanning", "MEDIUM",
                                f"{len(group)} HTTP 404 responses within {cfg.http_window_seconds}s"))
        for event in items:
            if event.event_type != "http_request": continue
            detected = _attack_kind(event.url + " " + event.details)
            if detected:
                alerts.append(Alert(event.timestamp, ip, f"Web attack signature: {detected}", "HIGH", f"Matched {detected} pattern in {event.method} request (HTTP {event.status}). URL: {event.url[:300]}"))
    # Collapse duplicate same-type same-IP detections at same incident time and enforce stable sorting.
    unique = {(a.timestamp, a.source_ip, a.event_type, a.severity): a for a in alerts}
    return sorted(unique.values(), key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.timestamp, a.source_ip, a.event_type))

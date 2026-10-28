"""Tolerant parsers for Linux SSH auth logs and Apache access logs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

SYSLOG_RE = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$")
APACHE_RE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<stamp>[^]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+\S+(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?')

@dataclass
class Event:
    timestamp: datetime
    source_ip: str
    event_type: str
    username: str = ""
    method: str = ""
    url: str = ""
    status: int | None = None
    details: str = ""

@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    skipped: int = 0
    parsed: int = 0

def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

def parse_auth_lines(lines: Iterable[str], year: int | None = None) -> ParseResult:
    """Parse common sshd messages; yearless syslog timestamps use configured/local year."""
    year = year or datetime.now().year
    result = ParseResult()
    for raw in lines:
        line = raw.rstrip("\r\n")
        m = SYSLOG_RE.match(line)
        if not m:
            result.skipped += 1
            continue
        msg = m["msg"]
        try:
            stamp = datetime.strptime(f'{year} {m["stamp"]}', "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            result.skipped += 1
            continue
        ipm = re.search(r"(?:from\s+|rhost=)([0-9a-fA-F:.]+)", msg)
        if not ipm:
            result.skipped += 1
            continue
        ip = ipm.group(1)
        userm = re.search(r"invalid user\s+([^\s]+)", msg, re.I) or re.search(r"(?:user|for)\s+([^\s]+)", msg, re.I)
        username = userm.group(1) if userm else ""
        low = msg.lower()
        if "failed password" in low or "authentication failure" in low:
            result.parsed += 1
            kind = "ssh_failed"
            result.events.append(Event(stamp, ip, kind, username=username, details=msg))
            if "invalid user" in low:
                result.events.append(Event(stamp, ip, "ssh_invalid_user", username=username, details=msg))
            continue
        elif "accepted password" in low or "accepted publickey" in low or "accepted keyboard-interactive" in low:
            kind = "ssh_success"
        elif "invalid user" in low:
            kind = "ssh_invalid_user"
        else:
            result.skipped += 1
            continue
        result.parsed += 1
        result.events.append(Event(stamp, ip, kind, username=username, details=msg))
    return result

def parse_apache_lines(lines: Iterable[str]) -> ParseResult:
    result = ParseResult()
    for raw in lines:
        line = raw.rstrip("\r\n")
        m = APACHE_RE.match(line)
        if not m:
            result.skipped += 1
            continue
        try:
            stamp = _aware(datetime.strptime(m["stamp"], "%d/%b/%Y:%H:%M:%S %z"))
            parts = m["request"].split()
            method, url = (parts[0], parts[1]) if len(parts) >= 2 else ("", "")
            result.parsed += 1
            fields = "; ".join(f"{name}={m[name]}" for name in ("referer", "agent") if m[name])
            result.events.append(Event(stamp, m["ip"], "http_request", method=method, url=url,
                                       status=int(m["status"]), details=f'{method} {url} -> {m["status"]}' + (f"; {fields}" if fields else "")))
        except (ValueError, IndexError):
            result.skipped += 1
    return result

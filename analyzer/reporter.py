"""CSV and human-readable report generation."""
import csv
from collections import Counter
from pathlib import Path
from .detections import Alert, SEVERITY_ORDER

FIELDS = ["timestamp", "source_ip", "event_type", "severity", "details"]
def write_reports(alerts: list[Alert], output: Path, *, ssh_total: int, ssh_parsed: int, ssh_skipped: int,
                  web_total: int, web_parsed: int, web_skipped: int, period=None) -> tuple[Path, Path]:
    output.mkdir(parents=True, exist_ok=True)
    alerts = sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.timestamp, a.source_ip))
    csv_path, txt_path = output / "alerts.csv", output / "security_report.txt"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS); writer.writeheader()
        for a in alerts: writer.writerow({"timestamp": a.timestamp.isoformat(), "source_ip": a.source_ip, "event_type": a.event_type, "severity": a.severity, "details": a.details})
    all_dates = list(period) if period else [a.timestamp for a in alerts]
    counts = Counter(a.severity for a in alerts)
    lines = ["SECURITY LOG ANALYSIS REPORT", "=" * 28,
             f"Analysis period: {min(all_dates).isoformat()} to {max(all_dates).isoformat()}" if all_dates else "Analysis period: no recognized events",
             f"SSH lines: {ssh_total} total, {ssh_parsed} parsed, {ssh_skipped} skipped",
             f"Apache lines: {web_total} total, {web_parsed} parsed, {web_skipped} skipped",
             f"Alerts: {len(alerts)} total (CRITICAL {counts['CRITICAL']}, HIGH {counts['HIGH']}, MEDIUM {counts['MEDIUM']}, LOW {counts['LOW']})", ""]
    if alerts:
        lines.append("ALERT DETAILS")
        for a in alerts: lines.append(f"[{a.severity}] {a.timestamp.isoformat()} | {a.source_ip} | {a.event_type}\n  {a.details}")
    else: lines.append("No suspicious activity detected by the configured rules. Review skipped lines and retain analyst oversight.")
    lines += ["", "RECOMMENDED DEFENSIVE ACTIONS", "- SSH brute-force: investigate source IPs; consider firewall restrictions or rate limiting, Fail2ban, SSH keys, and disabling password authentication where appropriate.", "- Suspected compromise: review authentication history and affected accounts, rotate credentials or keys as needed, and follow incident response procedures.", "- Web attacks: review application logs, use parameterized SQL, validate input, encode output, and consider a suitable web application firewall.", "- Recommendations only: this tool does not change systems or block traffic.", "- Rule-based detections need analyst verification; benign patterns and incomplete logs can affect results."]
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return csv_path, txt_path

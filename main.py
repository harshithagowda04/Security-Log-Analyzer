"""Command-line entry point for the Security Log Analyzer."""
import argparse
from datetime import datetime
from pathlib import Path
from analyzer.parsers import parse_auth_lines, parse_apache_lines
from analyzer.detections import AnalyzerConfig, analyze_events
from analyzer.reporter import write_reports

def _read(path: Path, kind: str, max_bytes: int = 20_000_000):
    if not path.exists() or not path.is_file(): raise ValueError(f"{kind} log does not exist or is not a file: {path}")
    if path.stat().st_size > max_bytes: raise ValueError(f"{kind} log exceeds the 20 MB safety limit")
    return path.read_text(encoding="utf-8", errors="replace").splitlines()

def run(ssh: Path | None, web: Path | None, output: Path, year: int, config: AnalyzerConfig | None = None):
    auth_lines = _read(ssh, "SSH") if ssh else []
    web_lines = _read(web, "Apache") if web else []
    auth = parse_auth_lines(auth_lines, year=year) if ssh else None
    apache = parse_apache_lines(web_lines) if web else None
    events = (auth.events if auth else []) + (apache.events if apache else [])
    alerts = analyze_events(events, config)
    paths = write_reports(alerts, output,
        ssh_total=len(auth_lines), ssh_parsed=auth.parsed if auth else 0, ssh_skipped=auth.skipped if auth else 0,
        web_total=len(web_lines), web_parsed=apache.parsed if apache else 0, web_skipped=apache.skipped if apache else 0,
        period=[event.timestamp for event in events])
    parsed_lines = (auth.parsed if auth else 0) + (apache.parsed if apache else 0)
    print(f"Analyzed {len(auth_lines)+len(web_lines)} lines; parsed {parsed_lines} lines; generated {len(alerts)} alerts.")
    print(f"CSV: {paths[0]}\nReport: {paths[1]}")
    if not alerts: print("No suspicious activity detected by the configured rules.")
    return alerts

def main():
    parser = argparse.ArgumentParser(description="Analyze synthetic or authorized SSH and Apache logs locally.")
    parser.add_argument("--ssh", type=Path, help="Linux auth.log/syslog input")
    parser.add_argument("--web", type=Path, help="Apache combined/common access log input")
    parser.add_argument("--output", type=Path, default=Path("reports"), help="Output directory (default: reports)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Year for yearless auth.log timestamps")
    parser.add_argument("--ssh-threshold", type=int, default=5)
    parser.add_argument("--ssh-window", type=int, default=60)
    parser.add_argument("--correlation-seconds", type=int, default=900)
    parser.add_argument("--invalid-user-threshold", type=int, default=4)
    parser.add_argument("--web-404-threshold", type=int, default=8)
    args = parser.parse_args()
    if not args.ssh and not args.web: parser.error("provide at least one of --ssh or --web")
    if min(args.ssh_threshold, args.ssh_window, args.correlation_seconds, args.invalid_user_threshold, args.web_404_threshold) < 1:
        parser.error("thresholds and time windows must be positive")
    try:
        run(args.ssh, args.web, args.output, args.year, AnalyzerConfig(args.ssh_threshold, args.ssh_window, args.correlation_seconds, args.invalid_user_threshold, args.web_404_threshold))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
if __name__ == "__main__": main()

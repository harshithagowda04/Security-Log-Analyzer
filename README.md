# Security Log Analyzer & Suspicious Activity Detector

A beginner-friendly, offline Python tool for examining Linux SSH authentication logs and Apache access logs. It applies transparent rules, creates CSV and text reports, and includes an optional local Flask dashboard. It does not contact external systems or take remediation actions.

All checked-in logs are synthetic, use documentation-only IP ranges, and contain fictional account names. Use real logs only when you are authorized to analyze them; this tool reads the supplied files and does not change them.

## Features

- SSH brute-force, possible compromise, invalid username enumeration, 404 scanning, and common web attack signatures.
- Year-aware, timezone-aware event parsing; malformed lines are counted and skipped.
- Configurable thresholds, stable severity sorting, and deduplication of overlapping windows.
- CSV and TXT reports, CLI, reproducible sample generator, tests, and optional local dashboard.

## Requirements and installation

Python 3.10 or newer is recommended. The CLI and analysis core use only the standard library. For the optional dashboard install Flask:

```sh
python -m pip install -r requirements.txt
```

## Project layout

```text
analyzer/       parsers, detection rules, report writer
dashboard/      optional Flask UI and static assets
logs/           synthetic demonstration logs
reports/        generated CSV and text output
tests/          unittest suite
main.py         command-line interface
generate_logs.py reproducible sample generator
```

## Run it

Regenerate the synthetic examples, then analyze them:

```sh
python generate_logs.py
python main.py --ssh logs/auth.log --web logs/access.log --output reports --year 2026
```

Either `--ssh` or `--web` can be omitted. Run `python main.py --help` to see all options. The output directory contains `alerts.csv` and `security_report.txt`. Inputs are limited to 20 MB each. Auth log timestamps omit a year; `--year` supplies it (the default is the machine's current year). Yearless timestamps are interpreted as UTC because syslog lines do not include a timezone. Apache offsets are honored and converted to UTC.

To open the optional dashboard locally:

```sh
python -m dashboard.app
```

Visit `http://127.0.0.1:5000`, select `.log` or `.txt` files (up to 20 MB each), and analyze. Uploaded contents are held in memory and analyzed locally. CSV and TXT downloads become available after analysis. Do not expose the development server to a public network.

Run tests with:

```sh
python -m unittest discover -v
```

## Detection rules and severity

| Rule | Default condition | Severity |
|---|---|---|
| SSH brute-force | 5 failed attempts from one IP in a sliding 60-second window | HIGH |
| Possible SSH compromise | Successful login from same IP within 900 seconds after at least 5 failures | CRITICAL |
| SSH username enumeration | 4 invalid usernames from one IP in the analyzed input | MEDIUM |
| Directory scanning | 8 HTTP 404s from one IP in a sliding 60-second window | MEDIUM |
| Web attack signature | SQL injection, XSS, or traversal marker in request URL/log detail | HIGH |

Threshold options include `--ssh-threshold`, `--ssh-window`, `--correlation-seconds`, `--invalid-user-threshold`, and `--web-404-threshold`. Sliding windows are based on event time, so out-of-order input is normalized. Overlapping qualifying windows for the same source are consolidated. Enumeration counts distinct parsed invalid-user events across the provided input. A successful login alert requires enough preceding failed events inside the correlation period; a lone later success is not an alert.

## Example output

The bundled synthetic data currently produces alerts like these (exact timestamps reflect the sample set):

| Timestamp (UTC) | Source IP | Event | Severity |
|---|---|---|---|
| 2026-10-28 10:02:10 | 192.0.2.20 | Possible SSH compromise | CRITICAL |
| 2026-10-28 10:01:55 | 192.0.2.20 | SSH brute-force | HIGH |
| 2026-10-28 10:04:00 | 198.51.100.70 | SQL injection signature | HIGH |
| 2026-10-28 10:04:05 | 198.51.100.71 | XSS signature | HIGH |
| 2026-10-28 10:04:10 | 198.51.100.72 | Path traversal signature | HIGH |
| 2026-10-28 10:02:40 | 203.0.113.60 | Directory scanning | MEDIUM |
| 2026-10-28 10:03:03 | 198.51.100.30 | SSH username enumeration | MEDIUM |

The full generated report includes parsed/skipped counts, severity totals, alert details, and recommendations. The CLI prints the paths it wrote. If no rules match, it says so explicitly and the TXT report includes a useful empty-result summary.

## Defensive recommendations

For SSH brute-force signals, investigate source addresses and consider rate limiting, firewall restrictions, Fail2ban, SSH keys, and disabling password login where suitable. For a suspected compromise, review authentication history and affected accounts, rotate credentials or keys if warranted, and follow incident response procedures. For web signatures, review application logs, use parameterized SQL, validate inputs, encode output, and consider a suitable web application firewall. These are recommendations only; the analyzer never blocks traffic or modifies configurations.

## Limitations and false positives

This is a small rule-based teaching tool, not an IDS or proof of compromise. Legitimate users can mistype passwords; scanners and application testing can resemble attacks; unusual encodings and log formats may be missed. The signature checks intentionally look for common markers and can miss variants. Inspect alert context and skipped-line counts, tune thresholds for your environment, and verify findings with other evidence. Do not interpret absence of alerts as proof that a system is safe.

## Internship review demonstration

1. Explain the safe, offline design and show the synthetic data labels.
2. Run the generator and CLI; point to each rule's alert and explain why its threshold matched.
3. Open the CSV and TXT outputs and show the skipped malformed sample line.
4. Run the unit tests and demonstrate a benign request and a mistyped password that do not individually trigger alerts.
5. Optionally start the dashboard, upload the sample logs, filter alerts, and download reports.

## Troubleshooting

- `provide at least one...`: include `--ssh` or `--web`.
- File errors: check spelling, working directory, and read access; paths can be absolute or relative.
- No alerts: confirm the selected files contain supported log formats and timestamps; lower thresholds only for a controlled demonstration.
- Incorrect auth dates: set `--year` to the year represented by the syslog input.
- Dashboard import error: install Flask from `requirements.txt`; the CLI does not require it.

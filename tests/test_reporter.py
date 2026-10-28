import csv
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
from analyzer.detections import Alert
from analyzer.reporter import write_reports

class ReporterTests(unittest.TestCase):
    def test_reports_have_headers_counts_and_empty_summary(self):
        with tempfile.TemporaryDirectory() as d:
            alert = Alert(datetime(2026,1,1,tzinfo=timezone.utc), "192.0.2.1", "SSH brute-force", "HIGH", "five failures")
            csvpath, txtpath = write_reports([alert], Path(d), ssh_total=5, ssh_parsed=5, ssh_skipped=0, web_total=0, web_parsed=0, web_skipped=0)
            with csvpath.open(newline="", encoding="utf8") as f: rows=list(csv.DictReader(f))
            self.assertEqual(rows[0]["severity"], "HIGH")
            self.assertIn("Alerts: 1 total", txtpath.read_text(encoding="utf8"))
            write_reports([], Path(d), ssh_total=0, ssh_parsed=0, ssh_skipped=0, web_total=0, web_parsed=0, web_skipped=0)
            self.assertIn("No suspicious activity", txtpath.read_text(encoding="utf8"))

if __name__ == "__main__": unittest.main()

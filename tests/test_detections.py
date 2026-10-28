import unittest
from datetime import datetime, timedelta, timezone
from analyzer.parsers import Event
from analyzer.detections import analyze_events, AnalyzerConfig

BASE = datetime(2026, 10, 28, tzinfo=timezone.utc)
def ev(sec, ip="192.0.2.1", kind="ssh_failed", **kw): return Event(BASE+timedelta(seconds=sec), ip, kind, **kw)
class DetectionTests(unittest.TestCase):
    def test_bruteforce_sliding_threshold_and_boundary(self):
        good = [ev(x) for x in (0, 10, 20, 30, 60)]
        self.assertIn("SSH brute-force", [a.event_type for a in analyze_events(good)])
        outside = [ev(x) for x in (0, 10, 20, 30, 61)]
        self.assertNotIn("SSH brute-force", [a.event_type for a in analyze_events(outside)])
    def test_out_of_order_and_overlap_deduplicated(self):
        events = [ev(x) for x in (50, 0, 30, 10, 20, 40)]
        alerts = analyze_events(events)
        self.assertEqual(sum(a.event_type == "SSH brute-force" for a in alerts), 1)
    def test_compromise_requires_prior_threshold_and_window(self):
        fail = [ev(x) for x in (0, 10, 20, 30, 40)]
        ok = ev(50, kind="ssh_success", username="alice", details="Accepted publickey")
        far = ev(1000, kind="ssh_success", username="alice", details="Accepted publickey")
        self.assertEqual(sum(a.severity == "CRITICAL" for a in analyze_events(fail+[ok, far])), 1)
        self.assertIn("Accepted publickey", next(a.details for a in analyze_events(fail+[ok]) if a.severity == "CRITICAL"))
        self.assertFalse(any(a.severity == "CRITICAL" for a in analyze_events([*fail[:4], ok])))
    def test_invalid_user_enumeration(self):
        es = [ev(i, kind="ssh_invalid_user", username=f"u{i}") for i in range(4)]
        self.assertIn("SSH username enumeration", [a.event_type for a in analyze_events(es)])
    def test_single_mistyped_password_is_not_an_alert(self):
        self.assertEqual(analyze_events([ev(0)]), [])
    def test_directory_scan_window(self):
        es = [ev(i*8, kind="http_request", status=404) for i in range(8)]
        self.assertIn("Directory scanning", [a.event_type for a in analyze_events(es)])
        es[-1] = ev(61, kind="http_request", status=404)
        self.assertNotIn("Directory scanning", [a.event_type for a in analyze_events(es)])
    def test_attack_signatures_encoded_and_benign(self):
        attacks = [ev(0, kind="http_request", method="GET", url="/q?a=%27%20OR%201%3D1--"), ev(1, kind="http_request", method="GET", url="/%3Cscript%3Ealert(1)%3C%2Fscript%3E"), ev(2, kind="http_request", method="GET", url="/file?x=..%2F..%2Fetc%2Fpasswd")]
        self.assertEqual(sum(a.severity == "HIGH" for a in analyze_events(attacks)), 3)
        benign = [ev(0, kind="http_request", method="GET", url="/products?id=123"), ev(1, kind="http_request", method="GET", url="/search?q=union%20station")]
        self.assertEqual(analyze_events(benign), [])
    def test_signature_in_referer_field(self):
        event = ev(0, kind="http_request", method="GET", url="/", details="referer=/search?q=%3Cscript%3E")
        self.assertEqual(analyze_events([event])[0].severity, "HIGH")

if __name__ == "__main__": unittest.main()

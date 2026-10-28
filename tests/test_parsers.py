import unittest
from analyzer.parsers import parse_auth_lines, parse_apache_lines

class ParserTests(unittest.TestCase):
    def test_auth_supported_events_and_year(self):
        result = parse_auth_lines(["Oct 28 12:00:00 host sshd[1]: Failed password for sam from 192.0.2.1 port 22 ssh2", "Oct 28 12:00:01 host sshd[2]: Accepted publickey for sam from 192.0.2.1 port 22 ssh2"], 2026)
        self.assertEqual([e.event_type for e in result.events], ["ssh_failed", "ssh_success"])
        self.assertEqual(result.events[0].timestamp.year, 2026)
        self.assertEqual(result.events[0].timestamp.utcoffset().total_seconds(), 0)
    def test_invalid_user_also_counts_as_failure(self):
        r = parse_auth_lines(["Oct 28 12:00:00 host sshd[1]: Failed password for invalid user guest from 192.0.2.1 port 22 ssh2"], 2026)
        self.assertEqual({e.event_type for e in r.events}, {"ssh_failed", "ssh_invalid_user"})
        self.assertEqual(r.events[0].username, "guest")
    def test_malformed_auth_skipped(self):
        r = parse_auth_lines(["gibberish", "Oct 40 12:00:00 host sshd[1]: Failed password for x from 192.0.2.1"] , 2026)
        self.assertEqual(r.skipped, 2)
    def test_missing_file_is_rejected_by_cli_reader(self):
        from main import _read
        from pathlib import Path
        with self.assertRaises(ValueError): _read(Path("definitely-missing-auth.log"), "SSH")
    def test_apache_combined_and_common(self):
        r = parse_apache_lines(['192.0.2.1 - - [28/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Browser"', '192.0.2.2 - - [28/Oct/2026:12:00:01 +0000] "POST /login HTTP/1.0" 401 50'])
        self.assertEqual(len(r.events), 2)
        self.assertEqual(r.events[1].method, "POST")
        self.assertEqual(r.events[1].status, 401)
        self.assertEqual(r.skipped, 0)

if __name__ == "__main__": unittest.main()

"""Regenerate deterministic, fictional demonstration logs."""
from pathlib import Path

ROOT = Path(__file__).parent / "logs"
def generate():
    ROOT.mkdir(exist_ok=True)
    ssh = [
      "Oct 28 10:00:00 demo-host sshd[1001]: Accepted publickey for analyst from 192.0.2.10 port 5000 ssh2",
      "Oct 28 10:01:00 demo-host sshd[1002]: Failed password for analyst from 192.0.2.20 port 5001 ssh2",
      "Oct 28 10:01:14 demo-host sshd[1003]: Failed password for analyst from 192.0.2.20 port 5002 ssh2",
      "Oct 28 10:01:28 demo-host sshd[1004]: Failed password for analyst from 192.0.2.20 port 5003 ssh2",
      "Oct 28 10:01:42 demo-host sshd[1005]: Failed password for analyst from 192.0.2.20 port 5004 ssh2",
      "Oct 28 10:01:55 demo-host sshd[1006]: Failed password for analyst from 192.0.2.20 port 5005 ssh2",
      "Oct 28 10:02:10 demo-host sshd[1007]: Accepted publickey for analyst from 192.0.2.20 port 5006 ssh2",
    ]
    for i, name in enumerate(("alpha", "bravo", "charlie", "delta")):
        ssh.append(f"Oct 28 10:03:0{i} demo-host sshd[11{i}]: Failed password for invalid user {name} from 198.51.100.30 port 510{i} ssh2")
    ssh += ["Oct 28 10:05:00 demo-host sshd[1200]: Failed password for analyst from 203.0.113.40 port 5200 ssh2", "Oct 28 10:10:00 demo-host sshd[1201]: Accepted publickey for analyst from 203.0.113.40 port 5201 ssh2", "not an ssh event: deliberately malformed sample"]
    access = [
      '192.0.2.50 - - [28/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "DemoBrowser/1.0"',
      '192.0.2.50 - - [28/Oct/2026:10:00:12 +0000] "GET /images/logo.png HTTP/1.1" 200 1234 "-" "DemoBrowser/1.0"',
      '203.0.113.60 - - [28/Oct/2026:10:02:00 +0000] "GET /missing1 HTTP/1.1" 404 120 "-" "DemoScanner/1.0"',
    ]
    for i in range(2, 9): access.append(f'203.0.113.60 - - [28/Oct/2026:10:02:{i*5:02d} +0000] "GET /missing{i} HTTP/1.1" 404 120 "-" "DemoScanner/1.0"')
    access += [
      '198.51.100.70 - - [28/Oct/2026:10:04:00 +0000] "GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 200 200 "-" "DemoBrowser/1.0"',
      '198.51.100.71 - - [28/Oct/2026:10:04:05 +0000] "GET /page?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 200 200 "-" "DemoBrowser/1.0"',
      '198.51.100.72 - - [28/Oct/2026:10:04:10 +0000] "GET /download?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 400 100 "-" "DemoBrowser/1.0"',
      'not an apache line: deliberately malformed sample',
    ]
    (ROOT / "auth.log").write_text("\n".join(ssh)+"\n", encoding="utf-8")
    (ROOT / "access.log").write_text("\n".join(access)+"\n", encoding="utf-8")
    print(f"Generated synthetic logs in {ROOT}")
if __name__ == "__main__": generate()

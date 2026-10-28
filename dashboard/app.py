"""Optional local dashboard. Uploaded text is parsed in memory and never executed."""
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file
from analyzer.parsers import parse_auth_lines, parse_apache_lines
from analyzer.detections import analyze_events, SEVERITY_ORDER
from analyzer.reporter import write_reports

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
OUTPUT = Path(__file__).resolve().parents[1] / "reports"
LAST = {"alerts": [], "counts": {}}

@app.get("/")
def index(): return render_template("index.html")

@app.post("/api/analyze")
def analyze():
    events, counts = [], {}
    for field, parser, label in (("ssh", parse_auth_lines, "ssh"), ("web", parse_apache_lines, "web")):
        uploaded = request.files.get(field)
        if uploaded and uploaded.filename:
            if not uploaded.filename.lower().endswith((".log", ".txt")):
                return jsonify(error=f"{label.upper()} file must end in .log or .txt"), 400
            content = uploaded.stream.read(20 * 1024 * 1024 + 1)
            if len(content) > 20 * 1024 * 1024: return jsonify(error="Each log must be 20 MB or smaller."), 413
            parsed = parser(content.decode("utf-8", errors="replace").splitlines())
            events.extend(parsed.events); counts[label] = {"total": len(content.splitlines()), "parsed": parsed.parsed, "skipped": parsed.skipped}
        else: counts[label] = {"total": 0, "parsed": 0, "skipped": 0}
    if not events: return jsonify(error="Choose a log file containing recognizable SSH or Apache events."), 400
    alerts = analyze_events(events)
    write_reports(alerts, OUTPUT, ssh_total=counts["ssh"]["total"], ssh_parsed=counts["ssh"]["parsed"], ssh_skipped=counts["ssh"]["skipped"], web_total=counts["web"]["total"], web_parsed=counts["web"]["parsed"], web_skipped=counts["web"]["skipped"], period=[event.timestamp for event in events])
    LAST["alerts"], LAST["counts"] = alerts, counts
    return jsonify(log_lines=sum(c["total"] for c in counts.values()), parsed=sum(c["parsed"] for c in counts.values()), alerts=[{"timestamp": a.timestamp.isoformat(), "source_ip": a.source_ip, "event_type": a.event_type, "severity": a.severity, "details": a.details} for a in alerts], severity={s: sum(a.severity == s for a in alerts) for s in SEVERITY_ORDER})

@app.get("/download/<kind>")
def download(kind):
    if kind not in ("alerts.csv", "security_report.txt"): return jsonify(error="Unknown report."), 404
    path = OUTPUT / kind
    if not path.is_file(): return jsonify(error="Run an analysis before downloading reports."), 404
    return send_file(path, as_attachment=True, download_name=kind)

if __name__ == "__main__": app.run(host="127.0.0.1", port=5000, debug=False)

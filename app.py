import os
import json
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from analyzer.email_parser import parse_email
from analyzer.ml_detector import predict_email
from analyzer.threat_intel import enrich_iocs
from analyzer.auth_checks import analyze_authentication
from analyzer.risk_engine import calculate_risk
from analyzer.report import create_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload cap
DB = os.environ.get("DB_PATH", "analyses.db")

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = app.logger


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS analyses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT, subject TEXT, sender TEXT, risk INTEGER,
        level TEXT, sha256 TEXT, result_json TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at)")
    con.commit()
    return con


def _read_upload_text(f):
    raw_bytes = f.read()
    for enc in ("utf-8", "latin-1"):
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="ignore")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Email Threat Intelligence Platform"})


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/api/history")
def history():
    try:
        limit = min(100, max(1, int(request.args.get("limit", 30))))
    except (TypeError, ValueError):
        limit = 30
    con = db()
    rows = con.execute(
        "SELECT id,created_at,subject,sender,risk,level,sha256 FROM analyses ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/history/<int:item_id>")
def history_item(item_id):
    con = db()
    row = con.execute("SELECT result_json FROM analyses WHERE id=?", (item_id,)).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(json.loads(row["result_json"]))


@app.route("/api/history/<int:item_id>", methods=["DELETE"])
def delete_history_item(item_id):
    con = db()
    cur = con.execute("DELETE FROM analyses WHERE id=?", (item_id,))
    con.commit()
    deleted = cur.rowcount
    con.close()
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"deleted": item_id})


@app.route("/analyze", methods=["POST"])
def analyze():
    raw = ""
    filename = ""
    if "file" in request.files:
        f = request.files["file"]
        if f and f.filename:
            filename = secure_filename(f.filename)
            if not filename.lower().endswith((".eml", ".txt", ".msg")):
                return jsonify({"error": "Please upload a .eml or .txt file."}), 400
            raw = _read_upload_text(f)
    if not raw:
        raw = request.form.get("email", "")
    if not raw.strip():
        return jsonify({"error": "Upload an .eml file or paste an email."}), 400
    if len(raw) > 2_000_000:
        return jsonify({"error": "Email content is too large to analyze."}), 400

    try:
        parsed = parse_email(raw)
    except Exception as e:
        logger.warning("Failed to parse email: %s", e)
        return jsonify({"error": "Could not parse this as a valid email message."}), 400

    try:
        ml = predict_email(parsed.get("subject", ""), parsed.get("body", ""))
        iocs = enrich_iocs(parsed.get("urls", []), parsed.get("ips", []))
        auth = analyze_authentication(parsed.get("authentication_headers", {}))
        result = {**parsed, "ml": ml, "threat_intelligence": iocs, "authentication": auth}
        result["risk"] = calculate_risk(result)
        digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
        result["sha256"] = digest
        result["source_file"] = filename
        result["analyzed_at"] = datetime.now(timezone.utc).isoformat()

        con = db()
        cur = con.execute(
            "INSERT INTO analyses(created_at,subject,sender,risk,level,sha256,result_json) VALUES(?,?,?,?,?,?,?)",
            (
                result["analyzed_at"], result.get("subject", ""), result.get("sender", ""),
                result["risk"]["score"], result["risk"]["level"], digest, json.dumps(result),
            ),
        )
        con.commit()
        result["id"] = cur.lastrowid
        con.close()
        return jsonify(result)
    except Exception as e:
        logger.exception("Analysis failed")
        return jsonify({"error": f"Analysis failed: {e}"}), 500


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "No analysis supplied"}), 400
    try:
        path = create_report(data)
    except Exception as e:
        logger.exception("Report generation failed")
        return jsonify({"error": f"Could not generate report: {e}"}), 500
    return send_file(path, as_attachment=True, download_name="email-forensic-report.html")


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "Upload is too large (5 MB limit)."}), 413


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/") or request.path in ("/analyze", "/report"):
        return jsonify({"error": "Not found"}), 404
    return render_template("index.html"), 404


if __name__ == "__main__":
    db()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug)

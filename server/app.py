#!/usr/bin/env python3
"""SSH Blacklist Server - Central service for collecting and serving SSH brute-force IPs."""

import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

DB_PATH = os.environ.get("BLACKLIST_DB", "/var/lib/ssh-blacklist/blacklist.db")
HOST = os.environ.get("BLACKLIST_HOST", "0.0.0.0")
PORT = int(os.environ.get("BLACKLIST_PORT", "5000"))

# In-memory blacklist: {ip_address: attempt_count}
blacklist = {}
blacklist_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reported_at TEXT NOT NULL,
            reporter_ip TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_reported_at ON reports_log(reported_at);
        CREATE INDEX IF NOT EXISTS idx_reports_reporter_ip ON reports_log(reporter_ip);
        CREATE INDEX IF NOT EXISTS idx_reports_ip ON reports_log(ip);
    """)
    conn.commit()
    conn.close()


def load_blacklist():
    conn = get_db()
    rows = conn.execute("SELECT ip, attempts FROM blacklist").fetchall()
    conn.close()
    with blacklist_lock:
        blacklist.clear()
        for row in rows:
            blacklist[row["ip"]] = row["attempts"]


def get_reporter_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    if request.headers.get("X-Real-IP"):
        return request.headers["X-Real-IP"]
    return request.remote_addr


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/report", methods=["POST"])
def report_ip():
    """Report one or more IPs that attempted unauthorized SSH access.

    Accepts JSON:
        {"ip": "1.2.3.4"}              - single report
        {"ips": ["1.2.3.4", "5.6.7.8"]} - batch report (duplicates = multiple attempts)
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    if "ip" in data:
        ips = [data["ip"]]
    elif "ips" in data and isinstance(data["ips"], list):
        ips = data["ips"]
    else:
        return jsonify({"error": "Missing 'ip' or 'ips' field"}), 400

    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    reporter_ip = get_reporter_ip()
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    results = {}

    try:
        for ip in ips:
            ip = str(ip).strip()
            parts = ip.split(".")
            if len(parts) != 4 or not all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            ):
                results[ip] = {"error": "invalid IP format"}
                continue

            conn.execute(
                """INSERT INTO blacklist (ip, attempts, first_seen, last_seen)
                   VALUES (?, 1, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       attempts = attempts + 1,
                       last_seen = ?""",
                (ip, now, now, now),
            )
            conn.execute(
                "INSERT INTO reports_log (ip, reported_at, reporter_ip) VALUES (?, ?, ?)",
                (ip, now, reporter_ip),
            )

            with blacklist_lock:
                blacklist[ip] = blacklist.get(ip, 0) + 1
                results[ip] = {"attempts": blacklist[ip]}

        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "ok", "results": results})


@app.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    """Return the blacklist.

    Query parameters:
        days  - only return IPs reported within the last N days (optional)
    """
    days = request.args.get("days", type=int)

    if days is None:
        with blacklist_lock:
            data = [
                {"ip": ip, "attempts": attempts}
                for ip, attempts in blacklist.items()
            ]
        data.sort(key=lambda x: x["attempts"], reverse=True)
        return jsonify({"count": len(data), "blacklist": data})

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = get_db()
    rows = conn.execute(
        """SELECT ip, COUNT(*) as attempts
           FROM reports_log
           WHERE reported_at >= ?
           GROUP BY ip
           ORDER BY attempts DESC""",
        (cutoff,),
    ).fetchall()
    conn.close()

    data = [{"ip": row["ip"], "attempts": row["attempts"]} for row in rows]
    return jsonify({"count": len(data), "days": days, "blacklist": data})


@app.route("/api/stats")
def stats():
    """Statistics page rendered as HTML for browser viewing."""
    server_filter = request.args.get("server")
    conn = get_db()

    total_ips = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    total_reports = conn.execute("SELECT COUNT(*) FROM reports_log").fetchone()[0]

    now = datetime.now(timezone.utc)
    windows = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    counts = {}
    for label, delta in windows.items():
        cutoff = (now - delta).isoformat()
        counts[label] = conn.execute(
            "SELECT COUNT(*) FROM reports_log WHERE reported_at >= ?", (cutoff,)
        ).fetchone()[0]

    cutoff_24h = (now - timedelta(hours=24)).isoformat()
    new_ips_24h = conn.execute(
        "SELECT COUNT(*) FROM blacklist WHERE first_seen >= ?", (cutoff_24h,)
    ).fetchone()[0]

    avg_daily = round(counts["30d"] / 30, 1)

    top_ips = conn.execute(
        "SELECT ip, attempts, first_seen, last_seen FROM blacklist ORDER BY attempts DESC LIMIT 50"
    ).fetchall()

    top_ips_24h = conn.execute(
        """SELECT ip, COUNT(*) as attempts
           FROM reports_log WHERE reported_at >= ?
           GROUP BY ip ORDER BY attempts DESC LIMIT 20""",
        (cutoff_24h,),
    ).fetchall()

    servers = conn.execute(
        """SELECT reporter_ip, COUNT(*) as report_count, COUNT(DISTINCT ip) as unique_ips
           FROM reports_log GROUP BY reporter_ip ORDER BY report_count DESC"""
    ).fetchall()

    server_ips = []
    if server_filter:
        server_ips = conn.execute(
            """SELECT ip, COUNT(*) as times_reported,
                      MIN(reported_at) as first_report, MAX(reported_at) as last_report
               FROM reports_log WHERE reporter_ip = ?
               GROUP BY ip ORDER BY times_reported DESC""",
            (server_filter,),
        ).fetchall()

    conn.close()

    return render_template_string(
        STATS_TEMPLATE,
        total_ips=total_ips,
        total_reports=total_reports,
        counts=counts,
        new_ips_24h=new_ips_24h,
        avg_daily=avg_daily,
        top_ips=top_ips,
        top_ips_24h=top_ips_24h,
        servers=servers,
        server_filter=server_filter,
        server_ips=server_ips,
    )


# ---------------------------------------------------------------------------
# HTML template for statistics
# ---------------------------------------------------------------------------

STATS_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Blacklist &mdash; Statistics</title>
<style>
  :root { --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a; --text: #e0e0e0;
          --muted: #888; --accent: #5b9aff; --danger: #ff5555; --green: #50fa7b; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 20px; }
  h1 { color: var(--accent); margin-bottom: 8px; font-size: 1.6em; }
  h2 { color: var(--accent); margin: 30px 0 12px; font-size: 1.2em; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  .subtitle { color: var(--muted); margin-bottom: 24px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 10px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .label { color: var(--muted); font-size: 0.85em; margin-bottom: 4px; }
  .card .value { font-size: 1.8em; font-weight: bold; }
  .card .value.danger { color: var(--danger); }
  .card .value.green { color: var(--green); }
  table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 10px; }
  th { background: #22253a; text-align: left; padding: 10px 14px; font-size: 0.85em; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 8px 14px; border-top: 1px solid var(--border); font-size: 0.95em; }
  tr:hover td { background: #1f2233; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; background: #2a2d3a; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
  .back { margin-bottom: 14px; display: inline-block; }
  .container { max-width: 1100px; margin: 0 auto; }
</style>
</head>
<body>
<div class="container">
<h1>SSH Blacklist Statistics</h1>
<p class="subtitle">Central blacklist service for unauthorized SSH access attempts</p>

<div class="cards">
  <div class="card"><div class="label">Total Blacklisted IPs</div><div class="value danger">{{ total_ips }}</div></div>
  <div class="card"><div class="label">Total Reports</div><div class="value">{{ total_reports }}</div></div>
  <div class="card"><div class="label">New IPs (24h)</div><div class="value green">{{ new_ips_24h }}</div></div>
  <div class="card"><div class="label">Avg Reports / Day</div><div class="value">{{ avg_daily }}</div></div>
</div>

<h2>Recent Activity</h2>
<div class="cards">
  <div class="card"><div class="label">Last 24 hours</div><div class="value">{{ counts['24h'] }}</div></div>
  <div class="card"><div class="label">Last 7 days</div><div class="value">{{ counts['7d'] }}</div></div>
  <div class="card"><div class="label">Last 30 days</div><div class="value">{{ counts['30d'] }}</div></div>
</div>

<h2>Top Reported IPs (All Time)</h2>
<table>
<tr><th>#</th><th>IP Address</th><th>Attempts</th><th>First Seen</th><th>Last Seen</th></tr>
{% for row in top_ips %}
<tr>
  <td>{{ loop.index }}</td>
  <td><code>{{ row['ip'] }}</code></td>
  <td><strong>{{ row['attempts'] }}</strong></td>
  <td>{{ row['first_seen'][:19] }}</td>
  <td>{{ row['last_seen'][:19] }}</td>
</tr>
{% endfor %}
{% if not top_ips %}<tr><td colspan="5" style="text-align:center;color:var(--muted)">No data yet</td></tr>{% endif %}
</table>

<h2>Most Active IPs (Last 24h)</h2>
<table>
<tr><th>#</th><th>IP Address</th><th>Attempts</th></tr>
{% for row in top_ips_24h %}
<tr>
  <td>{{ loop.index }}</td>
  <td><code>{{ row['ip'] }}</code></td>
  <td><strong>{{ row['attempts'] }}</strong></td>
</tr>
{% endfor %}
{% if not top_ips_24h %}<tr><td colspan="3" style="text-align:center;color:var(--muted)">No data in the last 24 hours</td></tr>{% endif %}
</table>

<h2>Reporting Servers</h2>
<table>
<tr><th>Server IP</th><th>Total Reports</th><th>Unique IPs</th><th>Details</th></tr>
{% for row in servers %}
<tr>
  <td><code>{{ row['reporter_ip'] }}</code></td>
  <td>{{ row['report_count'] }}</td>
  <td>{{ row['unique_ips'] }}</td>
  <td><a href="?server={{ row['reporter_ip'] }}">View IPs &rarr;</a></td>
</tr>
{% endfor %}
{% if not servers %}<tr><td colspan="4" style="text-align:center;color:var(--muted)">No reporting servers yet</td></tr>{% endif %}
</table>

{% if server_filter %}
<h2>IPs Reported by <code>{{ server_filter }}</code></h2>
<a class="back" href="/api/stats">&larr; Back to overview</a>
<table>
<tr><th>#</th><th>IP Address</th><th>Times Reported</th><th>First Report</th><th>Last Report</th></tr>
{% for row in server_ips %}
<tr>
  <td>{{ loop.index }}</td>
  <td><code>{{ row['ip'] }}</code></td>
  <td>{{ row['times_reported'] }}</td>
  <td>{{ row['first_report'][:19] }}</td>
  <td>{{ row['last_report'][:19] }}</td>
</tr>
{% endfor %}
{% if not server_ips %}<tr><td colspan="5" style="text-align:center;color:var(--muted)">No reports from this server</td></tr>{% endif %}
</table>
{% endif %}

</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    init_db()
    load_blacklist()
    print(f"SSH Blacklist Server starting on {HOST}:{PORT}")
    print(f"Database: {DB_PATH}")
    print(f"Loaded {len(blacklist)} IPs from database")
    app.run(host=HOST, port=PORT)

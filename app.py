# app.py

from flask import Flask, render_template_string, request, redirect, url_for, flash
from settings import load_config, save_config
import os
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")

LOG_FILE = os.path.join(CONFIG_DIR, "queries.log")
LOG_PATH = os.path.join(os.path.dirname(__file__), 'queries.log')

TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>DNS Firewall Dashboard</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f9f9f9;
      padding: 40px;
      max-width: 600px;
      margin: auto;
    }
    h1 {
      color: #333;
      border-bottom: 2px solid #ccc;
      padding-bottom: 10px;
    }
    label {
      font-weight: bold;
    }
    input[type="text"], input[type="number"] {
      width: 100%%;
      padding: 10px;
      margin: 8px 0 20px;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    input[type="submit"] {
      background-color: #4CAF50;
      color: white;
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
    }
    input[type="submit"]:hover {
      background-color: #45a049;
    }
    .nav-link {
      display: inline-block;
      margin-bottom: 20px;
      text-decoration: none;
      color: #4CAF50;
      font-weight: bold;
    }
    .success {
      color: green;
      font-weight: bold;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>

  <h1>DNS Firewall Settings</h1>
   
  <div style="margin-bottom: 20px;">
    <strong>DNS Statistics:</strong><br>
    ✅ Allowed: {{ stats.allowed }}<br>
    ❌ Blocked: {{ stats.blocked }}<br>
    📊 Total Queries: {{ stats.total }}
  </div>
  <a class="nav-link" href="{{ url_for('view_logs') }}">📄 View DNS Logs</a>
  <form method="post" action="{{ url_for('refresh_logs') }}" style="display:inline;">
    <button type="submit" style="margin-left: 10px;">🔄 Refresh</button>
  </form>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="success">{{ messages[0] }}</div>
    {% endif %}
  {% endwith %}

<form method="post" style="margin-top: 20px;">
  <div style="
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    max-width: 700px;
    margin: auto;
    align-items: end;
  ">
    <div>
      <label><strong>Model:</strong></label><br>
      <input name="model" value="{{ config.model }}" style="width: 100%;">
    </div>

    <div>
      <label><strong>API URL:</strong></label><br>
      <input name="api_url" value="{{ config.api_url }}" style="width: 100%;">
    </div>

    <div>
      <label><strong>Upstream DNS IP:</strong></label><br>
      <input name="upstream_dns" value="{{ config.upstream_dns }}" style="width: 100%;">
    </div>

    <div>
      <label><strong>Listen Address:</strong></label><br>
      <input name="dns_listen_address" value="{{ config.dns_listen_address }}" style="width: 100%;">
    </div>

    <div>
      <label><strong>DNS Port:</strong></label><br>
      <input name="dns_port" type="number" value="{{ config.dns_port }}" style="width: 90%;">
    </div>

    <div>
      <label><strong>Broken Link Threshold:</strong></label><br>
      <input name="broken_link_threshold" type="number" value="{{ config.broken_link_threshold }}" style="width: 100%;">
    </div>

    <div style="grid-column: span 2;">
      <label>
        <input type="checkbox" name="filtering_enabled" value="1"
          {% if config.filtering_enabled %}checked{% endif %}>
        <strong>Enable DNS Filtering</strong>
      </label>
    </div>

    <div style="grid-column: span 2; text-align: center;">
      <button type="submit" style="padding: 10px 25px; font-weight: bold; background: green; color: white; border: none; border-radius: 6px;">
        💾 Save Settings
      </button>
    </div>
  </div>
</form>


</body>
</html>
"""


LOG_TEMPLATE = """
<!doctype html>
<title>DNS Query Logs</title>
<style>
  body { font-family: sans-serif; padding: 20px; max-width: 800px; margin: auto; }
  pre { background: #f4f4f4; padding: 10px; border: 1px solid #ccc; white-space: pre-wrap; }
  .success { color: green; margin-bottom: 10px; }
</style>

<h1>Recent DNS Queries</h1>

{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div class="success">{{ messages[0] }}</div>
  {% endif %}
{% endwith %}

<pre>{% for line in logs %}
{{ line.strip() }}
{% endfor %}</pre>

<form method="get" action="{{ url_for('view_logs') }}">
  <button type="submit">🔄 Refresh</button>
</form>

<form method="post" action="{{ url_for('clear_logs') }}">
  <button type="submit">🧹 Clear Log File</button>
</form>

<br>
<a href="{{ url_for('dashboard') }}">← Back to Settings</a>
"""

class Dashboard:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'dev'
        self._setup_routes()
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

    def _setup_routes(self):
        @self.app.route("/", methods=["GET", "POST"])
        def dashboard():
            config = load_config()
            stats = self.get_log_stats(LOG_FILE)

            if request.method == "POST":
                try:
                    config["filtering_enabled"] = "filtering_enabled" in request.form
                    config["model"] = request.form["model"]
                    config["api_url"] = request.form["api_url"]
                    config["dns_port"] = int(request.form["dns_port"])
                    config["upstream_dns"] = request.form["upstream_dns"]
                    config["dns_listen_address"] = request.form["dns_listen_address"]
                                
                    save_config(config)
                    flash("Settings saved successfully! Restart the program to apply them.")
                    return redirect(url_for("dashboard"))

                except Exception as e:
                    return f"<h2>Error:</h2><pre>{e}</pre>"

            return render_template_string(TEMPLATE, config=config, stats=stats)

        @self.app.route("/logs")
        def view_logs():
            try:
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()[-100:]
            except FileNotFoundError:
                lines = ["Log file not found."]
            return render_template_string(LOG_TEMPLATE, logs=lines)

        @self.app.route("/refresh_logs", methods=["POST"])
        def refresh_logs():
            flash("Logs refreshed.")
            return redirect(url_for("dashboard"))

        @self.app.route("/clear_logs", methods=["POST"])
        def clear_logs():
            try:
                open(LOG_FILE, 'w').close()
                flash("Logs cleared.")
            except Exception as e:
                flash(f"Error clearing logs: {e}")
            return redirect(url_for("view_logs"))

    # -------------------- STATISTICS HELPER --------------------
    def get_log_stats(self, log_path):
        allowed = blocked = 0
        try:
            with open(log_path, "r") as f:
                for line in f:
                    if " - allow" in line:
                        allowed += 1
                    elif " - block" in line:
                        blocked += 1
        except FileNotFoundError:
            pass
        return {"allowed": allowed, "blocked": blocked, "total": allowed + blocked}

    def start(self, host="0.0.0.0", port=5000):
        self.app.run(host=host, port=port, debug=False, use_reloader=False)

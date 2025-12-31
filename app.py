#app.py

from flask import Flask, render_template_string, request, redirect, url_for, flash
from settings import load_config, save_config
import os
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")

LOG_FILE = os.path.join(CONFIG_DIR, "queries.log")
WHITELIST_FILE = os.path.join(CONFIG_DIR, "whitelist.txt")


#-----------------------HTML TEMPLATES-----------------------

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
      max-width: 700px;
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
    input[type="submit"], button {
      background-color: #4CAF50;
      color: white;
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
    }
    input[type="submit"]:hover, button:hover {
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
      <input name="model" value="{{ config.model }}">
    </div>

    <div>
      <label><strong>API URL:</strong></label><br>
      <input name="api_url" value="{{ config.api_url }}">
    </div>

    <div>
      <label><strong>Upstream DNS IP:</strong></label><br>
      <input name="upstream_dns" value="{{ config.upstream_dns }}">
    </div>

    <div>
      <label><strong>Listen Address:</strong></label><br>
      <input name="dns_listen_address" value="{{ config.dns_listen_address }}">
    </div>

    <div>
      <label><strong>DNS Port:</strong></label><br>
      <input name="dns_port" type="number" value="{{ config.dns_port }}">
    </div>

    <div>
      <label><strong>Dashboard Port:</strong></label><br>
      <input name="dashboard_port" type="number" value="{{ config.dashboard_port }}">
    </div>

    <div>
      <label><strong>Block Score Threshold:</strong></label><br>
      <input name="block_score" type="number" value="{{ config.block_score }}">
    </div>

    <div style="grid-column: span 2;">
      <label>
        <input type="checkbox" name="filtering_enabled" value="1"
          {% if config.filtering_enabled %}checked{% endif %}>
        <strong>Enable DNS Filtering</strong>
      </label>
    </div>

    <div style="grid-column: span 2;">
      <label>
        <input type="checkbox" name="advanced_analysis_enabled" value="1"
          {% if config.advanced_analysis_enabled %}checked{% endif %}>
        <strong>Enable Advanced Analysis</strong>
      </label>
    </div>

    <div style="grid-column: span 2;">
      <label><strong>Add Blacklist URL:</strong></label><br>
      <input name="new_blacklist_url" placeholder="https://example.com/blacklist.txt">
    </div>

    <div style="grid-column: span 2;">
      <label><strong>Add Whitelisted Domain:</strong></label><br>
      <input name="new_whitelist_domain" placeholder="example.com">
    </div>

    <div style="grid-column: span 2; text-align: center;">
      <button type="submit">💾 Save Settings</button>
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

#-----------------------MAIN FLASK DASHBOARD CLASS-----------------------

class Dashboard:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'dev'
        self._setup_routes()

        # Suppress Werkzeug logging for cleaner output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

#-----------------------ROUTE SETUP-----------------------

    def _setup_routes(self):
        @self.app.route("/", methods=["GET", "POST"])
        
#-----------------------DASHBOARD ROUTE-----------------------        
        def dashboard():
            config = load_config()
            config.setdefault("blacklist_urls", [])
            stats = self.get_log_stats(LOG_FILE)
            if request.method == "POST":
                try:
                    #Update config settings
                    config["filtering_enabled"] = "filtering_enabled" in request.form
                    config["advanced_analysis_enabled"] = "advanced_analysis_enabled" in request.form
                    config["model"] = request.form["model"]
                    config["api_url"] = request.form["api_url"]
                    config["dns_port"] = int(request.form["dns_port"])
                    config["dashboard_port"] = int(request.form["dashboard_port"])  # New line
                    config["upstream_dns"] = request.form["upstream_dns"]
                    config["dns_listen_address"] = request.form["dns_listen_address"]
                    config["block_score"] = int(request.form["block_score"])

                    new_url = request.form.get("new_blacklist_url", "").strip()
                    if new_url and new_url not in config["blacklist_urls"]:
                        config["blacklist_urls"].append(new_url)
                        flash("✅ New blacklist URL added.")

                    new_domain = request.form.get("new_whitelist_domain", "").strip().lower()
                    if new_domain:
                        if os.path.exists(WHITELIST_FILE):
                            with open(WHITELIST_FILE, "r") as f:
                                existing = set(line.strip().lower() for line in f)
                        else:
                            existing = set()
                        if new_domain not in existing:
                            with open(WHITELIST_FILE, "a") as f:
                                f.write(new_domain + "\n")
                            flash("✅ Whitelisted domain added.")

                    save_config(config)
                    flash("⚙️ Settings saved successfully! Restart the program to apply them.")
                    return redirect(url_for("dashboard"))

                except Exception as e:
                    return f"<h2>Error:</h2><pre>{e}</pre>"

            return render_template_string(TEMPLATE, config=config, stats=stats)

#-----------------------VIEW LOGS ROUTE-----------------------
        @self.app.route("/logs")
        def view_logs():
            try:
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()[-100:]
            except FileNotFoundError:
                lines = ["Log file not found."]
            return render_template_string(LOG_TEMPLATE, logs=lines)

#-----------------------CLEAR LOG FILE ROUTE-----------------------
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


#-----------------------HELPERS-----------------------

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

    def start(self, host="0.0.0.0", port=None):
        config = load_config()
        actual_port = port or config.get("dashboard_port", 5000)
        self.app.run(host=host, port=actual_port, debug=False, use_reloader=False)

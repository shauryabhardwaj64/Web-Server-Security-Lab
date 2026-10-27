"""
=============================================================================
IIIT Allahabad - Department of Information Technology
Course: Cyber Security (IT-30001) | Autumn Semester 2026
Assignment: Web Server Security - Exploitation & Mitigation
Variant: OS Command Injection - In-band (Command Output Returned)
=============================================================================
Project: Vulnerable Implementation (Standalone)
Port: 5000
=============================================================================
"""

import os
import platform
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)
CURRENT_MODE = "VULNERABLE"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Diagnostic Ping Tool (Vulnerable) | Cyber Security Lab</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --vuln-red: #ef4444;
            --terminal-bg: #030712;
            --terminal-border: #1e293b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 20px;
        }
        .container { width: 100%; max-width: 820px; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        .title-group h1 {
            font-size: 1.4rem;
            font-weight: 700;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .title-group p { font-size: 0.85rem; color: var(--text-muted); margin-top: 4px; }
        .badge {
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 6px 12px;
            border-radius: 9999px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .badge-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #ef4444;
            box-shadow: 0 0 8px #ef4444;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            margin-bottom: 24px;
        }
        .form-group { display: flex; flex-direction: column; gap: 8px; }
        label { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }
        .input-row { display: flex; gap: 12px; }
        input[type="text"] {
            flex: 1;
            background-color: #1e293b;
            border: 1px solid #334155;
            color: #ffffff;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.95rem;
            padding: 12px 16px;
            border-radius: 8px;
            outline: none;
        }
        input[type="text"]:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.2);
        }
        button.btn-primary {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: #ffffff;
            border: none;
            font-weight: 600;
            font-size: 0.9rem;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
        }
        .quick-payloads {
            margin-top: 14px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }
        .quick-label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
        .chip {
            background: #1f2937;
            border: 1px solid #374151;
            color: #93c5fd;
            font-family: ui-monospace, monospace;
            font-size: 0.75rem;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
        }
        .chip-danger { color: #fca5a5; }
        .chip-danger:hover { background: #dc2626; color: #fff; }
        .terminal-card {
            background-color: var(--terminal-bg);
            border: 1px solid var(--terminal-border);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
        }
        .terminal-header {
            background-color: #0f172a;
            padding: 10px 16px;
            border-bottom: 1px solid var(--terminal-border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .window-controls { display: flex; gap: 6px; }
        .dot { width: 10px; height: 10px; border-radius: 50%; }
        .dot-red { background-color: #ef4444; }
        .dot-yellow { background-color: #f59e0b; }
        .dot-green { background-color: #10b981; }
        .terminal-title { color: #64748b; font-size: 0.75rem; font-family: monospace; }
        .command-bar {
            background-color: #0b1120;
            padding: 8px 16px;
            font-family: monospace;
            font-size: 0.8rem;
            color: #f87171;
            border-bottom: 1px solid #1e293b;
        }
        .terminal-body {
            padding: 16px;
            min-height: 160px;
            max-height: 480px;
            overflow-y: auto;
            font-family: ui-monospace, Consolas, monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            color: #e2e8f0;
            white-space: pre-wrap;
        }
        .footer { margin-top: 24px; text-align: center; font-size: 0.8rem; color: #64748b; }
        .footer code { background: #1e293b; color: #94a3b8; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="title-group">
                <h1>Network Diagnostic Ping Tool</h1>
                <p>Cyber Security Lab &bull; In-band OS Command Injection (VULNERABLE BUILD)</p>
            </div>
            <div class="badge">
                <span class="badge-dot"></span>
                Vulnerable Mode (shell=True)
            </div>
        </header>

        <div class="card">
            <form method="POST" action="/" class="form-group">
                <label for="target-input">Target Hostname or IP Address</label>
                <div class="input-row">
                    <input type="text" id="target-input" name="target" value="{{ target }}" placeholder="127.0.0.1" autocomplete="off" required autofocus>
                    <button type="submit" class="btn-primary">Execute Ping</button>
                </div>

                <div class="quick-payloads">
                    <span class="quick-label">Payloads:</span>
                    <button type="button" class="chip" onclick="fillInput('127.0.0.1')">127.0.0.1</button>
                    {% if is_windows %}
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1 & whoami')">127.0.0.1 & whoami</button>
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1 & dir')">127.0.0.1 & dir</button>
                    {% else %}
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1; whoami')">127.0.0.1; whoami</button>
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1; cat /etc/passwd')">127.0.0.1; cat /etc/passwd</button>
                    {% endif %}
                </div>
            </form>
        </div>

        <div class="terminal-card">
            <div class="terminal-header">
                <div class="window-controls">
                    <span class="dot dot-red"></span>
                    <span class="dot dot-yellow"></span>
                    <span class="dot dot-green"></span>
                </div>
                <div class="terminal-title">system_output.log &mdash; Shell Output</div>
                <div></div>
            </div>
            {% if executed_command %}
            <div class="command-bar">
                <span>[SHELL COMMAND] > </span>{{ executed_command }}
            </div>
            {% endif %}
            <div class="terminal-body">
                {%- if output is not none -%}
{{ output }}
                {%- else -%}
                <span style="color: #475569;">Console ready. Awaiting ping command input...</span>
                {%- endif -%}
            </div>
        </div>

        <footer class="footer">
            IIIT Allahabad &bull; Cyber Security (IT-30001) &bull; Vulnerable Server Port: <code>5000</code>
        </footer>
    </div>
    <script>
        function fillInput(val) {
            const input = document.getElementById('target-input');
            input.value = val;
            input.focus();
        }
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    output = None
    target = ""
    executed_command = None
    is_windows = platform.system() == "Windows"
    ping_flag = "-n" if is_windows else "-c"

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if target:
            # =================================================================
            # VULNERABLE CODE PATH:
            # 1. String concatenation with untrusted input `target`
            # 2. shell=True spawns a shell interpreter (cmd.exe or /bin/sh)
            # 3. Metacharacters like &, ;, | trigger arbitrary command execution
            # =================================================================
            try:
                command_str = f"ping {ping_flag} 1 {target}"
                executed_command = command_str
                raw_output = subprocess.check_output(
                    command_str,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    timeout=10
                )
                output = raw_output.decode("utf-8", errors="replace")
            except subprocess.CalledProcessError as e:
                output = e.output.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                output = "Error: Command timed out after 10s."
            except Exception as ex:
                output = f"Execution error: {str(ex)}"

    return render_template_string(
        HTML_TEMPLATE,
        target=target,
        output=output,
        executed_command=executed_command,
        is_windows=is_windows
    )

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  [VULNERABLE APP] Network Diagnostic Ping Tool")
    print(f"  Platform: {platform.system()} | shell=True enabled")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 65 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)

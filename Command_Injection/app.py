"""
=============================================================================
IIIT Allahabad - Department of Information Technology
Course: Cyber Security (IT-30001) | Autumn Semester 2026
Assignment: Web Server Security - Exploitation & Mitigation
Variant: OS Command Injection - In-band (Command Output Returned)
=============================================================================
File: app.py
Description:
    A single-file Python Flask web application demonstrating In-band OS
    Command Injection via a "Network Diagnostic Ping Tool".
    Contains both the VULNERABLE code path (active by default) and the
    MITIGATED code path (commented out by default) with clear instructions
    for live video demonstration and viva defense.
=============================================================================
"""

import os
import platform
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# =============================================================================
# MODE CONFIGURATION (For UI Badge & Status Display)
# =============================================================================
# Set to "VULNERABLE" when BLOCK 1 is active.
# Set to "MITIGATED" when switching to BLOCK 2.
CURRENT_MODE = "VULNERABLE"


# =============================================================================
# EMBEDDED HTML & MINIMALIST DEVELOPER-TOOL DARK CSS TEMPLATE
# =============================================================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Diagnostic Ping Tool | Cyber Security Lab</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --vuln-red: #ef4444;
            --safe-green: #10b981;
            --terminal-bg: #030712;
            --terminal-border: #1e293b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 20px;
        }

        .container {
            width: 100%;
            max-width: 820px;
        }

        /* Top Header */
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
            letter-spacing: -0.02em;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .title-group p {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 4px;
        }

        /* Status Badge */
        .badge {
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            padding: 6px 12px;
            border-radius: 9999px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .badge-vulnerable {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .badge-mitigated {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .badge-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: currentColor;
            box-shadow: 0 0 8px currentColor;
        }

        /* Main Card */
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            margin-bottom: 24px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        label {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .input-row {
            display: flex;
            gap: 12px;
        }

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
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        input[type="text"]:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.2);
        }

        button.btn-primary {
            background: linear-gradient(135deg, #0ea5e9, #0284c7);
            color: #ffffff;
            border: none;
            font-weight: 600;
            font-size: 0.9rem;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.1s;
        }

        button.btn-primary:hover {
            opacity: 0.92;
        }

        button.btn-primary:active {
            transform: scale(0.98);
        }

        /* Payload Quick-Select Chips */
        .quick-payloads {
            margin-top: 14px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            font-size: 0.8rem;
        }

        .quick-label {
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .chip {
            background: #1f2937;
            border: 1px solid #374151;
            color: #93c5fd;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.75rem;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .chip:hover {
            background: #2563eb;
            color: #ffffff;
            border-color: #3b82f6;
        }

        .chip-danger {
            color: #fca5a5;
        }

        .chip-danger:hover {
            background: #dc2626;
            color: #ffffff;
            border-color: #ef4444;
        }

        /* Terminal Window */
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

        .window-controls {
            display: flex;
            gap: 6px;
        }

        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .dot-red { background-color: #ef4444; }
        .dot-yellow { background-color: #f59e0b; }
        .dot-green { background-color: #10b981; }

        .terminal-title {
            color: #64748b;
            font-size: 0.75rem;
            font-family: ui-monospace, monospace;
        }

        .command-bar {
            background-color: #0b1120;
            padding: 8px 16px;
            font-family: ui-monospace, monospace;
            font-size: 0.8rem;
            color: #38bdf8;
            border-bottom: 1px solid #1e293b;
            word-break: break-all;
        }

        .terminal-body {
            padding: 16px;
            min-height: 160px;
            max-height: 480px;
            overflow-y: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            color: #e2e8f0;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .prompt-symbol {
            color: #10b981;
            margin-right: 6px;
            user-select: none;
        }

        .empty-state {
            color: #475569;
            font-style: italic;
        }

        .error-message {
            color: #f87171;
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid #ef4444;
            padding: 10px 14px;
            border-radius: 4px;
            margin-bottom: 12px;
            font-size: 0.85rem;
        }

        /* Footer Info */
        .footer {
            margin-top: 24px;
            text-align: center;
            font-size: 0.8rem;
            color: #64748b;
        }

        .footer code {
            background: #1e293b;
            color: #94a3b8;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.75rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Navigation / Header -->
        <header class="header">
            <div class="title-group">
                <h1>
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="2" y1="12" x2="22" y2="12"></line>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                    </svg>
                    Network Diagnostic Ping Tool
                </h1>
                <p>Cyber Security Lab | In-band OS Command Injection Demonstration</p>
            </div>

            {% if mode == "VULNERABLE" %}
            <div class="badge badge-vulnerable">
                <span class="badge-dot"></span>
                Vulnerable Mode (shell=True)
            </div>
            {% else %}
            <div class="badge badge-mitigated">
                <span class="badge-dot"></span>
                Mitigated Mode (shell=False)
            </div>
            {% endif %}
        </header>

        <!-- Input Form Card -->
        <div class="card">
            <form method="POST" action="/" class="form-group">
                <label for="target-input">Target Hostname or IP Address</label>
                <div class="input-row">
                    <input 
                        type="text" 
                        id="target-input" 
                        name="target" 
                        value="{{ target }}" 
                        placeholder="e.g. 127.0.0.1 or 8.8.8.8" 
                        autocomplete="off" 
                        required 
                        autofocus
                    >
                    <button type="submit" class="btn-primary" id="btn-ping">
                        Execute Ping
                    </button>
                </div>

                <!-- Quick-Fill Payloads for Live Video Demonstration -->
                <div class="quick-payloads">
                    <span class="quick-label">Quick Payloads:</span>
                    <button type="button" class="chip" onclick="fillInput('127.0.0.1')">
                        127.0.0.1 (Benign)
                    </button>
                    {% if is_windows %}
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1 & whoami')">
                        127.0.0.1 & whoami (Win)
                    </button>
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1 & dir')">
                        127.0.0.1 & dir (Win)
                    </button>
                    {% else %}
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1; whoami')">
                        127.0.0.1; whoami (Unix)
                    </button>
                    <button type="button" class="chip chip-danger" onclick="fillInput('127.0.0.1; cat /etc/passwd')">
                        127.0.0.1; cat /etc/passwd (Unix)
                    </button>
                    {% endif %}
                </div>
            </form>
        </div>

        <!-- Terminal Console Output Window -->
        <div class="terminal-card">
            <div class="terminal-header">
                <div class="window-controls">
                    <span class="dot dot-red"></span>
                    <span class="dot dot-yellow"></span>
                    <span class="dot dot-green"></span>
                </div>
                <div class="terminal-title">system_output.log &mdash; In-Band Output Console</div>
                <div></div>
            </div>

            {% if executed_command %}
            <div class="command-bar">
                <span class="prompt-symbol">$</span>{{ executed_command }}
            </div>
            {% endif %}

            <div class="terminal-body" id="terminal-body">
                {%- if error -%}
                <div class="error-message">{{ error }}</div>
                {%- endif -%}
                {%- if output is not none -%}
{{ output }}
                {%- else -%}
                <span class="empty-state">Console ready. Enter an IP address or click a quick payload to execute diagnostic probe...</span>
                {%- endif -%}
            </div>
        </div>

        <footer class="footer">
            IIIT Allahabad &bull; Cyber Security (IT-30001) &bull; Table 1 Variant: <code>In-band OS Command Injection</code>
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


# =============================================================================
# FLASK ROUTE: VULNERABILITY & MITIGATION LOGIC
# =============================================================================
@app.route("/", methods=["GET", "POST"])
def index():
    output = None
    target = ""
    error = None
    executed_command = None

    is_windows = platform.system() == "Windows"
    ping_flag = "-n" if is_windows else "-c"

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if not target:
            error = "Please provide an IP address or hostname."
            return render_template_string(
                HTML_TEMPLATE,
                mode=CURRENT_MODE,
                target=target,
                output=output,
                error=error,
                executed_command=executed_command,
                is_windows=is_windows
            )

        # =====================================================================
        # BLOCK 1: VULNERABLE IMPLEMENTATION (Active by Default)
        # =====================================================================
        # ROOT CAUSE:
        # User input is directly concatenated into the command string passed to
        # subprocess.check_output with shell=True. This instructs the OS to spawn
        # a command shell interpreter (cmd.exe on Windows, /bin/sh on Linux/Unix).
        # The shell parses metacharacters like '&', '&&', ';', '|', executing
        # arbitrary secondary commands with the privileges of the web server process.
        # Output is captured and returned directly to the user (In-band Injection).
        # =====================================================================
        try:
            command_str = f"ping {ping_flag} 1 {target}"
            executed_command = command_str

            # VULNERABLE: Direct string concatenation + shell=True
            raw_output = subprocess.check_output(
                command_str,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=10
            )
            output = raw_output.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            # Captures in-band output even if the command returns a non-zero exit status
            output = e.output.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            error = "Execution timed out after 10 seconds."
        except Exception as ex:
            error = f"Execution error: {str(ex)}"

        # =====================================================================
        # BLOCK 2: MITIGATED IMPLEMENTATION (Commented Out by Default)
        # =====================================================================
        # MITIGATION MECHANISM:
        # Parameterized Execution with an Argument Vector (shell=False).
        #
        # Instead of passing a raw string to a shell interpreter, the command
        # and arguments are passed as a discrete list (array of strings) directly
        # to the operating system's process creation API (CreateProcess on Windows,
        # execve on Linux/POSIX).
        #
        # With shell=False, NO shell interpreter is invoked. Shell metacharacters
        # (;, &, |, `, $, etc.) lose their semantic meaning and are treated
        # strictly as literal text representing a single argument (the hostname).
        # The ping binary safely reports "unknown host", completely neutralizing
        # command execution.
        #
        # ---------------------------------------------------------------------
        # TO SWITCH TO MITIGATED MODE FOR VIDEO DEMO / VIVA:
        # 1. Comment out BLOCK 1 above.
        # 2. Uncomment the code block below.
        # 3. Change CURRENT_MODE = "MITIGATED" at line 25 of this file.
        # ---------------------------------------------------------------------
        # try:
        #     # Parameterized argument vector - direct invocation without shell
        #     cmd_args = ["ping", ping_flag, "1", target]
        #     executed_command = " ".join(cmd_args)
        #
        #     raw_output = subprocess.check_output(
        #         cmd_args,
        #         shell=False,
        #         stderr=subprocess.STDOUT,
        #         timeout=10
        #     )
        #     output = raw_output.decode("utf-8", errors="replace")
        # except subprocess.CalledProcessError as e:
        #     # Safe failure: ping treats the payload as an invalid host name
        #     output = e.output.decode("utf-8", errors="replace")
        # except subprocess.TimeoutExpired:
        #     error = "Execution timed out after 10 seconds."
        # except Exception as ex:
        #     error = f"Execution error: {str(ex)}"
        # =====================================================================

    return render_template_string(
        HTML_TEMPLATE,
        mode=CURRENT_MODE,
        target=target,
        output=output,
        error=error,
        executed_command=executed_command,
        is_windows=is_windows
    )


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  NETWORK DIAGNOSTIC PING TOOL - CYBER SECURITY LAB")
    print(f"  Current Status : [{CURRENT_MODE} MODE]")
    print(f"  Host Platform  : [{platform.system()} {platform.release()}]")
    print("  Server running at: http://127.0.0.1:5000")
    print("=" * 65 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)

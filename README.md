# SQLiX Injection Detection Demo

A Flask‐based web application that demonstrates a multi‐layer SQL Injection (SQLiX). Incoming text inputs are analyzed through several layers of pattern matching (regex, keyword checks, boolean tests, and a simple Petri‐net‐style flow check). Detected injection attempts are logged to `sqliX.log` and (optionally) sent to a Discord webhook for real‐time alerting.

---

## Table of Contents

1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Configuration](#configuration)  
5. [Usage](#usage)  
6. [Detection Layers](#detection-layers)  
7. [Log File](#log-file)  
8. [Discord Alerts](#discord-alerts)  
9. [File Structure](#file-structure)  

---

## Features

- **Layer 1 (Regex Patterns):**  
  - Numeric comparisons (e.g. `1234 = 5678`)  
  - LIKE operator checks (e.g. `foo LIKE 'bar'`)  
  - Database built-in function calls (`dbms_pipe.receive_message`, `randomblob`, etc.)  
  - Arithmetic-blind tricks (e.g. `) * 1234`)  
  - Standard SQL keywords (`SELECT`, `INSERT`, `DELETE`, etc.)  
  - Tautologies (`OR 1=1`, etc.)  
  - SQL comment markers (`--`, `#`, `/* … */`, `;`)  
  - Function‐call patterns (`CHAR(…)`, `VARCHAR(…)`, `CAST(…)`, `CONVERT(…)`)  

- **Layer 2 (Keyword Randomization):**  
  - Detects any remaining canonical SQL keywords (e.g. `SELECT`, `UPDATE`, `DROP`, etc.) even if payloads are obfuscated.

- **Layer 3 (Boolean-Based False Conditions):**  
  - Flags common boolean‐based SQLi patterns like `OR 1=0` or `|| (0)`.

- **Layer 4 (Petri-Net-Style Sequence Checks):**  
  - A lightweight flow‐based check for second-order or time-based SQLi (e.g. `sleep(…)`, `benchmark(…)`, `‘ UNION SELECT …`, etc.).

- **Logging & Alerting:**  
  - Every detection (or safe pass) is appended to `sqliX.log` with a timestamp, severity, and matched pattern.  
  - High‐severity (Layer 1 or Layer 4) detections trigger a Discord webhook alert.

- **Web Interface:**  
  - Simple HTML form for submitting input strings.  
  - Displays a “Detection Report” and a running “Detection Log” in the browser.

---

## Prerequisites

- **Python 3.7+** installed on your machine.  
- (Optional) A Discord server and a valid webhook URL if you want real‐time alerts.

---

## Installation

1. Clone or download this repository to your local machine.  
2. (Optional but recommended) Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate       # macOS/Linux
   .venv\Scripts\activate          # Windows
   ```
3. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## Configuration

1. Discord Webhook  
   If you want Discord notifications, copy your webhook URL. Open `sqliX_demo.py` (or `app.py`) and set the `DISCORD_WEBHOOK_URL` variable:
   ```python
   DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/your_webhook_id/your_webhook_token"
   ```
   If you leave `DISCORD_WEBHOOK_URL = ""`, no alerts will be sent.

2. Port and Debug Mode  
   By default, the Flask app runs on port 5000 with debug mode enabled. To change the port, edit the last lines:
   ```python
   if __name__ == "__main__":
       app.run(debug=True, port=5000)
   ```

---

## Usage

1. Start the Flask server:
   ```bash
   python sqliX_demo.py
   ```
2. Open your browser and navigate to http://127.0.0.1:5000.  
3. Enter any text in the “Enter input…” field and click Analyze.  
   - If a SQLi pattern is detected, the page will show a red “⚠️ Potential SQL Injection Detected!” report, listing the layer, matched pattern, severity, and timestamp.  
   - If no injection is found, a green “✅ No SQL injection detected.” message appears.  
4. The Detection Log table at the bottom continuously appends each submission (both malicious and safe).

---

## Detection Layers

1. **Layer 1: Classic Regex Patterns**  
   Uses regular expressions to catch common SQLi syntax (numeric comparisons, built-in functions, SQL comments, keywords, etc.).

2. **Layer 2: Keyword Randomization**  
   Scans for any canonical SQL keywords leftover in the decoded input string (case-insensitive). If found, flags as SQLi.

3. **Layer 3: Boolean-Based Checks**  
   Detects `OR/AND 1=0` tautology patterns and the short‐circuit `|| (0)` or `|| (1=0)` syntax.

4. **Layer 4: Petri-Net-Style Flow**  
   Converts input into lowercase “tokens” (alphanumeric sequences, comment markers, punctuation, etc.) and checks for suspicious token sequences:
   - `["admin", "'"]` → login bypass  
   - `["'", "union", "select"]` → data extraction  
   - `["'", "or", "1", "=", "1"]` → tautology  
   - `["'||", "select"]` → string injection  
   - `["sleep"]`, `["benchmark"]`, `["pg_sleep"]`, `["waitfor", "delay"]` → time-based

---

## Log File

Location: `sqliX.log` in the same directory as the Flask app.  
Format: Each entry is appended as a new line:
```
[YYYY-MM-DD HH:MM:SS] [Severity] LayerName – Pattern | Input: user_submitted_input
```
Both safe and malicious submissions are logged.  
- Safe entries have `Severity = None` and `Pattern = No injection detected`.  
- Malicious entries list the matching layer, pattern snippet, and severity classification (High or Medium).

---

## Discord Alerts

When a High severity detection (Layer 1 or Layer 4) occurs, the app:

1. Sends a JSON payload to the configured `DISCORD_WEBHOOK_URL` containing an embed with:  
   - Title: “🚨 SQL Injection Attempt Detected!”  
   - Fields: Input text, Match Type (layer), Pattern, Severity, Time

2. Uploads the full `sqliX.log` file to Discord as an attached file.  
   If the webhook URL is blank or invalid, alerts will be skipped (no error raised).

---

## File Structure

```
.
├── sqliX_demo.py       # Main Flask application
├── requirements.txt    # Python dependencies
├── sqliX.log           # Auto-generated detection log (created at runtime)
└── README.md           # This README file
```

---

## Running in Production

For production deployment, consider:
- Disabling `debug=True` in `app.run()`.  
- Using a production WSGI server (e.g., Gunicorn) behind a reverse proxy (e.g., Nginx).  
- Securing the Discord webhook URL and log file permissions.  
- Enabling HTTPS on your server.

from flask import Flask, request, render_template_string
import re, random, string, datetime, requests
import urllib.parse
import json

app = Flask(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1371030100115460146/AjX94u6xpdKKafXhqMgmDH5dWjqkgyOZ5Dd5Ac1PJYpwFF20U5wmRccMFUgpNpwbtzJc"
# ────────────────────────────────────────────────────────────────────────────────

# ─── Layer 1: Classic Regex Patterns ───────────────────────────────────────────
patterns = [
    # ─── catch “3400=6002” etc ────────────────────────────
    {"name": "Numeric Comparison",
    "regex": re.compile(r"(?<!\w)(\d+\s*=\s*\d+)(?!\w)")},

    # ─── catch “foo like 'bar'” tests ──────────────────────
    {"name": "LIKE Operator",
    "regex": re.compile(r"(?i)\bLIKE\b\s*['\"]?\w+")},

    # ─── catch built-ins & procedural calls ─────────────────
    {"name": "DB Built-in Func",
    "regex": re.compile(
      r"(?i)\b(?:dbms_pipe\.receive_message|randomblob|generate_series|hex|upper|lower|make_set|iif|elt|regexp_substring)\b"
    )},

    # ─── catch arithmetic-blind tricks “) * 1234” ─────────────
    {"name": "Arithmetic Injection",
    "regex": re.compile(r"\)\s*\*\s*\d+")},

    # ─── your existing four ──────────────────────────────────
    {"name": "SQL Keyword",    "regex": re.compile(r"(?i)(?<!\w)(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|UNION|EXEC|TRUNCATE)(?!\w)")},
    {"name": "Tautology",       "regex": re.compile(r"(?i)\b(?:OR|AND)\b\s*'?1'?\s*=\s*'?1'?")},
    {"name": "SQL Comment",     "regex": re.compile(r"--|#|/\*|\*/|;")},
    {"name": "Function Call",   "regex": re.compile(r"(?i)\b(?:CHAR\s*\(|VARCHAR\s*\(|CAST\s*\(|CONVERT\s*\()\b")},
]
# ────────────────────────────────────────────────────────────────────────────────

detection_log = []

def write_to_log(entry):
    with open("sqliX.log", "a") as log_file:
        log_file.write(
            f"[{entry['timestamp']}] [{entry['severity']}] "
            f"{entry['match_type']} - {entry['pattern']} | Input: {entry['input']}\n"
        )

def notify_discord(entry):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        # 1) send the embed
        embed_payload = {
            "username": "SQLiX Alert",
            "embeds": [{
                "title": "🚨 SQL Injection Attempt Detected!",
                "color": 16711680,
                "fields": [
                    {"name": "Input",      "value": entry['input'],      "inline": False},
                    {"name": "Match Type", "value": entry['match_type'], "inline": True},
                    {"name": "Pattern",    "value": entry['pattern'],    "inline": True},
                    {"name": "Severity",   "value": entry['severity'],   "inline": True},
                    {"name": "Time",       "value": entry['timestamp'],  "inline": False}
                ]
            }]
        }
        requests.post(DISCORD_WEBHOOK_URL, json=embed_payload, timeout=3)

        # 2) then upload the log file
        with open("sqliX.log", "rb") as f:
            requests.post(
                DISCORD_WEBHOOK_URL,
                files={"file": ("sqliX.log", f, "text/plain")},
                timeout=3
            )
    except Exception as e:
        print(f"❌ Discord notification failed: {e}")

def mock_petri_net_model(input_text):
    """
    Layer 4: Petri-Net–style detection, which now also
    catches time-based functions and second-order (quote)
    attacks if they slip past the first three layers.
    """
    # normalize various quote characters → ASCII `'`
    normalized = (
        input_text
        .replace("‘", "'")
        .replace("’", "'")
        .replace("“", '"')
        .replace("”", '"')
        .replace("`", "'")
    )
    # split out words, punctuation tokens, comment markers, ||, etc.
    tokens = re.findall(r"[a-zA-Z0-9_]+|--|\|\||['\"=><!]+", normalized.lower())

    suspicious_flows = [
        # second-order / login-bypass:
        ["admin", "'"],

        # data extraction:
        ["'", "union", "select"],

        # tautology:
        ["'", "or", "1", "=", "1"],

        # string injection:
        ["'||", "select"],

        # time-based (all functors here):
        ["sleep"],      # e.g. sleep(5)
        ["benchmark"],  # benchmark(…)
        ["pg_sleep"],   # pg_sleep(…)
        ["waitfor", "delay"],
    ]

    for flow in suspicious_flows:
        if all(token in tokens for token in flow):
            return True, f"PetriNet Sequence Match ({' → '.join(flow)})"
    return False, None

def randomize_keywords(query: str) -> bool:
    """
    Layer 2: simply see if any canonical SQL keyword remains
    (we’re not actually randomizing it here, just flagging its presence)
    """
    keywords = ["SELECT","INSERT","UPDATE","DELETE","DROP","ALTER","WHERE","FROM","UNION","AND","OR","EXEC","TRUNCATE"]
    for kw in keywords:
        if re.search(rf"(?i)\b{re.escape(kw)}\b", query):
            return True
    return False

def detect_sqli(input_text: str):
    decoded = urllib.parse.unquote_plus(input_text)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ─── Layer 1: RegEx ─────────────────────────────────────────────────────────
    for pat in patterns:
        m = pat["regex"].search(decoded)
        if m:
            return [{
                "input": input_text,
                "match_type": "Regex",
                "pattern": f"{pat['name']} ('{m.group(0)}')",
                "severity": "High",
                "timestamp": ts
            }], input_text

    # ─── Layer 2: Keyword Randomization ─────────────────────────────────────────
    if randomize_keywords(decoded):
        return [{
            "input": input_text,
            "match_type": "Keyword Randomization",
            "pattern": "Detected SQL keyword via token match",
            "severity": "Medium",
            "timestamp": ts
        }], input_text

    # ─── Layer 3: Boolean-Based ─────────────────────────────────────────────────
    # detect OR/AND 1=0
    bm1 = re.search(r"(?i)\b(?:or|and)\b\s*1\s*=\s*0", decoded)
    # detect "|| (0)" or "|| (1=0)"
    bm2 = re.search(r"\|\|\s*\(?\s*(?:0|1\s*=\s*0)\s*\)?", decoded)
    if bm1 or bm2:
        m = bm1 or bm2
        return [{
            "input":      input_text,
            "match_type": "Boolean",
            "pattern":    f"False condition ('{m.group(0)}')",
            "severity":   "Medium",
            "timestamp":  ts
        }], input_text
    

    # ─── Layer 4: Petri-Net (incl. time-based & second-order) ────────────────────
    petri_hit, petri_pat = mock_petri_net_model(decoded)
    if petri_hit:
        return [{
            "input": input_text,
            "match_type": "Petri Net",
            "pattern": petri_pat,
            "severity": "High",
            "timestamp": ts
        }], input_text

    # ─── No detection ────────────────────────────────────────────────────────────
    return [], input_text

@app.route("/", methods=["GET","POST"])
def index():
    results = []
    if request.method == "POST":
        txt = request.form["input_text"]
        results, _ = detect_sqli(txt)
        if results:
            for r in results:
                write_to_log(r)
                if r["severity"] == "High":
                    notify_discord(r)
            detection_log.extend(results)
        else:
            # log safe
            safe = {
                "input": txt,
                "match_type": "None",
                "pattern": "No injection detected",
                "severity": "None",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            write_to_log(safe)
            detection_log.append(safe)

    return render_template_string("""
<!doctype html>
<html><head><title>SQLiX Demo</title>
  <style>
    body { font-family:sans-serif; padding:20px }
    table { width:100%; border-collapse:collapse; margin-top:1em }
    th,td { border:1px solid #ccc; padding:6px }
    th { background:#eee }
    .high td { background:#fdd }
    .medium td { background:#ffd }
    .none  td { background:#dfd }
  </style>
</head><body>
  <h1>🛡️ SQLiX Injection Detection Demo</h1>
  <form method="POST">
    <input name="input_text" style="width:60%" placeholder="Enter input…" required>
    <button>Analyze</button>
  </form>
  {% if results %}
    <h2>Detection Report</h2>
    {% if results|length==0 %}
      <p style="color:green"><strong>✅ No SQL injection detected.</strong></p>
    {% else %}
      <p style="color:red"><strong>⚠️ Potential SQL Injection Detected!</strong></p>
      <table>
        <tr><th>Input</th><th>Layer</th><th>Pattern</th><th>Severity</th><th>Time</th></tr>
        {% for r in results %}
          <tr class="{{r.severity|lower}}">
            <td>{{r.input}}</td>
            <td>{{r.match_type}}</td>
            <td>{{r.pattern}}</td>
            <td>{{r.severity}}</td>
            <td>{{r.timestamp}}</td>
          </tr>
        {% endfor %}
      </table>
    {% endif %}
  {% endif %}
  <h2>Detection Log</h2>
  <table>
    <tr><th>Input</th><th>Layer</th><th>Pattern</th><th>Severity</th><th>Time</th></tr>
    {% for l in detection_log %}
      <tr class="{{l.severity|lower}}">
        <td>{{l.input}}</td><td>{{l.match_type}}</td><td>{{l.pattern}}</td>
        <td>{{l.severity}}</td><td>{{l.timestamp}}</td>
      </tr>
    {% endfor %}
  </table>
</body></html>
""", results=results, detection_log=detection_log)

if __name__=="__main__":
    app.run(debug=True, port=5000)
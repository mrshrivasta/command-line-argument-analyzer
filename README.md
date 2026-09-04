# Command-Line Argument Analyzer

**A real, no-mock-data command-line argument threat analyzer for process-list export CSVs — CLI + Web App.**
Parses real forensic/IR process-list exports and flags defense-evasion flags, excessively long command lines, embedded network indicators on non-browser processes, high escape-character density, repeated identical command lines across many processes, and rows with missing captured command lines — by real-parsing the actual `CommandLine` text present in the CSV.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and digital-forensics/incident-response (DFIR) purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against process-list export CSVs that you own, that you collected from systems you administer, or for which you have explicit, documented authorization to analyze. Analyzing data collected without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction) and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including missed detections, false accusations, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a certified forensic tool.** This tool is **not a substitute** for a certified DFIR platform, a professional incident-response engagement, or a review by a qualified security analyst. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a host was not compromised. This tool checks a specific, limited set of command-line-argument heuristics only, and only over what the source export actually captured.
- **Read-only by design.** The Security Engine only reads the CSV file(s) you point it at — it never modifies, deletes, or writes back to the source export, and it never touches the live process list of any machine. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything sensitive.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given export, **do not run this tool against it.**

---

## Who should use this project

- Incident responders and SOC analysts triaging a real `Get-CimInstance Win32_Process` / `tasklist` / Sysmon export pulled from a host during an investigation.
- DFIR practitioners and threat hunters who want a quick, scriptable first pass over process-list exports before deeper analysis.
- Security students and self-learners studying command-line-argument-based defense-evasion techniques (encoded PowerShell, hidden windows, LOLBin abuse).
- CI/CD or SOC automation pipelines that want a command-line-argument-hygiene gate over collected exports (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from real-parsing the actual `CommandLine` text of an actual process-list export CSV you provide. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented pure-Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI/SOC automation) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Expected input: a real process-list export CSV

This tool ingests a **real process-list export CSV** — the standard real forensic/IR input format. It does **not** enumerate live processes itself; you generate the export with a standard tool and point this analyzer at the resulting file (or a directory of them).

### Expected real CSV columns

| Column | Required? | Description |
|---|---|---|
| `Name` | **Required** | Process image name, e.g. `powershell.exe` |
| `CommandLine` | **Required** | The full real command line the process was launched with — this is what every rule analyzes |
| `ProcessId` | Recommended | Real PID, used for CLA-005 distinct-process grouping |
| `ParentProcessId` | Recommended | Real parent PID |
| `ExecutablePath` | Recommended | Full real path to the executable image |
| `CreationDate` | Recommended | Real process start timestamp |
| `User` | Recommended | Real account the process ran as |

A reasonable real subset is tolerated — the hard minimum is **`Name` + `CommandLine`**. Header matching is case/whitespace-insensitive.

### How to produce a real export

**PowerShell (Windows, live host or WinRM against a remote host):**
```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate |
  Export-Csv -Path processes.csv -NoTypeInformation
```

**`tasklist` (Windows, quick local capture):**
```cmd
tasklist /v /fo csv > processes.csv
```

**Sysmon Event ID 1 (Process Create) or Windows Security Event ID 4688, normalized to CSV:**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = @{}
    $xml.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [PSCustomObject]@{
      ProcessId = $d.ProcessId; ParentProcessId = $d.ParentProcessId
      Name = $d.Image; ExecutablePath = $d.Image
      CommandLine = $d.CommandLine; CreationDate = $d.UtcTime; User = $d.User
    }
  } | Export-Csv -Path sysmon_processes.csv -NoTypeInformation
```

Once you have a real CSV (single file, or a directory of them), give its path to the CLI or the web app's "Run a New Scan" form.

---

## Architecture

```
command-line-argument-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real CSV-parsing engine (csv.DictReader + shlex tokenizer)
│   ├── detection_rules/      # 6 documented detection rules (CLA-001..CLA-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp CSV files + real DictReader/shlex parsing
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, dir-walk depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| CLA-001 | Defense-Evasion Flag Present | High | Real `CommandLine` contains a common attacker/evasion flag (`-nop`, `-noni`, `-w hidden`, `-windowstyle hidden`, `/c`, `-enc`, `-EncodedCommand`, `--no-check-certificate`, `-ExecutionPolicy Bypass`) |
| CLA-002 | Excessively Long Command Line | Medium | Real `CommandLine` character length exceeds 500 characters — common obfuscation/complexity signal |
| CLA-003 | Embedded Network Indicator | Medium | Real IP literal or URL embedded directly as an argument to a non-browser process (`Name` not in `chrome.exe`/`firefox.exe`/`msedge.exe`/`curl.exe`/`wget.exe`) |
| CLA-004 | High Escape-Character Density | Low | Real count of `"`/`'`/`` ` ``/`^` characters exceeds 15% of total `CommandLine` length — obfuscation-via-escaping heuristic |
| CLA-005 | Repeated Identical Command Line | Medium | The exact same real `CommandLine` string appears across 5+ distinct real `ProcessId`s in one CSV — scripted/repeated process spawning |
| CLA-006 | Missing Command Line | Low | Real row has a `Name` but an empty/missing `CommandLine` — informational parse-note, nothing to analyze |

---

## Setup & Run

### Requirements
- Python 3.9+
- Any OS Python runs on (the analyzer only reads CSV text files — no OS-specific APIs are used)

### Install

```bash
git clone <this-repository-url>
cd command-line-argument-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
CLAA_SECRET_KEY=change-me  # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/claa.db`.

### Run the CLI

```bash
python3 cli/main.py scan processes.csv
python3 cli/main.py scan ./exports --depth 2
python3 cli/main.py scan processes.csv --json
python3 cli/main.py scan processes.csv --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/SOC-automation gate) and `0` if the export is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

All tests use real temporary CSV files written with `csv.DictWriter` and parsed with the real `ScanEngine` (plus full web-route integration tests) — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Command-Line Argument Analyzer check?**
It real-parses a real process-list export CSV and flags defense-evasion flags, excessively long command lines, embedded IP addresses/URLs on non-browser processes, high escape-character density, repeated identical command lines across many distinct processes, and rows missing captured command-line data — using the actual `CommandLine` text present in the CSV.

**Where do I get a process-list export CSV?**
Run `Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | Export-Csv` on Windows, `tasklist /v /fo csv`, or normalize a Sysmon Event ID 1 / Windows Event ID 4688 export to CSV. See "Expected input" above for full examples.

**Who should use it?**
Incident responders, SOC analysts, DFIR practitioners, and security students triaging process-list exports they own or are authorized to analyze.

**Is it a replacement for a professional security audit or DFIR engagement?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it enumerate live processes on my machine?**
No. It only reads the CSV file(s) you point it at. It never queries the live process list, and it never writes to, deletes, or modifies the source export.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

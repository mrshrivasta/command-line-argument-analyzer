"""
Detection Rules — Command-Line Argument Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL, parsed process-list row (built from an actual
process-list export CSV — see app/security_engine for the parsing logic) and
returns a Finding dict if the condition is met. Rules are intentionally
conservative, pure functions, and documented so results can be independently
verified by reading the source CSV in a text editor.

A "row" dict passed to every per-row rule has (at minimum) these keys, all
sourced directly from the CSV with no fabrication:
    process_id       -> str, the CSV ProcessId column (may be "")
    parent_pid        -> str, the CSV ParentProcessId column (may be "")
    name               -> str, the CSV Name column (process image name)
    executable_path    -> str, the CSV ExecutablePath column (may be "")
    command_line       -> str, the CSV CommandLine column (the raw string analyzed)
    tokens              -> list[str], command_line tokenized via shlex/whitespace
    creation_date       -> str, the CSV CreationDate column (may be "")
    user                -> str, the CSV User column (may be "")
    source_file         -> str, the real CSV file path this row came from

The cross-row rule (rule_repeated_identical_command_line) instead receives the
full list of parsed rows for one CSV file and emits one Finding per group of
duplicate CommandLine strings that meets the threshold.
"""
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Common attacker/defense-evasion flags seen across PowerShell, cmd.exe,
# wscript/cscript, wget, and other LOLBins. Case-insensitive.
EVASION_FLAG_PATTERN = re.compile(
    r"("
    r"-nop\b|-noni\b|-w\s+hidden|-windowstyle\s+hidden|/c\b|-enc\b|-e\s|"
    r"-encodedcommand|--no-check-certificate|-executionpolicy\s+bypass"
    r")",
    re.IGNORECASE,
)

# Real IPv4 literal or URL embedded directly in an argument.
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"\b\w+://[^\s'\"]+", re.IGNORECASE)

# Small, real allowlist of processes that are *expected* to embed URLs/IPs
# as normal, legitimate behavior.
BROWSER_ALLOWLIST = {"chrome.exe", "firefox.exe", "msedge.exe", "curl.exe", "wget.exe"}

LONG_COMMAND_LINE_THRESHOLD = 500  # characters
ESCAPE_DENSITY_THRESHOLD = 0.15  # 15% of characters
ESCAPE_CHARS = set('"\'`^')
REPEATED_COMMAND_THRESHOLD = 5  # distinct ProcessIds sharing one CommandLine


def rule_evasion_flag_present(row):
    """CLA-001: The real CommandLine contains a real argument matching common
    defense-evasion / attacker flags used across many real tools (PowerShell
    -nop/-noni/-w hidden/-enc/-EncodedCommand/-ExecutionPolicy Bypass,
    cmd.exe /c, wget --no-check-certificate). High risk — these flags are
    disproportionately used to hide execution or evade logging/inspection."""
    cmd = row.get("command_line") or ""
    match = EVASION_FLAG_PATTERN.search(cmd)
    if match:
        return {
            "rule_id": "CLA-001",
            "rule_name": "Defense-Evasion Flag Present",
            "severity": SEVERITY_HIGH,
            "description": (
                f"Process '{row.get('name')}' (PID {row.get('process_id')}) was launched "
                f"with a command line containing the evasion-associated flag "
                f"'{match.group(0).strip()}': {cmd[:300]}"
            ),
            "matched_snippet": match.group(0).strip(),
        }
    return None


def rule_excessively_long_command_line(row):
    """CLA-002: The real CommandLine's total character length exceeds a real
    threshold (default 500 characters). Unusually long command lines are a
    common signal of obfuscation, embedded encoded payloads, or scripted
    complexity worth reviewing manually."""
    cmd = row.get("command_line") or ""
    length = len(cmd)
    if length > LONG_COMMAND_LINE_THRESHOLD:
        return {
            "rule_id": "CLA-002",
            "rule_name": "Excessively Long Command Line",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Process '{row.get('name')}' (PID {row.get('process_id')}) has a command "
                f"line {length} characters long (threshold {LONG_COMMAND_LINE_THRESHOLD})."
            ),
            "matched_snippet": cmd[:200] + ("..." if length > 200 else ""),
        }
    return None


def rule_embedded_network_indicator(row):
    """CLA-003: The real CommandLine contains a real IP-address literal or a
    real URL embedded directly as an argument to a process whose Name is NOT
    in the small browser/downloader allowlist. A non-browser process reaching
    directly out to a network address in its own command line is common
    downloader/dropper behavior."""
    cmd = row.get("command_line") or ""
    name = (row.get("name") or "").strip().lower()
    if name in BROWSER_ALLOWLIST:
        return None
    match = URL_PATTERN.search(cmd) or IP_PATTERN.search(cmd)
    if match:
        return {
            "rule_id": "CLA-003",
            "rule_name": "Embedded Network Indicator",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Non-browser process '{row.get('name')}' (PID {row.get('process_id')}) has "
                f"a network indicator '{match.group(0)}' embedded directly in its command line."
            ),
            "matched_snippet": match.group(0),
        }
    return None


def rule_high_escape_density(row):
    """CLA-004: The real CommandLine's count of quote/escape characters
    (", ', `, ^) exceeds a real proportion of the total command-line length
    (default >15%). High escape-character density is a common heuristic for
    obfuscation-via-escaping / nested-quoting evasion techniques."""
    cmd = row.get("command_line") or ""
    length = len(cmd)
    if length == 0:
        return None
    escape_count = sum(1 for ch in cmd if ch in ESCAPE_CHARS)
    density = escape_count / length
    if density > ESCAPE_DENSITY_THRESHOLD:
        return {
            "rule_id": "CLA-004",
            "rule_name": "High Escape-Character Density",
            "severity": SEVERITY_LOW,
            "description": (
                f"Process '{row.get('name')}' (PID {row.get('process_id')}) has {escape_count} "
                f"escape/quote characters out of {length} total ({density:.0%}), "
                f"above the {ESCAPE_DENSITY_THRESHOLD:.0%} threshold."
            ),
            "matched_snippet": cmd[:200] + ("..." if length > 200 else ""),
        }
    return None


def rule_missing_command_line(row):
    """CLA-006: The real row's CommandLine field was empty/missing while Name
    was present. Informational — the export captured that a process existed
    but not the arguments it ran with, so no argument-level analysis is
    possible for this row."""
    cmd = (row.get("command_line") or "").strip()
    name = (row.get("name") or "").strip()
    if name and not cmd:
        return {
            "rule_id": "CLA-006",
            "rule_name": "Missing Command Line",
            "severity": SEVERITY_LOW,
            "description": (
                f"Row for process '{name}' (PID {row.get('process_id')}) has no CommandLine "
                f"captured in the export — argument-level analysis is not possible for this row."
            ),
            "matched_snippet": "",
        }
    return None


# Per-row rules: called once for every parsed CSV row.
ROW_RULES = [
    rule_evasion_flag_present,
    rule_excessively_long_command_line,
    rule_embedded_network_indicator,
    rule_high_escape_density,
    rule_missing_command_line,
]


def rule_repeated_identical_command_line(rows, source_file):
    """CLA-005: The SAME real CommandLine string (exact match) appears across
    an unusually high real number of DISTINCT ProcessId rows within one CSV
    (default threshold 5+). Identical arguments repeated across many distinct
    processes is common evidence of repeated/scripted process spawning (e.g.
    a malicious scheduled task or loop launching the same payload)."""
    findings = []
    groups = {}
    for row in rows:
        cmd = (row.get("command_line") or "").strip()
        if not cmd:
            continue
        pid = row.get("process_id") or ""
        groups.setdefault(cmd, set()).add(pid)

    for cmd, pids in groups.items():
        if len(pids) >= REPEATED_COMMAND_THRESHOLD:
            findings.append({
                "rule_id": "CLA-005",
                "rule_name": "Repeated Identical Command Line",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"The exact command line '{cmd[:200]}' appears across "
                    f"{len(pids)} distinct ProcessIds in {source_file} "
                    f"(threshold {REPEATED_COMMAND_THRESHOLD})."
                ),
                "matched_snippet": cmd[:200] + ("..." if len(cmd) > 200 else ""),
                "name": None,
                "process_id": ",".join(sorted(pids, key=lambda x: (len(x), x))[:10]),
                "source_file": source_file,
            })
    return findings


ALL_RULES = [
    rule_evasion_flag_present,
    rule_excessively_long_command_line,
    rule_embedded_network_indicator,
    rule_high_escape_density,
    rule_repeated_identical_command_line,
    rule_missing_command_line,
]

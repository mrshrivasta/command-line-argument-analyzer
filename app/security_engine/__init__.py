"""
Security Engine — Command-Line Argument Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses process-list export CSV files (the standard real forensic/IR
input format — e.g. real output of
`Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,
ExecutablePath,CommandLine,CreationDate | Export-Csv`, a real Sysmon Event
ID 1 / Windows Event ID 4688 export normalized to CSV, or
`tasklist /v /fo csv`) and runs every rule in app.detection_rules against
every real row it can parse. No sample/mock data is ever generated — every
Finding reflects the actual CommandLine text present in the CSV at scan
time.

Expected real CSV columns (a reasonable real subset is tolerated — the only
hard requirement is Name + CommandLine):
    ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine,
    CreationDate, User

Designed to run unprivileged and never crash on malformed input: rows or
files that cannot be parsed are counted as errors and skipped, never
fabricated.
"""
import csv
import os
import shlex
import time

from app.detection_rules import ALL_RULES, ROW_RULES, rule_repeated_identical_command_line

REQUIRED_COLUMNS = {"name", "commandline"}


def _normalize_header(fieldnames):
    """Map real CSV header names (case/whitespace tolerant) to our canonical keys."""
    mapping = {}
    if not fieldnames:
        return mapping
    for raw in fieldnames:
        if raw is None:
            continue
        key = raw.strip().lower().replace(" ", "").replace("_", "")
        mapping[key] = raw
    return mapping


def _tokenize(command_line):
    """Real-tokenize a real CommandLine string. shlex.split handles POSIX-style
    quoting well; Windows-style paths (backslashes, unbalanced quotes) can make
    shlex raise ValueError, so we fall back to naive whitespace-splitting."""
    if not command_line:
        return []
    try:
        return shlex.split(command_line, posix=False)
    except ValueError:
        return command_line.split()


class ScanEngine:
    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.rows_parsed = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous CSV parse + rule evaluation. Returns
        summary dict: files_scanned, dirs_scanned, errors_count, findings,
        elapsed_seconds."""
        start = time.time()

        if os.path.isfile(self.target_path):
            if self.target_path.lower().endswith(".csv"):
                self._process_csv_file(self.target_path)
            else:
                self.errors_count += 1
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    self._walk(full_path, depth + 1)
                elif entry.is_file(follow_symlinks=False) and full_path.lower().endswith(".csv"):
                    self._process_csv_file(full_path)
            except OSError:
                self.errors_count += 1
                continue

    def _process_csv_file(self, csv_path):
        rows = []
        try:
            with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                colmap = _normalize_header(reader.fieldnames)
                if not REQUIRED_COLUMNS.issubset(colmap.keys()):
                    self.errors_count += 1
                    return
                for raw_row in reader:
                    try:
                        row = self._parse_row(raw_row, colmap, csv_path)
                    except Exception:
                        self.errors_count += 1
                        continue
                    if row is None:
                        continue
                    rows.append(row)
                    self.rows_parsed += 1
        except (OSError, csv.Error, UnicodeDecodeError):
            self.errors_count += 1
            return

        self.files_scanned += 1
        self._apply_rules(rows, csv_path)

    def _parse_row(self, raw_row, colmap, source_file):
        def get(canonical_key):
            raw_key = colmap.get(canonical_key)
            if raw_key is None:
                return ""
            value = raw_row.get(raw_key)
            return value.strip() if isinstance(value, str) else (value or "")

        name = get("name")
        if not name:
            return None

        command_line = get("commandline")
        row = {
            "process_id": get("processid"),
            "parent_pid": get("parentprocessid"),
            "name": name,
            "executable_path": get("executablepath"),
            "command_line": command_line,
            "tokens": _tokenize(command_line),
            "creation_date": get("creationdate"),
            "user": get("user"),
            "source_file": source_file,
        }
        return row

    def _apply_rules(self, rows, source_file):
        for row in rows:
            for rule in ROW_RULES:
                try:
                    result = rule(row)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    self._store_finding(result, row)

        try:
            cross_row_findings = rule_repeated_identical_command_line(rows, source_file)
        except Exception:
            self.errors_count += 1
            cross_row_findings = []

        for result in cross_row_findings:
            self._store_finding(result, {
                "command_line": result.get("matched_snippet", ""),
                "source_file": source_file,
            })

    def _store_finding(self, result, row):
        result["file_path"] = row.get("source_file", "")
        result["permissions_octal"] = result.get("matched_snippet", "")[:64]
        result["owner_uid"] = None
        result["owner_gid"] = None
        self.findings.append(result)

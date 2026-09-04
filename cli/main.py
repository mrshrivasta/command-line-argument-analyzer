#!/usr/bin/env python3
"""
Command-Line Argument Analyzer — Command Line Interface
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

DISCLAIMER: Parses REAL process-list export CSV files (or a directory of
them) that you provide. Only run against exports you own or are authorized
to analyze. Provided AS IS, no warranty. See README.md for the full
disclaimer.

Expected real CSV columns (subset tolerated, minimum Name + CommandLine):
    ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine,
    CreationDate, User

Usage:
    python3 cli/main.py scan processes.csv
    python3 cli/main.py scan ./exports --depth 2
    python3 cli/main.py scan processes.csv --json
    python3 cli/main.py scan processes.csv --csv findings.csv
    python3 cli/main.py rules
"""
import argparse
import csv
import io
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import ALL_RULES

BANNER = """\
==============================================================
 Command-Line Argument Analyzer (CLI)
 Developed by Karanam Shrivasta
 GitHub:   https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta
 DISCLAIMER: Authorized use only. Provided AS IS, no warranty.
==============================================================\
"""

SEVERITY_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}
RESET = "\033[0m"


def cmd_scan(args):
    print(BANNER)
    print(f"Analyzing: {args.path}  (max dir depth {args.depth}, max files {args.max_files})\n")

    engine = ScanEngine(
        args.path,
        max_depth=args.depth,
        excludes=args.exclude.split(",") if args.exclude else None,
        max_files=args.max_files,
    )
    result = engine.run()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    print(f"CSV files parsed : {result['files_scanned']}")
    print(f"Dirs walked      : {result['dirs_scanned']}")
    print(f"Errors           : {result['errors_count']}")
    print(f"Elapsed          : {result['elapsed_seconds']}s")
    print(f"Findings         : {len(result['findings'])}\n")

    for f in result["findings"]:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"{color}[{f['severity'].upper():8}]{RESET} {f['rule_id']} {f['rule_name']}")
        print(f"           source: {f['file_path']}")
        print(f"           match : {f['permissions_octal']}")
        print(f"           {f['description']}\n")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule_id", "rule_name", "severity", "source_csv", "matched_snippet", "description"])
            for f in result["findings"]:
                writer.writerow([f["rule_id"], f["rule_name"], f["severity"], f["file_path"], f["permissions_octal"], f["description"]])
        print(f"CSV report written to {args.csv}")

    if result["findings"]:
        sys.exit(1)  # non-zero exit for CI pipelines when issues are found
    sys.exit(0)


def cmd_rules(args):
    print(BANNER)
    print("Detection rules:\n")
    for rule in ALL_RULES:
        doc = (rule.__doc__ or "").strip().split("\n")[0]
        print(f" - {rule.__name__}: {doc}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="claa-cli",
        description="Command-Line Argument Analyzer — real process-list export CSV command-line scanner (by Karanam Shrivasta).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Analyze a real process-list export CSV file or a directory of them")
    scan_p.add_argument("path", help="Path to a .csv file, or a directory to walk for *.csv files")
    scan_p.add_argument("--depth", type=int, default=6, help="Max directory recursion depth when path is a directory (default 6)")
    scan_p.add_argument("--max-files", type=int, default=20000, dest="max_files", help="Safety cap on CSV files parsed")
    scan_p.add_argument("--exclude", type=str, default="", help="Comma-separated directory paths to exclude")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON")
    scan_p.add_argument("--csv", type=str, default=None, help="Write findings to a CSV report file")
    scan_p.set_defaults(func=cmd_scan)

    rules_p = sub.add_parser("rules", help="List all detection rules")
    rules_p.set_defaults(func=cmd_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

import csv
import os
import shutil
import tempfile

CSV_COLUMNS = ["ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine", "CreationDate", "User"]


def _write_findings_csv(path):
    """Write a REAL process-list export CSV that is guaranteed to trigger
    CLA-001 (evasion flag), so downstream pages have real data to render."""
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerow({
            "ProcessId": "9001", "ParentProcessId": "500", "Name": "powershell.exe",
            "ExecutablePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -nop -noni -w hidden -enc SGVsbG8gV29ybGQ=",
            "CreationDate": "2026-08-17 09:00:00", "User": "NT AUTHORITY\\SYSTEM",
        })


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "processes.csv")
        _write_findings_csv(csv_path)

        # Run a real scan against a real process-list export CSV.
        resp = registered_client.post("/scan/run", data={"target_path": csv_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert csv_path.encode() in resp.data

        # Alerts page should load with a real alert generated from the finding
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json
        data = resp.get_json()
        assert data["severity_breakdown"].get("high", 0) >= 1

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"CLA-001" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp/processes.csv",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp/processes.csv" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404


def test_scan_run_requires_target_path(registered_client):
    resp = registered_client.post("/scan/run", data={"target_path": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"provide a path" in resp.data

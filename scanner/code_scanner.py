import json
import subprocess
import sys
from pathlib import Path


def scan_python_file(file_path):
    file_path = Path(file_path).resolve()

    if not file_path.is_file() or file_path.suffix != ".py":
        raise ValueError("Please provide an existing Python file.")

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-f",
        "json",
        str(file_path),
    ]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    if not process.stdout.strip():
        raise RuntimeError(
            f"Bandit produced no JSON output. {process.stderr}"
        )

    report = json.loads(process.stdout)

    findings = []

    for result in report.get("results", []):
        findings.append({
            "rule_id": result.get("test_id"),
            "title": result.get("issue_text"),
            "severity": result.get("issue_severity"),
            "confidence": result.get("issue_confidence"),
            "file": result.get("filename"),
            "line": result.get("line_number"),
            "cwe": result.get("issue_cwe", {}).get("id"),
        })

    return findings
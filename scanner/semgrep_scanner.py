import json
import subprocess
from pathlib import Path


def scan_with_semgrep(file_path):
    file_path = Path(file_path)

    command = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--json",
        "--quiet",
        str(file_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Could not parse Semgrep output: {result.stderr}"
        ) from error

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed with exit code {result.returncode}: "
            f"{result.stderr}"
        )

    findings = []

    for item in output.get("results", []):
        extra = item.get("extra", {})
        start = item.get("start", {})
        metadata = extra.get("metadata", {})
        cwe_data = metadata.get("cwe", [])

        if isinstance(cwe_data, str):
            cwe_data = [cwe_data]

        cwe_value = ", ".join(cwe_data) if cwe_data else "Not mapped"
        findings.append({
            "scanner": "Semgrep",
            "rule_id": item.get("check_id", "UNKNOWN"),
            "title": extra.get("message", "Potential security issue"),
            "severity": {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
            }.get(extra.get("severity", "INFO").upper(), "LOW"),
            "confidence": "MEDIUM",
            "file": str(file_path),
            "line": start.get("line"),
            "cwe": cwe_value,
            "evidence": extra.get("lines", ""),
        })

    return findings
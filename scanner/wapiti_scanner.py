import json
import os
import shutil
import subprocess
import tempfile

from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# SIMHARA — WAPITI SCANNER
# ============================================================

def validate_target(target: str) -> str:
    """Validate and normalize an HTTP/HTTPS URL."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target URL cannot be empty.")

    target = target.strip()
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")

    if parsed.port and not 1 <= parsed.port <= 65535:
        raise ValueError("Target port is invalid.")

    return target.rstrip("/")


# ============================================================
# FINDING NORMALIZATION
# ============================================================

def normalize_findings(report: dict) -> list:
    """Convert Wapiti findings into SIMHARA's common format."""

    findings = []
    vulnerabilities = report.get("vulnerabilities", {})

    if not isinstance(vulnerabilities, dict):
        return findings

    for category, items in vulnerabilities.items():
        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict):
                continue

            findings.append({
                "scanner": "Wapiti",
                "category": category,
                "title": category.replace("_", " ").title(),
                "severity": item.get("level"),
                "severity_source": "Wapiti",
                "description": item.get("info", ""),
                "url": item.get("path", ""),
                "method": item.get("method", ""),
                "parameter": item.get("parameter", ""),
                "module": item.get("module", ""),
                "reference": item.get("referer", ""),
            })

    return findings


# ============================================================
# SHARED WAPITI EXECUTION
# ============================================================

def _execute_wapiti(
    target: str,
    max_scan_time: int,
    max_attack_time: int,
    openapi_spec: str = None,
    operation_name: str = "Web Application Security",
) -> dict:
    """Execute Wapiti and return normalized results."""

    try:
        target = validate_target(target)

        if (
            not isinstance(max_scan_time, int)
            or isinstance(max_scan_time, bool)
            or not 1 <= max_scan_time <= 300
        ):
            raise ValueError("Scan duration must be 1–300 seconds.")

        if (
            not isinstance(max_attack_time, int)
            or isinstance(max_attack_time, bool)
            or not 1 <= max_attack_time <= 60
        ):
            raise ValueError("Attack duration must be 1–60 seconds.")

        if openapi_spec is not None:
            openapi_spec = validate_target(openapi_spec)

    except ValueError as exc:
        return {
            "success": False,
            "scanner": "Wapiti",
            "operation": operation_name,
            "target": target,
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "error": str(exc),
        }

    executable = shutil.which("wapiti")

    if not executable:
        return {
            "success": False,
            "scanner": "Wapiti",
            "operation": operation_name,
            "target": target,
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "error": "Wapiti was not found in the active environment.",
        }

    try:
        with tempfile.TemporaryDirectory(
            prefix="simhara_wapiti_"
        ) as temp_dir:

            report_path = Path(temp_dir) / "report.json"

            command = [
                executable,
                "-u", target,
                "--scope", "folder",
                "--max-scan-time", str(max_scan_time),
                "--max-attack-time", str(max_attack_time),
                "-f", "json",
                "-o", str(report_path),
            ]

            if openapi_spec:
                command.extend(["--swagger", openapi_spec])

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=max_scan_time + 90,
                check=False,
            )

            if not report_path.exists():
                return {
                    "success": False,
                    "scanner": "Wapiti",
                    "operation": operation_name,
                    "target": target,
                    "status": "error",
                    "findings": [],
                    "finding_count": 0,
                    "error": (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or "Wapiti did not generate a JSON report."
                    ),
                }

            with report_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            findings = normalize_findings(report)

            success = result.returncode == 0

            return {
                "success": success,
                "scanner": "Wapiti",
                "operation": operation_name,
                "target": target,
                "status": (
                    "completed" if success
                    else "completed_with_warnings"
                ),
                "finding_count": len(findings),
                "findings": findings,
                "pages": report.get("infos", {}).get("nb_urls"),
                "report_version": report.get("version", ""),
                "error": (
                    result.stderr.strip() if not success else None
                ),
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "scanner": "Wapiti",
            "operation": operation_name,
            "target": target,
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "error": "Wapiti exceeded its execution timeout.",
        }

    except (OSError, json.JSONDecodeError) as exc:
        return {
            "success": False,
            "scanner": "Wapiti",
            "operation": operation_name,
            "target": target,
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "error": str(exc),
        }


# ============================================================
# STANDARD WEB APPLICATION ASSESSMENT
# ============================================================

def run_wapiti_scan(
    target: str,
    max_scan_time: int = 60,
    max_attack_time: int = 10,
) -> dict:
    """Run the standard web application security assessment."""

    return _execute_wapiti(
        target=target,
        max_scan_time=max_scan_time,
        max_attack_time=max_attack_time,
        operation_name="Web Application Security",
    )


# ============================================================
# API SECURITY ASSESSMENT
# ============================================================

def run_wapiti_api_scan(
    target: str,
    openapi_spec: str,
    max_scan_time: int = 60,
    max_attack_time: int = 10,
) -> dict:
    """
    Run a Wapiti assessment using an OpenAPI/Swagger specification.

    target:
        Base URL of the API being assessed.

    openapi_spec:
        URL to a compatible OpenAPI/Swagger specification.

    Both URLs must refer to systems the user is authorized to test.
    """

    if not isinstance(openapi_spec, str) or not openapi_spec.strip():
        return {
            "success": False,
            "scanner": "Wapiti",
            "operation": "API Security Assessment",
            "target": target,
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "error": "An OpenAPI/Swagger specification URL is required.",
        }

    return _execute_wapiti(
        target=target,
        max_scan_time=max_scan_time,
        max_attack_time=max_attack_time,
        openapi_spec=openapi_spec.strip(),
        operation_name="API Security Assessment",
    )
import json
import shutil
import subprocess
from pathlib import Path


def _find_trivy():
    """Locate the Trivy executable."""

    trivy_path = shutil.which("trivy")

    if trivy_path:
        return trivy_path

    candidate = (
        Path.home()
        / "AppData"
        / "Local"
        / "Microsoft"
        / "WinGet"
        / "Packages"
        / "AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe"
        / "trivy.exe"
    )

    if candidate.is_file():
        return str(candidate)

    return None


def _error(message):
    return {
        "success": False,
        "error": message,
        "findings": [],
    }


def _normalize_findings(report, scan_type):
    """Convert Trivy JSON results into SIMHARA findings."""

    findings = []

    for item in report.get("Results", []):
        target = item.get("Target", "")

        if scan_type == "secret":
            for secret in item.get("Secrets", []) or []:
                findings.append({
                    "scanner": "Trivy",
                    "scan_type": "secret",
                    "rule_id": secret.get("RuleID", "UNKNOWN"),
                    "title": secret.get(
                        "Title", "Potential secret detected"
                    ),
                    "severity": secret.get("Severity", "UNKNOWN"),
                    "file": target,
                    "line": secret.get("StartLine"),
                    "evidence": secret.get("Match", ""),
                })

        elif scan_type == "vuln":
            for vulnerability in item.get("Vulnerabilities", []) or []:
                findings.append({
                    "scanner": "Trivy",
                    "scan_type": "vuln",
                    "rule_id": vulnerability.get(
                        "VulnerabilityID", "UNKNOWN"
                    ),
                    "title": vulnerability.get(
                        "Title",
                        vulnerability.get(
                            "PkgName", "Vulnerable package"
                        ),
                    ),
                    "severity": vulnerability.get("Severity", "UNKNOWN"),
                    "file": target,
                    "line": None,
                    "evidence": (
                        f"Package: {vulnerability.get('PkgName', 'Unknown')}; "
                        f"Installed: {vulnerability.get('InstalledVersion', 'Unknown')}; "
                        f"Fixed: {vulnerability.get('FixedVersion', 'Not specified')}"
                    ),
                })

        elif scan_type == "misconfig":
            for misconfiguration in (
                item.get("Misconfigurations", []) or []
            ):
                findings.append({
                    "scanner": "Trivy",
                    "scan_type": "misconfig",
                    "rule_id": misconfiguration.get("ID", "UNKNOWN"),
                    "title": misconfiguration.get(
                        "Title", "Configuration issue"
                    ),
                    "severity": misconfiguration.get(
                        "Severity", "UNKNOWN"
                    ),
                    "file": target,
                    "line": misconfiguration.get(
                        "CauseMetadata", {}
                    ).get("StartLine"),
                    "evidence": (
                        misconfiguration.get("Message", "")
                        or misconfiguration.get("Description", "")
                    ),
                    "resolution": misconfiguration.get(
                        "Resolution", ""
                    ),
                })

    return findings


def _run_trivy(command, scan_type, timeout=300):
    """Execute Trivy and normalize its JSON output."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            return _error(
                result.stderr.strip()
                or f"Trivy exited with code {result.returncode}."
            )

        report = json.loads(result.stdout or "{}")
        findings = _normalize_findings(report, scan_type)

        return {
            "success": True,
            "error": None,
            "scanner": "Trivy",
            "scan_type": scan_type,
            "findings": findings,
            "finding_count": len(findings),
        }

    except subprocess.TimeoutExpired:
        return _error(
            f"Trivy scan timed out after {timeout} seconds."
        )

    except json.JSONDecodeError:
        return _error("Trivy returned invalid JSON.")

    except OSError as exc:
        return _error(str(exc))


def run_trivy_scan(target_path, scan_type="secret"):
    """
    Scan a local file or directory.

    Supported scan types:
        secret    - Potential exposed secrets.
        vuln      - Dependency vulnerabilities.
        misconfig - Supported configuration misconfigurations.
    """

    supported_types = {"secret", "vuln", "misconfig"}

    if scan_type not in supported_types:
        return _error(
            "Unsupported filesystem scan type. "
            "Use 'secret', 'vuln', or 'misconfig'."
        )

    trivy_path = _find_trivy()

    if not trivy_path:
        return _error("Trivy executable was not found.")

    try:
        target = Path(target_path).resolve()

        if not target.exists():
            return _error(f"Target does not exist: {target}")

        if not target.is_file() and not target.is_dir():
            return _error("Target must be a regular file or directory.")

    except (OSError, ValueError) as exc:
        return _error(f"Invalid local target: {exc}")

    command = [
        trivy_path,
        "fs",
        "--scanners",
        scan_type,
        "--format",
        "json",
        "--quiet",
    ]

    if target.is_dir():
        command.extend([
            "--skip-dirs", ".venv",
            "--skip-dirs", ".git",
            "--skip-dirs", "__pycache__",
        ])

    command.append(str(target))

    return _run_trivy(command, scan_type)


def run_trivy_container_scan(image):
    """
    Scan a container image for OS and library vulnerabilities.

    Example image reference: alpine:3.20
    """

    if not isinstance(image, str) or not image.strip():
        return _error("A container image reference is required.")

    image = image.strip()

    if any(character.isspace() for character in image):
        return _error("Container image reference cannot contain whitespace.")

    trivy_path = _find_trivy()

    if not trivy_path:
        return _error("Trivy executable was not found.")

    command = [
        trivy_path,
        "image",
        "--scanners", "vuln",
        "--format", "json",
        "--quiet",
        image,
    ]

    return _run_trivy(
        command,
        scan_type="vuln",
        timeout=600,
    )
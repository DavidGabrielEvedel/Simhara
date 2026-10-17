import json
import shutil
import subprocess
from pathlib import Path


def run_trivy_scan(target_path, scan_type="secret"):
    """
    Run Trivy against a local file or directory.

    Supported scan types:
        secret - Detect potential secrets.
        vuln   - Detect dependency vulnerabilities.
    """

    trivy_path = shutil.which("trivy")

    # Fall back to the known WinGet installation location.
    if not trivy_path:
        local_appdata = Path.home() / "AppData" / "Local"
        candidate = (
            local_appdata
            / "Microsoft"
            / "WinGet"
            / "Packages"
            / "AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe"
            / "trivy.exe"
        )

        if candidate.is_file():
            trivy_path = str(candidate)
        else:
            return {
                "success": False,
                "error": "Trivy executable was not found.",
                "findings": [],
            }

    target = Path(target_path).resolve()

    if not target.exists():
        return {
            "success": False,
            "error": f"Target does not exist: {target}",
            "findings": [],
        }

    if scan_type not in {"secret", "vuln"}:
        return {
            "success": False,
            "error": "Unsupported scan type. Use 'secret' or 'vuln'.",
            "findings": [],
        }

    command = [
        trivy_path,
        "fs",
        "--scanners",
        scan_type,
        "--format",
        "json",
        "--quiet",
        "--skip-dirs",
        ".venv",
        "--skip-dirs",
        ".git",
        "--skip-dirs",
        "__pycache__",
        str(target),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "error": result.stderr.strip()
                or f"Trivy exited with code {result.returncode}.",
                "findings": [],
            }

        report = json.loads(result.stdout or "{}")
        findings = []

        for item in report.get("Results", []):
            if scan_type == "secret":
                for secret in item.get("Secrets", []):
                    findings.append({
                        "scanner": "Trivy",
                        "scan_type": "secret",
                        "rule_id": secret.get("RuleID", "UNKNOWN"),
                        "title": secret.get(
                            "Title", "Potential secret detected"
                        ),
                        "severity": secret.get("Severity", "UNKNOWN"),
                        "file": item.get("Target", ""),
                        "line": secret.get("StartLine"),
                        "evidence": secret.get("Match", ""),
                    })

            elif scan_type == "vuln":
                for vulnerability in item.get("Vulnerabilities", []):
                    findings.append({
                        "scanner": "Trivy",
                        "scan_type": "vuln",
                        "rule_id": vulnerability.get("VulnerabilityID", "UNKNOWN"),
                        "title": vulnerability.get(
                            "Title",
                            vulnerability.get("PkgName", "Vulnerable package"),
                        ),
                        "severity": vulnerability.get("Severity", "UNKNOWN"),
                        "file": item.get("Target", ""),
                        "line": None,
                        "evidence": (
                            f"Package: {vulnerability.get('PkgName', 'Unknown')}; "
                            f"Installed: {vulnerability.get('InstalledVersion', 'Unknown')}; "
                            f"Fixed: {vulnerability.get('FixedVersion', 'Not specified')}"
                        ),
                    })

        return {
            "success": True,
            "error": None,
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Trivy scan timed out after 300 seconds.",
            "findings": [],
        }

    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Trivy returned invalid JSON.",
            "findings": [],
        }

    except OSError as exc:
        return {
            "success": False,
            "error": str(exc),
            "findings": [],
        }
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

from pathlib import Path


SCAN_PROFILES = {
    "Network & Service Discovery": {
        "description": (
            "Discover common TCP ports, identify services "
            "and versions, and attempt OS detection."
        ),
        "arguments": [
            "-sT",
            "-sV",
            "-O",
            "--top-ports",
            "100",
        ],
    },

    "Comprehensive Port Scan": {
        "description": (
            "Scan all TCP ports, identify services, "
            "and execute Nmap's default scripts."
        ),
        "arguments": [
            "-sT",
            "-sV",
            "-sC",
            "-p-",
        ],
    },

    "Firewall & Filtering Analysis": {
        "description": (
            "Examine common TCP port states and identify "
            "possible network filtering."
        ),
        "arguments": [
            "-sT",
            "--top-ports",
            "100",
            "--reason",
        ],
    },

    "Security & Vulnerability Assessment": {
        "description": (
            "Run service detection and selected NSE scripts "
            "for supported security checks."
        ),
        "arguments": [
            "-sT",
            "-sV",
            "--script",
            "safe",
            "--top-ports",
            "100",
        ],
    },
}


def find_nmap():
    """Locate the Nmap executable."""

    executable = shutil.which("nmap")

    if executable:
        return executable

    # Standard Windows installation location.
    candidate = Path(
        r"C:\Program Files (x86)\Nmap\nmap.exe"
    )

    if candidate.is_file():
        return str(candidate)

    candidate = Path(
        r"C:\Program Files\Nmap\nmap.exe"
    )

    if candidate.is_file():
        return str(candidate)

    return None

def validate_target(target):
    """
    Validate a single IP address or ordinary hostname.

    This does not establish authorisation to scan a target.
    """

    target = target.strip()

    if not target:
        raise ValueError("A target IP address or hostname is required.")

    if target.startswith("-"):
        raise ValueError("Invalid target.")

    try:
        ipaddress.ip_address(target)
        return target

    except ValueError:
        pass

    hostname = target.rstrip(".")

    if len(hostname) > 253:
        raise ValueError("Hostname is too long.")

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                character.isalnum() or character == "-"
                for character in label
            )
        ):
            raise ValueError("Enter a valid IP address or hostname.")

    return target

def parse_nmap_xml(xml_output, profile, target):
    """Convert Nmap XML output into structured findings."""

    root = ET.fromstring(xml_output)

    findings = []
    hosts = []

    for host_element in root.findall("host"):

        status_element = host_element.find("status")

        host_status = (
            status_element.get("state", "unknown")
            if status_element is not None
            else "unknown"
        )

        address_element = host_element.find("address")

        host_address = (
            address_element.get("addr", target)
            if address_element is not None
            else target
        )

        hostname_element = host_element.find(
            "./hostnames/hostname"
        )

        hostname = (
            hostname_element.get("name", "")
            if hostname_element is not None
            else ""
        )

        host_record = {
            "address": host_address,
            "hostname": hostname,
            "status": host_status,
            "open_ports": 0,
            "os_guess": None,
        }

        os_match = host_element.find("./os/osmatch")

        if os_match is not None:
            host_record["os_guess"] = os_match.get("name")

        hosts.append(host_record)

        for port_element in host_element.findall(".//port"):

            state_element = port_element.find("state")

            if state_element is None:
                continue

            state = state_element.get("state", "unknown")

            service_element = port_element.find("service")

            service_name = (
                service_element.get("name", "unknown")
                if service_element is not None
                else "unknown"
            )

            product = (
                service_element.get("product", "")
                if service_element is not None
                else ""
            )

            version = (
                service_element.get("version", "")
                if service_element is not None
                else ""
            )

            extra_info = (
                service_element.get("extrainfo", "")
                if service_element is not None
                else ""
            )

            version_details = " ".join(
                part
                for part in [product, version, extra_info]
                if part
            )

            reason = (
                state_element.get("reason", "Not provided")
            )

            protocol = port_element.get("protocol", "unknown")
            port_number = int(port_element.get("portid", "0"))

            if state == "open":
                host_record["open_ports"] += 1

            include_port = (
                state == "open"
                or profile == "Firewall & Filtering Analysis"
            )

            if not include_port:
                continue

            findings.append({
                "scanner": "Nmap",
                "profile": profile,
                "host": host_address,
                "hostname": hostname,
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": version_details or "Not identified",
                "reason": reason,
                "severity": "INFO",
                "rule_id": f"NMAP-{state.upper()}",
                "title": (
                    f"{state.title()} {protocol.upper()} port "
                    f"{port_number}: {service_name}"
                ),
                "evidence": (
                    f"Observed state: {state}; "
                    f"reason: {reason}; "
                    f"service: {service_name}; "
                    f"version: {version_details or 'Not identified'}"
                ),
            })

        for script_element in host_element.findall(".//hostscript/script"):

            findings.append({
                "scanner": "Nmap",
                "profile": profile,
                "host": host_address,
                "hostname": hostname,
                "port": None,
                "protocol": None,
                "state": "script-result",
                "service": "Host script",
                "version": "Not applicable",
                "reason": "NSE script output",
                "severity": "INFO",
                "rule_id": script_element.get("id", "NMAP-SCRIPT"),
                "title": script_element.get("id", "Nmap script result"),
                "evidence": script_element.get("output", ""),
            })

        for port_element in host_element.findall(".//port"):

            port_number = int(port_element.get("portid", "0"))
            protocol = port_element.get("protocol", "unknown")

            for script_element in port_element.findall("./script"):

                findings.append({
                    "scanner": "Nmap",
                    "profile": profile,
                    "host": host_address,
                    "hostname": hostname,
                    "port": port_number,
                    "protocol": protocol,
                    "state": "script-result",
                    "service": "NSE script",
                    "version": "Not applicable",
                    "reason": "NSE script output",
                    "severity": "INFO",
                    "rule_id": script_element.get("id", "NMAP-SCRIPT"),
                    "title": script_element.get("id", "Nmap script result"),
                    "evidence": script_element.get("output", ""),
                })

    return hosts, findings

def run_nmap_scan(target, profile="Network & Service Discovery"):
    """
    Run an Nmap scan and return structured results.

    Only scan systems you own or are explicitly authorised
    to assess.
    """

    if profile not in SCAN_PROFILES:
        return {
            "success": False,
            "error": "Unknown scan profile.",
            "profile": profile,
            "hosts": [],
            "findings": [],
        }

    try:
        target = validate_target(target)

    except ValueError as error:
        return {
            "success": False,
            "error": str(error),
            "profile": profile,
            "hosts": [],
            "findings": [],
        }

    nmap_path = find_nmap()

    if not nmap_path:
        return {
            "success": False,
            "error": "Nmap executable was not found.",
            "profile": profile,
            "hosts": [],
            "findings": [],
        }

    command = [
        nmap_path,
        *SCAN_PROFILES[profile]["arguments"],
        "-oX",
        "-",
        target,
    ]

    timeout_seconds = (
        600
        if profile == "Comprehensive Port Scan"
        else 240
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "error": (
                    result.stderr.strip()
                    or f"Nmap exited with code {result.returncode}."
                ),
                "profile": profile,
                "hosts": [],
                "findings": [],
            }

        hosts, findings = parse_nmap_xml(
            result.stdout,
            profile,
            target,
        )

        return {
            "success": True,
            "error": None,
            "profile": profile,
            "target": target,
            "description": SCAN_PROFILES[profile]["description"],
            "hosts": hosts,
            "findings": findings,
            "summary": {
                "hosts_found": len(hosts),
                "open_ports": sum(
                    host["open_ports"] for host in hosts
                ),
                "findings": len(findings),
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": (
                f"Nmap scan timed out after {timeout_seconds} seconds."
            ),
            "profile": profile,
            "hosts": [],
            "findings": [],
        }

    except ET.ParseError:
        return {
            "success": False,
            "error": "Nmap returned invalid XML output.",
            "profile": profile,
            "hosts": [],
            "findings": [],
        }

    except OSError as error:
        return {
            "success": False,
            "error": str(error),
            "profile": profile,
            "hosts": [],
            "findings": [],
        }
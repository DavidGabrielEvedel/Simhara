import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

#Create a standard finding dictionary.
def make_finding(operation, title, severity, evidence):
    return {
        "scanner": "SIMHARA Native Checks",
        "operation": operation,
        "title": title,
        "severity": severity,
        "evidence": evidence,
    }


def validate_url(url):
    url = url.strip()
    if not url:
        raise ValueError("A target URL is required.")
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported.")
    if any(c in url for c in "\r\n"):
        raise ValueError("Invalid characters in URL.")
    return parsed


# TLS certificate and connection check
def check_tls(url):
    findings = []
    operation = "TLS / HTTPS Assessment"

    try:
        parsed = validate_url(url)
        if parsed.scheme != "https":
            raise ValueError("TLS assessment requires an HTTPS URL.")

        hostname, port = parsed.hostname, parsed.port or 443
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=8) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls:
                certificate = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()

        expiry_text = certificate.get("notAfter")
        if expiry_text:
            expiry = datetime.strptime(
                expiry_text, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days

            if days < 0:
                findings.append(make_finding(
                    operation, "TLS certificate expired", "HIGH",
                    f"Certificate expired on {expiry.isoformat()}."
                ))
            elif days <= 30:
                findings.append(make_finding(
                    operation, "TLS certificate expires soon", "MEDIUM",
                    f"Certificate expires in approximately {days} days."
                ))

        findings.append(make_finding(
            operation, "TLS connection established", "INFO",
            f"Host: {hostname}; Port: {port}; TLS: {version}; "
            f"Cipher: {cipher[0] if cipher else 'Unknown'}."
        ))
        return {"success": True, "error": None, "findings": findings}

    except (ValueError, OSError, ssl.SSLError, socket.timeout) as error:
        return {"success": False, "error": str(error), "findings": findings}


# Check common HTTP security headers
def check_headers(url):
    findings = []
    operation = "HTTP Security Headers"

    try:
        parsed = validate_url(url)
        response = requests.get(
            parsed.geturl(), timeout=10, allow_redirects=True, stream=True,
            headers={"User-Agent": "SIMHARA-Security-Assessment/1.0"}
        )

        try:
            headers = response.headers
            required = {
                "Strict-Transport-Security": "MEDIUM",
                "Content-Security-Policy": "LOW",
                "X-Content-Type-Options": "LOW",
                "X-Frame-Options": "LOW",
            }

            for header, severity in required.items():
                if header not in headers:
                    findings.append(make_finding(
                        operation, f"Missing {header}", severity,
                        f"The response from {response.url} did not include {header}."
                    ))

            findings.append(make_finding(
                operation, "HTTP response received", "INFO",
                f"URL: {response.url}; Status: {response.status_code}; "
                f"HTTPS: {response.url.startswith('https://')}."
            ))
            return {"success": True, "error": None, "findings": findings}

        finally:
            response.close()

    except (ValueError, requests.RequestException) as error:
        return {"success": False, "error": str(error), "findings": findings}


# Resolve hostnames and attempt reverse DNS lookups
def check_dns(target):
    findings = []
    operation = "DNS Security Checks"

    try:
        hostname = validate_url(target).hostname if "://" in target else target.strip()
        if not hostname:
            raise ValueError("A hostname is required.")

        try:
            ipaddress.ip_address(hostname)
            return {
                "success": True, "error": None,
                "findings": [make_finding(
                    operation, "Target is an IP address", "INFO",
                    f"{hostname} is an IP address; forward DNS lookup was skipped."
                )]
            }
        except ValueError:
            pass

        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = sorted({result[4][0] for result in results})

        findings.append(make_finding(
            operation, "DNS resolution succeeded", "INFO",
            f"Hostname: {hostname}; Addresses: {', '.join(addresses)}."
        ))

        for address in addresses:
            try:
                reverse = socket.gethostbyaddr(address)[0]
                findings.append(make_finding(
                    operation, "Reverse DNS result", "INFO",
                    f"IP: {address}; Hostname: {reverse}."
                ))
            except (socket.herror, socket.gaierror, OSError):
                pass

        return {"success": True, "error": None, "findings": findings}

    except (ValueError, socket.gaierror, socket.herror, OSError) as error:
        return {"success": False, "error": str(error), "findings": findings}
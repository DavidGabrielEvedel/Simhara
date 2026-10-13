import ipaddress
import re


SECRET_PATTERNS = [
    # Passwords, API keys, access tokens and secret keys.
    re.compile(
        r"""(?ix)
        \b(
            api[_-]?key |
            access[_-]?token |
            auth[_-]?token |
            secret[_-]?key |
            password |
            passwd |
            client[_-]?secret
        )\b
        (\s*[:=]\s*)
        (["']?)
        ([^\s"'`,;]+)
        """
    ),

    # Common AWS access key identifiers.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),

    # Common GitHub personal access token formats.
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
]


def redact_secrets(text):
    """Redact common secret patterns from a string."""

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    sanitized = text

    # Redact credentials while preserving their variable names.
    assignment_pattern = SECRET_PATTERNS[0]

    sanitized = assignment_pattern.sub(
        lambda match: (
            f"{match.group(1)}"
            f"{match.group(2)}"
            f"{match.group(3)}[REDACTED_SECRET]"
        ),
        sanitized,
    )

    # Redact recognizable standalone token formats.
    sanitized = SECRET_PATTERNS[1].sub(
        "[REDACTED_AWS_KEY]",
        sanitized,
    )

    sanitized = SECRET_PATTERNS[2].sub(
        "[REDACTED_GITHUB_TOKEN]",
        sanitized,
    )

    sanitized = SECRET_PATTERNS[3].sub(
        "[REDACTED_GITHUB_TOKEN]",
        sanitized,
    )

    return sanitized


def redact_private_ips(text):
    """Replace private IPv4 addresses with a redaction marker."""

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    ipv4_pattern = re.compile(
        r"(?<![\d.])"
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"(?![\d.])"
    )

    def replace_ip(match):
        address = match.group(0)

        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return address

        if isinstance(ip, ipaddress.IPv4Address) and ip.is_private:
            return "[REDACTED_PRIVATE_IP]"

        return address

    return ipv4_pattern.sub(replace_ip, text)


def sanitize_text(text, redact_ips=False):
    """Apply the configured sanitization steps."""

    sanitized = redact_secrets(text)

    if redact_ips:
        sanitized = redact_private_ips(sanitized)

    return sanitized
def validate_remediation(finding: dict, analysis: dict) -> dict:
    """
    Perform preliminary checks on an AI-generated remediation.

    This function identifies known warning signs.
    It does not prove that a remediation is secure.
    """

    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary")

    if not isinstance(analysis, dict):
        raise TypeError("analysis must be a dictionary")

    required_finding_fields = {
        "rule_id",
        "title",
        "severity",
    }

    missing_fields = required_finding_fields - finding.keys()

    if missing_fields:
        raise ValueError(
            f"Finding is missing fields: {sorted(missing_fields)}"
        )

    required_analysis_fields = {
        "vulnerability",
        "evidence",
        "impact",
        "remediation",
        "validation_steps",
        "limitations",
    }

    missing_fields = required_analysis_fields - analysis.keys()

    if missing_fields:
        raise ValueError(
            f"Analysis is missing fields: {sorted(missing_fields)}"
        )

    warnings = []

    rule_id = finding["rule_id"]
    remediation = analysis["remediation"]

    if not isinstance(remediation, str):
        raise TypeError("remediation must be a string")

    # Check 1: Flag a known weakness in the proposed
    # command-injection remediation.

    if rule_id == "B602":
        remediation_lower = remediation.lower()

        recommends_shell_false = "shell=false" in remediation_lower

        recommends_shlex = "shlex.split" in remediation_lower

        mentions_command_restrictions = any(
            phrase in remediation_lower
            for phrase in (
                "allowlist",
                "allow-list",
                "fixed executable",
                "permitted commands",
                "allowed commands",
                "restrict commands",
                "validated arguments",
            )
        )

        if (
            (recommends_shell_false or recommends_shlex)
            and not mentions_command_restrictions
        ):
            warnings.append({
                "code": "COMMAND_EXECUTION_REVIEW",
                "message": (
                    "The remediation mentions shell=False or "
                    "shlex.split() without clearly explaining how "
                    "executable selection and arguments are controlled."
                ),
            })

    # Check 2: Flag specific recommendations when the
    # scanner finding lacks the context needed to support them.

    if rule_id == "CUSTOM-001":
        limitations = analysis["limitations"]

        if not isinstance(limitations, str):
            raise TypeError("limitations must be a string")

        limitations_lower = limitations.lower()

        acknowledges_missing_context = any(
            phrase in limitations_lower
            for phrase in (
                "insufficient context",
                "insufficient evidence",
                "not provided",
                "not supplied",
                "cannot determine",
            )
        )

        remediation_lower = remediation.lower()

        makes_specific_file_security_claim = any(
            phrase in remediation_lower
            for phrase in (
                "directory traversal",
                "path traversal",
                "os.path.abspath",
                "os.path.expanduser",
            )
        )

        if (
            acknowledges_missing_context
            and makes_specific_file_security_claim
        ):
            warnings.append({
                "code": "INSUFFICIENT_EVIDENCE",
                "message": (
                    "The analysis acknowledges missing context but "
                    "recommends a specific file-security change "
                    "without enough evidence to establish that it "
                    "addresses the reported finding."
                ),
            })

    return {
        "status": (
            "REVIEW_REQUIRED"
            if warnings
            else "NO_KNOWN_WARNING"
        ),
        "warnings": warnings,
        "automatically_verified": False,
    }
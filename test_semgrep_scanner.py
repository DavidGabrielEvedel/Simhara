from scanner.semgrep_scanner import scan_with_semgrep


findings = scan_with_semgrep("vulnerable_demo_3.py")

print(f"Total Semgrep findings: {len(findings)}")

for finding in findings:
    print(
        finding["rule_id"],
        finding["severity"],
        finding["line"],
        finding["title"],
    )
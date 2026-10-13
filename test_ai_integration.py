from pprint import pprint

from scanner.ai_analyzer import analyse_finding
from scanner.code_scanner import scan_python_file


def main():
    print("Scanning vulnerable_demo.py...")

    findings = scan_python_file("vulnerable_demo.py")

    if not findings:
        print("No findings returned by Bandit.")
        return

    print(f"\nFound {len(findings)} security findings.")

    # Prefer the command-injection finding for this test.
    finding = next(
        (
            item for item in findings
            if item.get("rule_id") == "B602"
        ),
        findings[0],
    )

    print("\nSelected finding:")
    pprint(finding)

    print("\nSending finding to the local AI model...")
    print("This may take a little while.\n")

    analysis = analyse_finding(finding)

    print("=" * 60)
    print("SIMHARA AI SECURITY ANALYSIS")
    print("=" * 60)

    for key, value in analysis.items():
        print(f"\n{key.replace('_', ' ').title()}:")

        if isinstance(value, list):
            for step_number, step in enumerate(value, start=1):
                print(f"  {step_number}. {step}")
        else:
            print(f"  {value}")


if __name__ == "__main__":
    main()
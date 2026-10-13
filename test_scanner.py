from pprint import pprint

from scanner.code_scanner import scan_python_file

findings = scan_python_file("vulnerable_demo.py")

print(f"Total findings: {len(findings)}")
print()

pprint(findings)
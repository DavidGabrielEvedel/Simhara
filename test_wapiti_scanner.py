from scanner.wapiti_scanner import run_wapiti_scan


result = run_wapiti_scan(
    target="http://127.0.0.1:8501/",
    max_scan_time=60,
    max_attack_time=10,
)

print("\n========== SIMHARA WAPITI TEST ==========")
print("Status:", result["status"])
print("Target:", result["target"])
print("Findings:", result["finding_count"])

if result.get("pages") is not None:
    print("Pages crawled:", result["pages"])

if result.get("error"):
    print("Error:", result["error"])

for finding in result["findings"]:
    print("\n-----------------------------------------")
    print("Title:", finding["title"])
    print("Category:", finding["category"])
    print("Severity level:", finding["severity"])
    print("URL:", finding["url"])
    print("Description:", finding["description"])
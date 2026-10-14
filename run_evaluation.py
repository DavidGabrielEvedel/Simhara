import json
import time
from datetime import datetime, timezone
from pathlib import Path

from scanner.ai_analyzer import analyse_finding
from evaluation_cases import EVALUATION_CASES


RESULTS_DIR = Path("evaluation_results")
RESULTS_DIR.mkdir(exist_ok=True)


def run_evaluation():
    results = []

    print("=" * 65)
    print("SIMHARA SECURITY ANALYSIS EVALUATION")
    print("=" * 65)

    for index, case in enumerate(EVALUATION_CASES, start=1):
        case_id = case["id"]

        print(f"\n[{index}/{len(EVALUATION_CASES)}] {case_id}")
        print(f"Case: {case['name']}")

        try:
            start_time = time.perf_counter()

            analysis = analyse_finding(
                case["finding"],
                source_context=case["source_context"],
            )

            elapsed = round(time.perf_counter() - start_time, 2)

            result = {
                "case_id": case_id,
                "name": case["name"],
                "status": "SUCCESS",
                "elapsed_seconds": elapsed,
                "analysis": analysis,
                "expected_properties": case["expected_properties"],
                "review": {
                    "passed_properties": [],
                    "failed_properties": [],
                    "review_status": "NOT_REVIEWED",
                },
            }

            print(f"Status: SUCCESS")
            print(f"Time: {elapsed} seconds")
            print("\nAnalysis:")
            print(json.dumps(analysis, indent=2, ensure_ascii=False))

        except Exception as exc:
            result = {
                "case_id": case_id,
                "name": case["name"],
                "status": "ERROR",
                "error": f"{type(exc).__name__}: {exc}",
                "expected_properties": case["expected_properties"],
                "review": {
                    "passed_properties": [],
                    "failed_properties": [],
                    "review_status": "NOT_REVIEWED",
                },
            }

            print(f"Status: ERROR")
            print(f"Error: {type(exc).__name__}: {exc}")

        results.append(result)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_file = RESULTS_DIR / f"evaluation_{timestamp}.json"

    output_file.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    successful = sum(
        result["status"] == "SUCCESS"
        for result in results
    )

    print("\n" + "=" * 65)
    print("EVALUATION SUMMARY")
    print("=" * 65)
    print(f"Total cases: {len(results)}")
    print(f"Successful model responses: {successful}")
    print(f"Failed model responses: {len(results) - successful}")
    print(f"Results saved to: {output_file}")

    print(
        "\nIMPORTANT: A successful response means the model returned "
        "an accepted response. It does not mean the security analysis "
        "was correct."
    )


if __name__ == "__main__":
    run_evaluation()
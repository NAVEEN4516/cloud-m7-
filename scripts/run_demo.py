"""Terminal fallback for the same controlled Review 2 service used by the dashboard."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloud_m7.bridge_api import analyze_dataset, execute_sql

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CLOUD-M7 Review 2 controlled demonstration")
    parser.add_argument("--dataset", default="repeated", help="normal, attack, repeated, or a native JSON/CSV path")
    args = parser.parse_args()
    result = analyze_dataset(args.dataset)
    print("CLOUD-M7 REVIEW 2 - CONTROLLED LAPTOP DEMONSTRATION")
    for key in ("dataset_id", "dataset_provenance", "summary", "reduction", "placement"):
        print(f"\n{key}:\n{json.dumps(result[key], indent=2)}")
    print("\nOriginating edge sources:", result["novelty2_chokepoints"]["originating_sensors"])
    for step in result["reconstructed_timeline"]:
        print(f"{step['order']:02d} [{step['tier']}] {step['host_id']}: {step['action']} {step['entity']}")
    print("\nSQL count:", execute_sql("SELECT COUNT(*) AS event_count FROM provenance", result["dataset_id"]))

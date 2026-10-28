"""Record reproducible structural results and local measured timings, separate from the model."""
import argparse
import csv
from importlib.metadata import version
import json
import platform
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cloud_m7.bridge_api import analyze_dataset


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be positive")
    rows = []
    for name in ("normal", "attack", "repeated"):
        samples = [analyze_dataset(name) for _ in range(args.runs)]
        result = samples[-1]
        rows.append({"dataset": name, "dataset_id": result["dataset_id"],
            "events": result["summary"]["total_events"], "attack_labels": result["summary"]["attack_events_count"],
            "sources": len(result["novelty2_chokepoints"]["originating_sensors"]),
            "primary_path_events": result["summary"]["path_length"],
            "original_nodes": result["reduction"]["original_nodes"], "reduced_nodes": result["reduction"]["reduced_nodes"],
            "graph_reduction_pct": result["reduction"]["node_reduction_pct"],
            "reachability_preserved": result["reduction"]["source_target_reachability_preserved"],
            "json_bytes": result["parquet_storage"]["raw_json_bytes"], "parquet_bytes": result["parquet_storage"]["parquet_bytes"],
            "analysis_median_ms": round(statistics.median(s["processing_time_ms"] for s in samples), 3),
            "analysis_min_ms": min(s["processing_time_ms"] for s in samples),
            "analysis_max_ms": max(s["processing_time_ms"] for s in samples),
            "reduction_median_ms": round(statistics.median(s["reduction"]["execution_time_ms"] for s in samples), 3)})
    record = {"method": "Sequential local runs; no warmup excluded; Python analysis only, excludes process launch and HTTP/browser overhead",
        "runs_per_dataset": args.runs, "platform": platform.system(), "python": platform.python_version(),
        "libraries": {name: version(name) for name in ("networkx", "pandas", "pyarrow", "duckdb")},
        "datasets": rows, "placement_estimates": samples[-1]["placement"]}
    report = ROOT / "reports" / "review2_results.json"
    report.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    with report.with_suffix(".csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()

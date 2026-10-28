"""Fast prerequisite check used by the launcher; does not regenerate demo data."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    try:
        import duckdb
        import pandas
        import pyarrow
        import networkx
        from cloud_m7.adapters.factory import DatasetNormalizerFactory
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "data/demo/manifest.json").read_text())
        for name, expected in manifest["datasets"].items():
            for suffix in ("json", "csv"):
                events, _ = DatasetNormalizerFactory().normalize(str(root / f"data/demo/{name}.{suffix}"))
                if len(events) != expected["events"]:
                    raise ValueError(f"Fixture count mismatch: {name}.{suffix}")
        print("Demo prerequisites OK: native JSON/CSV fixtures and Python dependencies available.")
        return 0
    except (ImportError, ValueError, OSError) as exc:
        print(f"Demo prerequisite failed: {exc}. Run setup_demo.ps1.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# CLOUD-M7 · Review 2

Controlled attack-path reconstruction across Edge → Fog → Cloud, with evidence-preserving repeated-read folding and dataset-specific SQL.

The prepared demonstration runs on one Windows laptop with fixed synthetic traces and supplied ground-truth labels. It does not claim unseen-attack detection, physical deployment, automatic containment, or measured network savings.

## Start

Use Python 3.12, Node.js 18+ and npm. Prepare once with internet available:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_demo.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\start_demo.ps1
```

After setup, double-click `run_node_dashboard.bat` or run the launcher. Open [the local dashboard](http://localhost:3001). Python dependencies live in `.venv`; JavaScript libraries and styles are served locally. Prerequisites are checked before opening the browser. Internet is unnecessary for the prepared walkthrough.

## Demonstrate

1. Load a bundled fixture or upload its JSON/CSV equivalent.
2. Inspect the original graph and switch to its reduced representation.
3. Expand the folded node to inspect all twenty original read events.
4. Follow the fourteen-event primary attack and inspect all three edge origins and shared choke points.
5. Inspect the explicitly labelled placement cost-model comparison.
6. Run SQL, switch datasets, and verify that counts follow the current selection.

| Controlled fixture | Events | Attack labels | Edge origins | Reduced nodes |
|---|---:|---:|---:|---:|
| Normal | 16 | 0 | 0 | 16 |
| Three-source attack | 70 | 22 | 3 | 70 |
| Attack + repeated reads | 92 | 22 | 3 | 73 |

The last fixture has **20.65% fewer graph nodes**, preserving source-to-target reachability. The attack fixture has no eligible repeated-read chain and correctly reports zero folding. Every raw record remains available. Parquet compression and exclusion from one selected path are separate metrics; small Parquet files can be larger than JSON.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
npm run test:e2e --prefix web_dashboard
.\.venv\Scripts\python.exe scripts\run_demo.py
.\.venv\Scripts\python.exe scripts\evaluate_review2.py --runs 5
```

Browser tests use installed Google Chrome, block external requests, and exercise graph views, expansion, upload/reload and SQL selection. Traces/screenshots go to ignored `output/`. Evaluation writes measured durations and sizes to `reports/review2_results.json` and `.csv`, separately from placement estimates.

## Review 2 material

- [Ten-minute teacher runbook](docs/review2_demo_runbook.md)
- [Implemented architecture and interfaces](docs/architecture.md)
- [Initial paper draft](docs/review2_paper_draft.md)
- [Expected fixture results](data/demo/manifest.json)
- [Recorded measurements](reports/review2_results.json)

Native JSON contains UUID, timestamp, tier, host, event type, payload and parents. CSV encodes payload/parents as JSON columns. Supplied integrity digests are verified. Invalid fields, duplicate IDs, missing parents, reversed dependencies and cycles produce errors. Upload limits are 5 MB and 2,000 events.

Each dataset owns content-addressed JSON/Parquet files under ignored `data/processed/datasets`. SQL requires its ID and exposes original records as `provenance`. Tracked `data/demo` holds stable fixtures. Intentional regeneration uses `scripts/prepare_demo_fixtures.py`; review the resulting diff.

## Existing modules and later phases

Public dataset adapters, Streamlit, hardware scripts, Docker configuration, bridge heuristics, MITRE rules and remediation templates remain available. Supplementary views explicitly label hypotheses and command proposals. Public benchmark captures are not bundled. Docker, live eBPF and physical-device integration are later work.

Older Review 1 slides, generated summaries and integration guides are historical planning material. Use the Review 2 runbook, architecture and recorded results for current claims. An unkeyed SHA-256 digest is not a signature or trusted immutable log; passing tests do not establish production quality or research novelty.

## Project provenance

This Review 2 implementation builds on the team's [CLOUD-M7 repository](https://github.com/DharshiniPES/cloud-m7). The original Git history and contributor attribution are retained. Local environments, duplicate database exports, runtime output and OneDrive backup placeholders are excluded from this repository.

# Review 2: ten-minute teacher demonstration

This is a controlled, software-only reconstruction experiment on one laptop. The input is generated ground truth, not captured public benchmark data. Attack labels are supplied to the analysis. Docker, physical devices and automated response are later work.

## Prepare once, with internet available

From the `cloud-m7` repository folder, in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_demo.ps1
```

Requirements: Windows, Python 3.12 (the verified lock environment), Node.js 18 or newer, npm. Setup creates `.venv`, installs locked Python and Node dependencies, validates the bundled files, and runs the Python tests. Browser tests use installed Google Chrome. No global Python packages are required by the demo.

## Start on presentation day

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\start_demo.ps1
```

Alternatively double-click `run_node_dashboard.bat`. The launcher verifies Python imports, JSON/CSV fixtures and local JavaScript dependencies, starts a hidden local server, waits for its health endpoint, then opens `http://localhost:3001`. Subsequent launches reuse the running Review 2 server. Internet access is unnecessary after setup. Logs are in `output/demo-server.log` and `output/demo-server-error.log`.

## The walkthrough

| Time | Action | Explain and verify |
|---|---|---|
| 0–1 min | Start with **Attack + repeated reads**. | This fixed fixture contains 92 events: 22 attack-labelled, 70 normal. It contains three edge origins and four matched cross-tier flows. |
| 1–2 min | Open **Input evidence**. | All records retain UUIDs, timestamps, payloads, parents and their original SHA-256 digests. CSV contains JSON-encoded `payload_json` and `parents_json`. |
| 2–4 min | Return to **Graph & reduction**; switch Original/Reduced and expand the folded group. | 92 nodes become 73, and 55 edges become 36. Twenty consecutive identical reads become one display node. Expand it to inspect all twenty original events. Source-to-target reachability is preserved. |
| 4–6 min | Open **Attack reconstruction**. | Show the 14-event primary chain and the paths from `edge-sensor-01`, `edge-sensor-02`, and `edge-actuator-03`. Inspect the shared fog `connect` event with 100% calculated containment across enumerated paths. This does not mean an isolation rule has been deployed. |
| 6–7 min | Open **Placement model**. | Compare assignments and centralized/adaptive estimates. CPU/memory limits, traffic assumptions, bandwidth and latency values come from the explicit cost model, not live device measurements. |
| 7–8 min | Open **SQL workspace**; use the event-count query. | The count is 92. Switch to **Normal activity**, run it again: 16. The normal fixture reports no attack path. SQL reads the selected dataset, not a global most-recent file. |
| 8–9 min | Upload `data/demo/attack.csv`; reload analysis. | The parsed file has 70 events, 22 attack labels, 48 normal events and three originating devices. SQL now counts 70. JSON and CSV versions represent identical evidence. |
| 9–10 min | Show test output and the result files. | The automated checks include shuffled arrival order, full socket matching, causal errors, lossless evidence expansion and dataset switching. Discuss controlled-data limits and next steps. |

The main attack fixture has no eligible repeated-read chain: it correctly reports **0% graph folding**, rather than inventing compression. Selected-path exclusion (80% on the 70-event file) is a different metric from graph folding and Parquet file compression.

## Evidence and commands

```powershell
.\.venv\Scripts\python.exe -m pytest -q
npm run test:e2e --prefix web_dashboard
.\.venv\Scripts\python.exe scripts\evaluate_review2.py --runs 5
```

`data/demo/manifest.json` documents expected structural results. `reports/review2_results.json` and `.csv` hold measured sizes/timings and separately labelled placement estimates. Browser verification blocks external requests, exercises the full workflow and saves `output/review2-dashboard.png`. It does not disconnect the laptop's network adapter.

## Terminal fallback

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py
```

This uses the same fixture and service as the dashboard, prints the reconstruction/reduction/model summary, and executes the 92-event count query. To select another fixture, append `--dataset attack` or `--dataset normal`.

## Troubleshooting and stopping

- Missing dependencies: rerun setup before disconnecting the internet. The launcher never silently substitutes the global Python interpreter.
- Wrong port owner: stop the other application; the launcher does not terminate unrelated processes.
- Invalid upload: the page displays row-level errors and retains the previous valid selection. Missing public benchmark samples are explicitly unavailable.
- Failed browser test: confirm Google Chrome is installed; inspect the retained trace in `output/browser-tests`.
- Stop this demo server using its recorded PID: inspect `output/demo-server.pid`, confirm that PID is the expected Node process with `Get-Process -Id <PID>`, then run `Stop-Process -Id <PID>`. A server started manually is stopped in its terminal with Ctrl+C.

No claim of unseen-attack detection, real-device bandwidth savings, cryptographic non-repudiation, or zero-collateral containment is established by this experiment. An unkeyed event hash can detect mismatches against an expected digest; it is not a signature or trusted log anchor.

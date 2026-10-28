# Review 2 verification record

Verified locally on 28 October 2026, Windows / Python 3.12.10 / Node.js 24.18.0 / Google Chrome.

Story: select or upload controlled evidence → validate and normalize → construct the causal DAG → inspect reduction and original records → reconstruct paths → query the selected persisted dataset.

| Boundary | Result | Evidence |
|---|---|---|
| Python implementation | Passed | `47 passed` from the project-local `.venv`, including all 26 existing tests. |
| Browser workflow | Passed | Two Playwright tests; the teacher walkthrough blocks external requests and observes no external requests or JavaScript page errors. |
| Views and evidence | Passed | Original/reduced graph, twenty-member expansion, fourteen-event timeline and three source devices. |
| Upload and reload | Passed | Native CSV upload gives 70 events; content-ID reload preserves identity; invalid JSON displays a row-level error. |
| SQL dataset isolation | Passed | Switching normal/repeated/uploaded evidence returns 16/92/70 records from the respective dataset. |
| Failure handling | Passed | Missing public samples, unsafe SQL, duplicates, hash mismatch, missing/reversed parents, cycles and disconnected paths are checked. |
| Setup and launch | Passed | `setup_demo.ps1` installs locked dependencies and runs tests; clean hidden-server launch and subsequent reuse pass prerequisite/health checks. |
| Runtime dependencies | Passed | `pip check` reports no broken requirements. |
| Terminal fallback | Passed | Same fixture/service prints three origins, fourteen primary events and SQL count 92. |
| Formatting check | Passed | `git diff --check` has no whitespace errors. Git emits only line-ending conversion notices. |

The launcher health check uses `127.0.0.1` to avoid the Windows PowerShell/localhost resolution issue observed during startup testing. The server remains bound to loopback. Node dependencies are served locally; tests do not disconnect the laptop's network adapter.

Structural expected results are in `data/demo/manifest.json`. Five-run measurements are in `reports/review2_results.json` and `.csv`; these record graph counts, file sizes, timing range/median, dependency versions and separately labelled model assumptions. The initial paper's timings describe that captured run, not guaranteed future latency.

Browser screenshot: `output/review2-dashboard.png`. Browser traces on failure: `output/browser-tests`. Runtime logs: `output/demo-server.log` and `output/demo-server-error.log`. These generated files are ignored by Git.

The prepared scope uses generated labelled traces. Public-dataset evaluation, Docker telemetry, hardware capture, real traffic/resource measurements and automatic enforcement remain outside this verification.

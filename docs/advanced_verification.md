# Advanced integration verification

Verified locally on **31 October 2026**, Windows, with the existing project environment and Google Chrome.

Story: select/upload evidence → validate and reconstruct the original graph → inspect six derived experimental tracks → download the full candidate trajectory → switch to normal evidence → query its original records.

| Check | Result and evidence |
|---|---|
| Complete Python suite | **70 passed in 2.92 seconds**, including the original 47 cases and 23 advanced regression cases. |
| Complete browser suite | **3 passed in 1.2 minutes** against a fresh server on port 3307. Includes both original Review 2 cases and the advanced workflow. |
| Final advanced browser rerun | **1 passed in 42.2 seconds** after the final backend corrections; refreshed screenshot and downloaded export checks passed. |
| Updated local launcher | `start_demo.ps1 -NoBrowser` succeeds. The running port-3001 API returns success, 92 original events, 73 reduced nodes, six tracks and 92 stream events, with hardware attestation and ZK validity both false as intended. |
| Browser dependencies | Both walkthroughs block non-local requests and assert no external requests or JavaScript page errors. |
| UI → API → evidence | Repeated fixture renders 92 original events, 73 folded nodes, three origins, a 14-event primary path and all six experimental panels. |
| Experimental correctness | Tests preserve the unlabelled attack intermediate, check all-pairs reachability on a reducible graph, reject simulated/corrupted proofs, exclude labels from temporal scoring and respond to timestamp changes. |
| Normal-only handling | Normal evidence has 16 received/accepted stream events, nominal RL state, no graph-cut claim and no invented threat objects. |
| Export/download | Browser download contains all 14 primary-trajectory attack patterns; internal relationship references resolve. External schema certification is not claimed. |
| Streaming | Tests consume an actual generator, count 25,000 generated events, and verify configured late-event rejection on out-of-order input. No minimum speed assertion or artificial elapsed-time constant. |
| Hardware → native ingestion | Producer digest round-trips through strict normalization. Changed payload is rejected. A loopback fog HTTP test accepts the canonical record and rejects the altered one before buffering. |
| Core regression | Original Python/browser tests still verify fixture counts, three sources, original/reduced views, evidence expansion, CSV upload/reload and dataset-specific SQL. |
| Terminal fallback | `scripts/run_demo.py` succeeds: 92 → 73 nodes, three origins, 14 primary-path events and SQL count 92. |
| Script compatibility | Direct `cloud_m7/hardware/edge_probe.py --help` succeeds from the checkout. |
| Source checks | JavaScript syntax checks and `git diff --check` pass. Git emits only Windows line-ending conversion notices. |

The experimental dashboard screenshot was visually inspected: `output/advanced-dashboard.png`. Desktop panels render without overlap; the browser test additionally checks that the normal-input page does not overflow horizontally at a 390-pixel viewport.

The final Python run includes the corrected edge-containment reward objective and graph metadata/digest agreement checks. The advanced browser case is rerun after those final backend corrections to refresh the screenshot.

Live eBPF/perf capture, hardware TPM attestation, trained anomaly detection, SNARK proving, deployed enforcement, external STIX/SIEM interoperability, distributed streaming and public-benchmark evaluation remain unverified. Their current status is explicit in the UI and [integration guide](advanced_integration.md).

No new runtime dependency is needed. The integration retains teammate attribution. These results verify the local implementation; publishing the source does not establish a deployment or additional runtime guarantees.

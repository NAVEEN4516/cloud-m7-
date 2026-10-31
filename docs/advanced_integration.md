# Advanced experiments integration

Integrated locally on 31 October 2026 into the Review 2 baseline `1a959edf435c94a2c62cf04269348fbea3c300a2`.

## Contribution provenance

The six module concepts, original data structures, telemetry profile examples and Q-learning reward environment come from **Dharshini's** [advanced-tracks commit](https://github.com/DharshiniPES/cloud-m7/commit/23ba5ed2e9122ee49321e2fa21135599eeb4fa68), reviewed at repository head `1ee1721071f7d116e17292fcea43ce5314766f93`. This integration adapts those contributions instead of replacing Naveen's corrected core with the older bridge/dashboard. Source headers retain that attribution. No GitHub push or merge commit is implied by this local file integration.

## Run and inspect

Use the existing setup and `start_demo.ps1` launch flow. Open **Advanced experiments** in the sidebar. All six views follow fixture selection or validated upload. Selecting normal evidence clears the incident-specific graph-cut result and exports no invented campaign or attack patterns. The RL trajectory begins in the nominal model state.

The page uses locally served assets only. It includes a candidate STIX download. The original graph, evidence expansion, attack timeline and SQL remain in their existing views.

## Implemented behavior and limits

| Track | Computation | Interpretation |
|---|---|---|
| 1: eBPF/HPC/TPM | Deterministic seeded sample profiles, hash extension and software HMAC | Simulation only. No eBPF/perf/TPM access. Hardware attestation is false. |
| 2: Entropy | Propose repetitive incoming edges, remove only if an alternate causal path survives, recheck final removed-edge reachability | Retains every node. Every original edge survives or has a path in the final graph, so original reachability is preserved. Raw evidence is untouched. |
| 2: Temporal scoring | Two fixed-weight message-passing rounds using actual nonnegative event-time deltas | Uses neither `is_attack` in features nor labels in score branching. Historical GNN class name remains for compatibility; this is an untrained structural heuristic. |
| 3: RL | Tabular Q-learning over the teammate's hand-authored five-state model | Supplied labels/tiers choose the initial state. Action shares are counted during training. Convergence is nullable and requires five episodes of small Q updates. Efficacy/disruption are reward-model assumptions; no command is executed. |
| 4: ZK | Public-input checksum bundle and an independent candidate-node deletion/reachability calculation | No SNARK implementation. `verify_proof` always rejects, including altered bundles. Graph reachability is a graph check, not a cryptographic containment proof. |
| 5: Shield | Check node timestamp order, cross-tier socket tuples/directions, supplied canonical event hashes and graph/evidence agreement | Failed temporal/socket edges are removed only from a derived inspection graph. Missing evidence and process-lineage checks are reported unavailable; overall integrity is not assigned a fabricated percentage. Hash consistency does not establish authenticity. |
| 6: STIX | Export every primary-timeline step, internal relationships and evidence-associated MITRE references | Candidate STIX 2.1 export. Internal IDs/metadata/references are checked. No external STIX schema certification or SIEM interoperability is claimed. Normal input yields an empty bundle. |
| 6: Streaming | Consume actual selected events, count tumbling windows, advance watermark and count late drops | Measured in-memory Python aggregation only. Throughput excludes network/storage. Watermark lag is configured lateness, not measured transport latency. The selected evidence is currently sorted before analysis. |

Entropy reduction and the existing repeated-read folding have different purposes. The advanced track reports a derived **edge** reduction; the Review 2 graph switch still uses conservative repeated-read **node** folding. Neither deletes raw records.

STIX output represents the full **primary trajectory**, not every branch in the global DAG. Course-of-action objects describe proposed graph-derived isolation; they do not establish real-world mitigation. Original labels and heuristic MITRE matches retain their existing limitations.

## Integration details

The upstream reward table rewarded rate-limiting that allowed an edge attack to reach the fog. Combined with the larger fog reward, it could make delaying containment preferable. The integrated model penalizes that progression; a regression assertion requires the learned edge policy to freeze the process. This is a correction to the simulated objective, not evidence of deployed response quality.

Entropy uses explicit edge actions when available, then source-event actions and relation labels. Consequently the reported global action entropy reflects the actual causal graph instead of treating every unlabelled edge as the same generic action.

`cloud_m7/advanced/analysis.py` runs each calculation once and returns `advanced_tracks`. It uses all labelled event IDs only for protected entropy nodes and scenario/model-state selection. The temporal scorer receives the graph but never reads its label field. ZK status and the actual graph-cut check are separate fields. All original events remain in the base response and dataset-specific storage.

Top-level analysis timing is assigned after placement and all experimental result calculations. Experimental timing is measured after all six tracks have completed. Both omit response serialization, Python process startup and the browser request/render cycle.

`web_dashboard/public/advanced.js` renders the isolated experimental panel. No CDN or new package dependency was introduced. Test configuration accepts `CLOUD_M7_TEST_PORT` so validation can start a fresh server without reusing stale application code.

Hardware events now use `ProvenanceEvent` for UUID uniqueness, serialization and canonical hashing. A complete checkout supports direct `edge_probe.py` execution as well as `python -m cloud_m7.hardware.edge_probe`. The fog receiver rejects missing/mismatched digests before buffering. This resolves the old hardware/native-upload format disagreement; it does not establish a trusted hardware identity or deploy devices.

## Verification

Run from the project root using the existing environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
$env:CLOUD_M7_TEST_PORT = '3307'
npm run test:e2e --prefix web_dashboard
```

The original 47 Python cases remain. Added regression cases cover the attack-chain counterexample, all-pairs reachability after actual reduction, changed timestamps, flipped labels, corrupted proof elements, missing evidence, socket mismatches, nominal RL behavior, deterministic RNG isolation, full trajectory export, dangling references, actual stream consumption, late-event drops, hardware round trip, fog rejection and selected-dataset integration.

The browser suite retains both original cases and adds the six-track view, simulation/incomplete-verification messages, full downloadable trajectory, normal-only behavior, mobile overflow and SQL selection. Its advanced walkthrough blocks non-local requests and checks for JavaScript page errors. Screenshot: `output/advanced-dashboard.png`.

Recorded results from this integration are listed in `docs/advanced_verification.md`. The October 28 `review2_verification.md` and captured measurement reports remain historical records rather than being silently relabelled as new experimental measurements.

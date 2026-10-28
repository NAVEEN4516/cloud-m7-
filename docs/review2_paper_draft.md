# CLOUD-M7: Evidence-Preserving Reduction for Controlled Cross-Tier Attack Reconstruction

Initial capstone manuscript draft · Review 2 · 28 October 2026

## Abstract

CLOUD-M7 investigates reconstruction of causal attack trajectories represented across edge, fog and cloud event streams. The prototype normalizes controlled JSON/CSV telemetry, constructs an order-independent causal graph, correlates cross-tier sockets, and folds structurally redundant file-read chains while retaining original evidence. A laptop dashboard exposes full and reduced graphs, reconstructed trajectories, candidate choke points and SQL over dataset-specific Parquet records. Three fixtures exercise normal activity, a three-source attack and repeated-read reduction. The repeated-read fixture decreases from 92 to 73 nodes (20.65%) while preserving source-to-target reachability and expandable evidence. The attack yields a fourteen-event primary explanation and paths from three edge devices to cloud impact. These results demonstrate behaviour on supplied ground truth; they do not establish accuracy on unseen attacks or savings in deployed networks.

## 1. Problem and objectives

Investigators using multi-tier telemetry need to preserve relationships across process/file operations and network boundaries. A smaller representation is useful only when connected to its underlying evidence. This review asks whether ingestion, reconstruction and conservative folding can operate together without silently dropping dependencies or changing source-to-impact reachability.

The acceptance objectives are equivalent JSON/CSV ingestion, independence from arrival order, all three edge sources reaching the cloud, expandable repeated-read folding, and isolated SQL results during dataset switching. These are implementation criteria, not claims of novelty against prior forensic systems.

## 2. Methods

**Events and validation.** Events record UUID, timestamp, tier, host, type, payload and parent UUIDs. Native ingestion validates fields, supplied digests, unique IDs and parent references. SHA-256 permits comparison against an expected digest; an unkeyed hash alone supplies neither authentication nor non-repudiation.

**Causal fusion.** Register nodes before resolving dependencies. Reject backward dependencies and cycles. Add cross-tier socket edges for equal source IP/port, destination IP/port and protocol, with inbound time zero to fifteen seconds after outbound. NetworkX provides DAG traversal and reachability primitives [1]. A disconnected pair remains disconnected; timestamp order is never fabricated as a path.

**Reduction.** A maximal chain of file reads may use one representative when host/tier and complete payloads match, process/resource identifiers exist, and every member has one predecessor and successor. Boundary, network, branch and merge nodes remain distinct. Representatives retain ordered original UUIDs. A path expands to the stored chain. Since folding introduces no alternative entry or exit, it preserves reachability between distinct representatives. Tests compare original/reduced reachability; runtime metrics check source/sink reachability. Not every input contains a foldable chain.

**Investigation and storage.** The original DAG is authoritative for shortest-path reconstruction, iterative root exploration and choke-point scoring. Supplied labels guide these modules. The reduced DAG is an inspection representation; raw records remain in JSON/Parquet. A content-derived dataset ID selects the immutable files used by SQL. PyArrow supplies Parquet I/O [2]. Storage compression is separate from graph reduction.

**Placement model.** A constrained optimizer compares centralized and adaptive assignments under fixed stage-resource and traffic assumptions. Its latency, bandwidth, privacy and CPU/memory values are estimates, not live-device measurements.

## 3. Controlled experiment

Fixtures use base timestamp 1,700,000,000 seconds and stable UUIDs. The attack fixture contains 48 normal and 22 attack-labelled events. Three edge devices converge through fog to a cloud target. The repeated fixture appends a benign start, twenty identical consecutive thermal reads, and an end. Paired JSON/CSV files and an expected-results manifest are bundled. Labels are known by construction.

The recorded run used Windows, Python 3.12.10, NetworkX 3.7, pandas 2.3.3, PyArrow 26.0.0 and DuckDB 2.0.0. Five sequential analyses ran per dataset with no excluded warmup. Timings exclude process startup, HTTP and browser overhead. Locked dependencies and `scripts/evaluate_review2.py` permit repetition. This is a functionality experiment, not a throughput benchmark.

## 4. Preliminary results

| Fixture | Events | Attack labels | Edge sources | Primary path events | Reduced nodes | Node reduction |
|---|---:|---:|---:|---:|---:|---:|
| Normal | 16 | 0 | 0 | 0 | 16 | 0% |
| Three-source attack | 70 | 22 | 3 | 14 | 70 | 0% |
| Attack + repeated reads | 92 | 22 | 3 | 14 | 73 | 20.65% |

Attack fixtures each contain four matched cross-tier flows. Folding removes nineteen representation nodes and nineteen edges from the repeated fixture, retaining every original member. All three sources remain connected to cloud impact. Normal-only data yields no claimed attack path.

| Fixture | JSON bytes | Parquet bytes | Median analysis (ms) | Median reduction (ms) |
|---|---:|---:|---:|---:|
| Normal | 6,766 | 12,603 | 62.64 | 0.419 |
| Three-source attack | 30,336 | 20,386 | 103.34 | 2.295 |
| Repeated reads | 38,635 | 22,458 | 99.86 | 2.957 |

These timings are one recorded machine run and may change. The small normal fixture grows in Parquet, illustrating overhead. Excluding 80% of nodes from one fourteen-event explanation is not 80% graph compression. Centralized/adaptive placement estimates of 160/20 ms and 500/50 KB/s follow model assumptions, not empirically measured network savings. Full captured results and assumptions are in `reports/review2_results.json`.

## 5. Verification and limitations

Tests cover existing modules, JSON/CSV equivalence, shuffled ingestion, malformed rows, temporal/cycle rejection, port/protocol mismatches, reachability, evidence expansion and SQL isolation. Browser tests exercise views, upload/reload, normal-only handling and queries with external requests blocked. These establish a local workflow rather than production reliability.

The fixtures are generated, small and labelled. They do not establish generalisation, adversarial robustness or calibrated confidence. Simple-path enumeration has a length cutoff and may become expensive on larger graphs; demo inputs are capped at 2,000 events. Folding retains ordered evidence, not raw node-level path lengths in the reduced representation. Physical deployment, trusted anchoring, live capture and public datasets remain future experiments. Complete a sourced literature comparison before claiming novelty or submitting this draft.

## 6. Conclusion

The Review 2 contribution is a reproducible ingestion/reconstruction workflow with conservative reduction of a known redundant chain, retained original evidence and preserved causal reachability. Next steps are sourced benchmark evaluation, deployed telemetry, alternative reduction rules and measured system costs.

## References and reproduction artifacts

1. NetworkX Developers. [Directed acyclic graph algorithms](https://networkx.org/documentation/stable/reference/algorithms/dag.html). Traversal and acyclicity primitives; no comparative performance claim is drawn from this documentation.
2. Apache Arrow. [Reading and Writing the Apache Parquet Format](https://arrow.apache.org/docs/python/parquet/). Parquet I/O support used by the prototype.
3. CLOUD-M7. `data/demo/manifest.json`, paired fixtures, `reports/review2_results.json`, `docs/architecture.md` and `docs/review2_demo_runbook.md`: controlled experiment, captured results, implementation and reproduction procedure.

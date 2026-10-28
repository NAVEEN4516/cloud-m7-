"""
High-Performance Python-to-Node.js JSON Bridge for CLOUD-M7 Dashboard.
Runs full graph analytics, the 5 novelties, dataset normalization, and SQL queries,
outputting clean JSON for the Node.js Express server.
"""

import argparse
import json
import os
import sys
import time
import hashlib
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from cloud_m7.adapters.factory import DatasetNormalizerFactory
from cloud_m7.adapters.canonical import DatasetValidationError
from cloud_m7.fusion.reduction import fold_repeated_reads
from cloud_m7.placement.demo import placement_comparison
from cloud_m7.fusion.active_remediation import ActiveChokePointRemediator
from cloud_m7.fusion.attack_path import AttackPathReconstructor
from cloud_m7.fusion.causal_bridge import CausalBridgeImputer
from cloud_m7.fusion.causal_graph import ProvenanceGraphEngine
from cloud_m7.fusion.interconnected_paths import InterconnectedAttackPathEngine
from cloud_m7.fusion.iterative_discovery import IterativeAttackDiscoveryEngine
from cloud_m7.fusion.mitre_mapper import MitreAttackMapper
from cloud_m7.hardware.edge_probe import generate_hardware_event
from cloud_m7.schema.event import ProvenanceEvent
from cloud_m7.schema.types import TierType
from cloud_m7.simulator.attack_scenario import MultiTierAttackSimulator
from cloud_m7.storage.parquet_engine import ProvenanceStorageEngine


DEMO_DIR = ROOT_DIR / "data" / "demo"
BUNDLED = {"synthetic": "attack", "attack": "attack", "normal": "normal", "repeated": "repeated"}


def load_dataset_events(dataset_id: str) -> tuple[List[ProvenanceEvent], str]:
    factory = DatasetNormalizerFactory()
    if dataset_id in BUNDLED:
        return factory.normalize(str(DEMO_DIR / f"{BUNDLED[dataset_id]}.json"))
    if dataset_id in ("darpa_optc", "darpa_tc", "ton_iot", "iot23"):
        raise DatasetValidationError(["Public benchmark files are not bundled. Upload a sourced file; Review 2 uses controlled fixtures."])
    if re.fullmatch(r"ds-[0-9a-f]{64}", dataset_id):
        path = ROOT_DIR / "data" / "processed" / "datasets" / f"{dataset_id}.json"
        return factory.normalize(str(path))
    if not os.path.isfile(dataset_id):
        raise DatasetValidationError([f"Dataset not found: {dataset_id}"])
    return factory.normalize(dataset_id)


def analyze_dataset(dataset_id: str) -> Dict[str, Any]:
    """Executes full multi-tier analysis across all 5 novelties and storage layer."""
    t0 = time.time()
    requested_dataset = dataset_id
    events, detected_fmt = load_dataset_events(requested_dataset)
    if len(events) > 2000:
        raise DatasetValidationError(["This laptop demo supports at most 2000 events per dataset"])
    events = sorted(events, key=lambda e: (e.timestamp, e.uuid))
    canonical = json.dumps([e.to_dict() for e in events], sort_keys=True, separators=(",", ":"))
    dataset_id = "ds-" + hashlib.sha256(canonical.encode()).hexdigest()
    provenance = {
        "kind": "controlled_synthetic" if requested_dataset in BUNDLED else "user_supplied",
        "source": f"data/demo/{BUNDLED[requested_dataset]}.json" if requested_dataset in BUNDLED else os.path.basename(requested_dataset),
        "description": "Controlled synthetic ground truth; not a real attack capture" if requested_dataset in BUNDLED else "User-supplied file; source claims have not been independently verified",
        "labels": "is_attack values are supplied labels; this demonstration reconstructs evidence, not unseen-attack detection",
        "sha256": dataset_id[3:],
    }

    # 1. Graph Synthesis
    engine = ProvenanceGraphEngine(time_window_seconds=15.0)
    engine.add_events(events)
    global_dag = engine.fuse_global_graph()
    summary_stats = engine.get_summary_statistics()

    # 2. Attack Path Slicing
    reconstructor = AttackPathReconstructor(engine)
    recon_res = reconstructor.reconstruct_attack_path()

    reconstructed_steps = []
    attack_node_set = set()
    if recon_res:
        for s in recon_res.attack_steps:
            attack_node_set.add(s.uuid)
            reconstructed_steps.append({
                "order": s.order,
                "uuid": s.uuid,
                "tier": s.tier,
                "host_id": s.host_id,
                "event_type": s.event_type,
                "action": s.action,
                "entity": s.entity,
                "description": s.description,
            })

    reduction = fold_repeated_reads(global_dag,
        protected_nodes=[recon_res.source_root_uuid, recon_res.target_impact_uuid] if recon_res else [])

    # 3. Novelty 1: Iterative Multi-Root Discovery
    iter_engine = IterativeAttackDiscoveryEngine(
        engine, max_iterations=5, impact_threshold_epsilon=5.0, causal_attenuation=0.85
    )
    iter_res = iter_engine.discover_all_attack_points()

    novelty1_history = []
    for h in iter_res.iteration_history:
        novelty1_history.append({
            "iteration": h.iteration,
            "converged": h.converged,
            "new_nodes_discovered": h.new_nodes_discovered,
            "total_discovered_nodes": h.total_discovered_nodes,
            "cumulative_impact_score": round(h.cumulative_impact_score, 2),
            "marginal_impact_gain_pct": round(h.marginal_impact_gain_pct, 2),
            "reason": h.reason,
        })

    discovered_vectors = []
    for v in iter_res.discovered_vectors:
        discovered_vectors.append({
            "vector_id": v.vector_id,
            "entry_tier": v.entry_tier,
            "entry_host": v.entry_host,
            "entry_entity": v.entry_entity,
            "path_length": v.path_length,
            "impact_score": round(v.vector_impact_score, 2),
            "description": v.description,
        })

    # 4. Novelty 2: Choke Points & Articulation Vertices
    intercon_engine = InterconnectedAttackPathEngine(engine)
    intercon_res = intercon_engine.analyze_interconnected_attack_graph()

    choke_points = []
    choke_node_ids = set()
    for cp in intercon_res.choke_points:
        if cp.containment_efficiency_pct >= 60.0 or cp.is_cut_vertex:
            choke_node_ids.add(cp.node_id)
        choke_points.append({
            "node_id": cp.node_id,
            "tier": cp.tier,
            "host_id": cp.host_id,
            "action": cp.action,
            "entity": cp.entity,
            "paths_severed": cp.paths_severed_count,
            "total_paths": cp.total_paths_count,
            "containment_efficiency_pct": cp.containment_efficiency_pct,
            "is_cut_vertex": cp.is_cut_vertex,
            "mitigation_recommendation": cp.mitigation_recommendation,
        })

    # 5. Novelty 3: Causal Bridge Imputation
    imputer = CausalBridgeImputer(max_time_window_sec=30.0, confidence_threshold=0.60)
    bridge_res = imputer.impute_missing_bridges(global_dag)

    imputed_bridges = []
    for b in bridge_res.imputed_bridges:
        imputed_bridges.append({
            "source_uuid": b.source_uuid,
            "target_uuid": b.target_uuid,
            "source_tier": b.source_tier,
            "target_tier": b.target_tier,
            "source_host": b.source_host,
            "target_host": b.target_host,
            "time_delta_sec": round(b.time_delta, 2),
            "endpoint_similarity": round(b.endpoint_similarity, 2),
            "confidence_pct": round(b.confidence_score * 100.0, 1),
            "rationale": b.imputation_rationale,
        })

    # 6. Novelty 4: Active Choke-Point Remediation
    remediator = ActiveChokePointRemediator(lambda_collateral_weight=0.5)
    nodes_meta = {n: d for n, d in global_dag.nodes(data=True)}
    remediation_plan = remediator.generate_remediation_plan(intercon_res.choke_points, nodes_meta)

    remediation_policies = []
    for p in remediation_plan.policies:
        remediation_policies.append({
            "choke_node_id": p.choke_point_node_id,
            "mechanism": p.mechanism.value,
            "target_tier": p.target_tier,
            "target_host": p.target_host,
            "containment_efficacy_pct": p.containment_efficacy_pct,
            "collateral_disruption_index": p.collateral_disruption_index,
            "rps_score": p.remediation_priority_score,
            "command": p.executable_command,
            "rollback": p.rollback_command,
            "description": p.policy_description,
        })

    # 7. Novelty 5: MITRE ATT&CK Matrix Mapping
    attack_subg = intercon_res.induced_attack_subgraph if intercon_res.induced_attack_subgraph.number_of_nodes() > 0 else global_dag
    mapper = MitreAttackMapper()
    mitre_report = mapper.map_attack_graph(attack_subg)

    mitre_matches = []
    for m in mitre_report.matched_techniques:
        mitre_matches.append({
            "tactic_id": m.tactic_id,
            "tactic_name": m.tactic_name,
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tier": m.tier,
            "host_id": m.host_id,
            "evidence_uuid": m.evidence_uuid,
            "confidence_pct": round(m.confidence_score * 100.0, 1),
            "reasoning": m.reasoning,
        })

    # 8. Parquet + DuckDB Storage Layer Benchmark
    storage = ProvenanceStorageEngine()
    data_dir = ROOT_DIR / "data" / "processed" / "datasets"
    data_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = str(data_dir / f"{dataset_id}.parquet")
    json_path = str(data_dir / f"{dataset_id}.json")
    # Publish completed files atomically; other dataset selections never overwrite them.
    with tempfile.TemporaryDirectory(dir=data_dir) as temporary:
        temp_parquet = str(Path(temporary) / "events.parquet")
        temp_json = str(Path(temporary) / "events.json")
        bench = storage.benchmark_compression(events, temp_parquet, temp_json)
        os.replace(temp_parquet, parquet_path)
        os.replace(temp_json, json_path)
    storage.conn.close()

    # 9. Graph representation for Frontend Vis-Network (Canvas)
    vis_nodes = []
    tier_colors = {"Edge": "#10B981", "Fog": "#F59E0B", "Cloud": "#8B5CF6"}

    for n, d in global_dag.nodes(data=True):
        tier = d.get("tier", "Edge")
        is_attack = d.get("is_attack", False) or (n in attack_node_set)
        action = str(d.get("action", d.get("event_type", "event")))
        host = str(d.get("host_id", ""))
        entity = str(d.get("entity", ""))

        is_choke = n in choke_node_ids
        color = "#EF4444" if is_attack else tier_colors.get(tier, "#94A3B8")
        if is_choke:
            color = "#EAB308"

        label = f"[{tier}]\n{action}\n({host})"
        if is_choke:
            label = f"★ CHOKE ★\n{action}\n({host})"

        vis_nodes.append({
            "id": n,
            "label": label,
            "tier": tier,
            "host": host,
            "action": action,
            "entity": entity,
            "is_attack": is_attack,
            "is_choke": is_choke,
            "color": color,
            "size": 26 if is_choke else (22 if is_attack else 15),
            "title": f"UUID: {n}<br>Tier: {tier}<br>Host: {host}<br>Action: {action}<br>Entity: {entity}<br>Attack: {is_attack}",
        })

    vis_edges = []
    for u, v, d in global_dag.edges(data=True):
        rel = d.get("relation", "FLOW")
        is_imputed = d.get("imputed", False)
        edge_color = "#EC4899" if is_imputed else ("#EF4444" if (u in attack_node_set and v in attack_node_set) else "#3B82F6")
        vis_edges.append({
            "from": u,
            "to": v,
            "label": f"imputed ({d.get('confidence', 0.8)*100:.0f}%)" if is_imputed else "",
            "color": edge_color,
            "dashes": is_imputed,
            "title": rel,
        })

    # Normalized events sample preview (first 50)
    events_preview = []
    for e in events[:50]:
        events_preview.append({
            "uuid": e.uuid,
            "timestamp": round(e.timestamp, 3),
            "tier": e.tier.value if isinstance(e.tier, TierType) else str(e.tier),
            "host_id": e.host_id,
            "event_type": e.event_type.value,
            "action": str(e.payload.get("action", "")),
            "entity": str(e.payload.get("entity", ""))[:40],
            "is_attack": bool(e.payload.get("is_attack", False)),
            "tamper_hash": e.tamper_hash[:16] + "..." if e.tamper_hash else "None",
        })

    original_vis = {node["id"]: node for node in vis_nodes}
    reduced_nodes = []
    for node, attrs in reduction.graph.nodes(data=True):
        members = reduction.membership[node]
        item = dict(original_vis[members[0]])
        item.update(id=node, member_uuids=members, folded_count=len(members))
        if len(members) > 1:
            item["label"] = f"{len(members)} identical reads\n({attrs.get('host_id')})"
            item["size"] = 28
        reduced_nodes.append(item)
    reduced_edges = [{"from": u, "to": v, "arrows": "to", "title": d.get("relation", "causal_dependency")}
        for u, v, d in reduction.graph.edges(data=True)]

    total_time_ms = round((time.time() - t0) * 1000, 2)

    return {
        "status": "success",
        "dataset_name": requested_dataset,
        "dataset_id": dataset_id,
        "dataset_provenance": provenance,
        "events": [e.to_dict() for e in events],
        "reduction": reduction.metrics,
        "reduced_graph": {"nodes": reduced_nodes, "edges": reduced_edges},
        "folded_membership": reduction.membership,
        "folded_evidence": {node: [engine.events_by_id[uid].to_dict() for uid in members]
            for node, members in reduction.membership.items() if len(members) > 1},
        "placement": placement_comparison(),
        "detected_format": detected_fmt,
        "processing_time_ms": total_time_ms,
        "summary": {
            "total_events": len(events),
            "total_nodes": summary_stats.get("total_nodes", len(events)),
            "total_edges": summary_stats.get("total_edges", 0),
            "cross_tier_flows": summary_stats.get("cross_tier_edges_count", 0),
            "is_valid_dag": summary_stats.get("is_directed_acyclic_graph", True),
            "path_length": recon_res.path_length if recon_res else 0,
            "noise_reduction_pct": recon_res.reduction_percentage if recon_res else 0.0,
            "attack_events_count": sum(1 for e in events if e.payload.get("is_attack")),
        },
        "events_preview": events_preview,
        "graph": {
            "nodes": vis_nodes,
            "edges": vis_edges,
        },
        "reconstructed_timeline": reconstructed_steps,
        "novelty1_iterative": {
            "total_iterations": iter_res.total_iterations_run,
            "history": novelty1_history,
            "vectors": discovered_vectors,
        },
        "novelty2_chokepoints": {
            "choke_points": choke_points,
            "originating_sensors": intercon_res.originating_sensors,
        },
        "novelty3_causal_bridge": {
            "severed_detected": bridge_res.severed_components_detected,
            "imputed_count": bridge_res.imputed_bridges_count,
            "repaired_paths_count": bridge_res.repaired_attack_paths_count,
            "bridges": imputed_bridges,
        },
        "novelty4_remediation": {
            "overall_containment_pct": remediation_plan.overall_containment_pct,
            "average_collateral_index": remediation_plan.average_collateral_index,
            "optimal_target_choke": remediation_plan.optimal_choke_point_node,
            "policies": remediation_policies,
            "deployment_script": remediation_plan.deployment_script,
        },
        "novelty5_mitre": {
            "total_mapped": mitre_report.total_techniques_mapped,
            "lifecycle_coverage_pct": mitre_report.kill_chain_coverage_pct,
            "tactics_observed": mitre_report.tactics_observed,
            "matches": mitre_matches,
            "summary_text": mitre_report.progression_summary,
        },
        "parquet_storage": {
            "total_events": bench["total_events"],
            "raw_json_bytes": bench["json_size_bytes"],
            "parquet_bytes": bench["parquet_size_bytes"],
            "compression_ratio": bench["compression_ratio"],
            "query_latency_ms": round(bench["parquet_query_time_sec"] * 1000, 2),
            "parquet_file_path": parquet_path,
        },
    }


def execute_sql(sql_query: str, dataset_id: str = "") -> Dict[str, Any]:
    """Query exactly the dataset selected in the UI; never a global last-written file."""
    if not re.fullmatch(r"ds-[0-9a-f]{64}", dataset_id):
        return {"status": "error", "message": "A valid selected dataset_id is required"}
    parquet_path = ROOT_DIR / "data" / "processed" / "datasets" / f"{dataset_id}.parquet"
    if not parquet_path.is_file():
        return {"status": "error", "message": "Dataset not initialized. Load it before querying."}
    storage = ProvenanceStorageEngine()
    t0 = time.perf_counter()
    try:
        # The teacher console is read-only and exposes the selected dataset as a view.
        storage.conn.execute("SET enable_external_access=false")
        import pyarrow.parquet as pq
        storage.conn.register("provenance", pq.read_table(parquet_path))
        statements = storage.conn.extract_statements(sql_query)
        if len(statements) != 1 or str(statements[0].type).split(".")[-1] != "SELECT":
            raise ValueError("Only one read-only SELECT statement is allowed")
        df = storage.conn.execute(sql_query).fetchdf()
        return {"status": "success", "dataset_id": dataset_id, "columns": list(df.columns),
            "rows": json.loads(df.to_json(orient="records")), "row_count": len(df),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 3)}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
    finally:
        storage.conn.close()


def generate_hardware_telemetry(count: int = 5) -> Dict[str, Any]:
    """Generates physical/simulated hardware readings from edge probe."""
    buffered = []
    for i in range(count):
        is_attack = (i == count - 1)
        evt = generate_hardware_event(
            event_type="Process" if is_attack else "File",
            action="exec" if is_attack else "write",
            entity="/usr/local/bin/tamper_firmware.sh" if is_attack else "/var/log/sensor_readings.csv",
            is_attack=is_attack,
            extra_payload={"cpu_temp_c": round(41.5 + i * 0.7, 1)},
            host_id="rpi-4-node-01",
        )
        buffered.append(evt)
    return {"status": "success", "count": count, "events": buffered}


def main():
    parser = argparse.ArgumentParser(description="CLOUD-M7 Python Bridge API for Node.js Dashboard")
    parser.add_argument("--action", choices=["analyze", "sql", "hardware"], default="analyze")
    parser.add_argument("--dataset", default="synthetic")
    parser.add_argument("--dataset-id", default="")
    parser.add_argument("--query", default="SELECT tier, event_type, COUNT(*) as count FROM provenance GROUP BY tier, event_type")
    parser.add_argument("--count", type=int, default=5)
    args = parser.parse_args()

    try:
        if args.action == "analyze":
            res = analyze_dataset(args.dataset)
        elif args.action == "sql":
            res = execute_sql(args.query, args.dataset_id)
        else:
            res = generate_hardware_telemetry(args.count)
    except (ValueError, OSError) as exc:
        res = {"status": "error", "message": str(exc), "errors": getattr(exc, "errors", [str(exc)])}
    print(json.dumps(res, allow_nan=False))


if __name__ == "__main__":
    main()

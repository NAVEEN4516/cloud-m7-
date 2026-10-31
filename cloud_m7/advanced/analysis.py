"""Run each experimental track once against the selected immutable evidence."""
from dataclasses import asdict
import json
import time

import networkx as nx

from .adversarial_shield import ProvenanceInvariantShield
from .ebpf_hpc import EbpfHpcTelemetryEngine
from .gnn_entropy import EntropyGraphPruner, TemporalGnnAnomalyScorer
from .rl_containment import AutonomousRlContainmentAgent
from .stix_stream import EventTimeStreamingEngine, StixThreatIntelGenerator
from .zk_provenance import ZkProvenanceVerifier


def analyze_advanced_tracks(graph, events, reconstructed_steps, choke_points,
                            mitre_matches, target_uuid=None):
    started = time.perf_counter()
    labelled = {event.uuid for event in events if event.payload.get('is_attack')}
    _, entropy = EntropyGraphPruner().prune_dependency_explosion(graph, labelled)
    scores = TemporalGnnAnomalyScorer().score_graph_anomalies(graph)
    _, shield = ProvenanceInvariantShield().verify_and_shield(graph, events=events)
    tier_states = {'Edge': 1, 'Fog': 2, 'Cloud': 3}
    state = max((tier_states.get(graph.nodes[node].get('tier'), 0)
                 for node in labelled), default=0)
    rl = AutonomousRlContainmentAgent().get_dashboard_summary(initial_state=state)

    # Verify graph reachability after a candidate cut, separately from any proof.
    candidate = next((cp['node_id'] for cp in choke_points
                      if cp.get('containment_efficiency_pct') == 100), None)
    cut_check = {'status': 'not_applicable', 'candidate_node': candidate,
                 'target_uuid': target_uuid, 'sources_checked': 0,
                 'sources_still_reaching_target': None, 'contained_in_graph': False}
    if candidate and target_uuid in graph:
        ancestors = nx.ancestors(graph, target_uuid) | {target_uuid}
        sources = [n for n in labelled & ancestors if graph.nodes[n].get('tier') == 'Edge'
                   and not any(p in labelled for p in graph.predecessors(n))]
        if sources:
            cut = graph.copy()
            cut.remove_node(candidate)
            remaining = sum(n in cut and target_uuid in cut and nx.has_path(cut, n, target_uuid)
                            for n in sources)
            cut_check.update(status='checked', sources_checked=len(sources),
                             sources_still_reaching_target=remaining,
                             contained_in_graph=remaining == 0)
    by_id = {event.uuid: event for event in events}
    first = by_id.get(reconstructed_steps[0]['uuid']) if reconstructed_steps else None
    last = by_id.get(target_uuid)
    verifier = ZkProvenanceVerifier()
    proof = verifier.generate_zk_proof(
        len(reconstructed_steps), first.tamper_hash if first else '',
        last.tamper_hash if last else '', cut_check['contained_in_graph'])
    export = StixThreatIntelGenerator().generate_stix_bundle(
        reconstructed_steps, candidate, mitre_matches)
    streaming = EventTimeStreamingEngine().process_events(event.to_dict() for event in events)
    result = {
        'status': 'experimental',
        'description': 'Derived analyses leave original evidence and selected-dataset SQL unchanged.',
        'track1_ebpf_hpc': EbpfHpcTelemetryEngine().get_full_telemetry_snapshot(bool(labelled)),
        'track2_gnn_entropy': {
            'mode': 'fixed_weight_heuristic', 'uses_attack_labels_for_scoring': False,
            'description': 'Label-free temporal structure scores; no trained detector or calibrated probabilities.',
            'entropy_reduction': asdict(entropy),
            'top_gnn_anomalies': [asdict(score) for score in scores[:10]],
        },
        'track3_rl_containment': rl,
        'track4_zk_provenance': {**asdict(proof), 'is_valid': verifier.verify_proof(proof),
                                 'graph_cut_check': cut_check},
        'track5_adversarial_shield': {'mode': 'partial_evidence_checks', **asdict(shield)},
        'track6_stix_streaming': {
            'mode': 'candidate_export_and_in_memory_aggregation',
            'stix_bundle': json.loads(export.stix_json_string),
            'export_status': export.validation_status,
            'trajectory_steps_exported': len(export.attack_pattern_ids),
            'streaming_metrics': asdict(streaming),
        },
    }
    result['processing_time_ms'] = round((time.perf_counter() - started) * 1000, 3)
    return result

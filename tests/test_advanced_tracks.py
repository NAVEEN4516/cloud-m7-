"""Regression coverage for the six integrated tracks and review counterexamples.

Adapted from Dharshini's track tests; adds rejection, causal preservation,
normal-only and actual event-processing checks rather than claimed speed tests.
"""
from copy import deepcopy
from dataclasses import asdict
import json
import random
import urllib.error
import urllib.request

import networkx as nx
import pytest

from cloud_m7.adapters.factory import DatasetNormalizerFactory
from cloud_m7.advanced.adversarial_shield import AdversarialCamouflageSuite, ProvenanceInvariantShield
from cloud_m7.advanced.ebpf_hpc import EbpfHpcTelemetryEngine
from cloud_m7.advanced.gnn_entropy import EntropyGraphPruner, TemporalGnnAnomalyScorer
from cloud_m7.advanced.rl_containment import AutonomousRlContainmentAgent
from cloud_m7.advanced.stix_stream import EventTimeStreamingEngine, StixThreatIntelGenerator
from cloud_m7.advanced.zk_provenance import ZkProvenanceVerifier
from cloud_m7.fusion.causal_graph import ProvenanceGraphEngine
from cloud_m7.hardware.edge_probe import generate_hardware_event
from cloud_m7.hardware.fog_receiver import FogHardwareGatewayServer
from cloud_m7.schema.event import ProvenanceEvent


def test_hardware_profiles_do_not_claim_capture_or_attestation():
    state = random.getstate()
    engine = EbpfHpcTelemetryEngine()
    for attack in (False, True):
        snapshot = engine.get_full_telemetry_snapshot(attack)
        assert snapshot['mode'] == 'simulation_only'
        assert snapshot['hardware_capture'] is False
        assert snapshot['tpm_attestation']['verified'] is False
        assert snapshot['ebpf_lsm']['is_anomaly'] == attack
    assert random.getstate() == state


def hub_graph():
    graph = nx.DiGraph()
    graph.add_nodes_from(['attack-a', 'attack-b'])
    for i in range(10):
        graph.add_edge(f'p{i}', 'hub', action='read')
    graph.add_edge('attack-a', 'p3')
    graph.add_edge('hub', 'attack-b')
    return graph


def test_entropy_does_not_sever_unlabelled_attack_intermediate():
    graph = hub_graph()
    edges = set(graph.edges)
    pruned, report = EntropyGraphPruner().prune_dependency_explosion(graph, {'attack-a', 'attack-b'})
    assert nx.has_path(pruned, 'attack-a', 'attack-b')
    assert report.attack_chain_preserved and report.reachability_preserved
    assert set(graph.edges) == edges


def test_entropy_reduces_redundant_edges_and_preserves_all_pairs():
    graph = hub_graph()
    graph.add_edges_from((f'p{i}', f'p{i+1}') for i in range(9))
    pruned, report = EntropyGraphPruner().prune_dependency_explosion(graph, {'attack-a', 'attack-b'})
    assert report.removed_edges and report.compression_ratio_pct > 0
    assert set(pruned) == set(graph)
    for source in graph:
        assert nx.descendants(graph, source) == nx.descendants(pruned, source)


def test_entropy_rejects_cycle():
    with pytest.raises(ValueError, match='DAG'):
        EntropyGraphPruner().prune_dependency_explosion(nx.DiGraph([('a', 'b'), ('b', 'a')]), set())


def test_temporal_scores_exclude_labels_and_use_actual_time():
    graph = nx.DiGraph()
    graph.add_node('a', tier='Edge', timestamp=1, is_attack=True)
    graph.add_node('b', tier='Fog', timestamp=2, is_attack=False)
    graph.add_edge('a', 'b')
    scorer = TemporalGnnAnomalyScorer()
    baseline = [asdict(s) for s in scorer.score_graph_anomalies(graph)]
    embeddings = scorer.compute_node_embeddings(graph)
    for node in graph:
        graph.nodes[node]['is_attack'] = not graph.nodes[node]['is_attack']
    assert baseline == [asdict(s) for s in scorer.score_graph_anomalies(graph)]
    graph.nodes['b']['timestamp'] = 100
    assert scorer.compute_node_embeddings(graph)['b'] != embeddings['b']
    assert all(0 <= s.anomaly_score <= 1 for s in scorer.score_graph_anomalies(graph))


@pytest.mark.parametrize('options', [{'embedding_dim': 3}, {'time_decay_tau': 0}, {'time_decay_tau': float('nan')}])
def test_temporal_scorer_invalid_configuration(options):
    with pytest.raises(ValueError):
        TemporalGnnAnomalyScorer(**options)


def test_rl_normal_state_and_observed_action_shares():
    state = random.getstate()
    zero = AutonomousRlContainmentAgent().train_agent(0)
    agent = AutonomousRlContainmentAgent()
    result = agent.get_dashboard_summary(initial_state=0)
    assert result['enforcement_executed'] is False
    assert result['initial_state'] == 'S0: NOMINAL_BENIGN'
    assert len(result['simulation_trajectory']) == 1
    assert result['simulation_trajectory'][0]['action'].startswith('NOOP')
    assert result['optimal_policy']['S1: EDGE_SENSOR_INTRUSION'].startswith('FREEZE_CGROUP_PID')
    assert sum(result['action_distribution'].values()) == pytest.approx(1)
    assert zero.action_distribution != result['action_distribution']
    assert random.getstate() == state
    repeated = AutonomousRlContainmentAgent().get_dashboard_summary(initial_state=0)
    assert repeated == result


def test_zk_fails_closed_even_with_corrupted_proof_and_true_flags():
    verifier = ZkProvenanceVerifier()
    proof = verifier.generate_zk_proof(14, 'root', 'target', True)
    assert proof.status == 'simulation_only' and not verifier.verify_proof(proof)
    assert proof.verification_time_ms is None and proof.num_constraints == 0
    proof.is_valid = True
    proof.public_inputs['containment_proven'] = '1'
    proof.public_inputs['path_hop_depth'] = '-999'
    proof.proof_pi_a = ['garbage']; proof.proof_pi_b = []; proof.proof_pi_c = []
    assert not verifier.verify_proof(proof)


def graph_for(events):
    engine = ProvenanceGraphEngine()
    engine.add_events(events)
    return engine.fuse_global_graph()


def test_shield_checks_timestamps_and_hashes_without_mutating_evidence():
    events = [ProvenanceEvent(uuid='a', timestamp=1),
              ProvenanceEvent(uuid='b', timestamp=2, parents=['a'])]
    graph = deepcopy(graph_for(events))
    graph.nodes['b']['timestamp'] = 0
    clean, report = ProvenanceInvariantShield().verify_and_shield(graph, events)
    assert graph.has_edge('a', 'b') and not clean.has_edge('a', 'b')
    assert report.temporal_inversions_neutralized == 1
    assert any(c['name'] == 'Canonical event digest' and c['failed'] == 1 for c in report.checks)
    assert not report.coverage_complete and report.graph_integrity_score_pct is None
    assert events[1].timestamp == 2


def test_shield_detects_socket_mismatch_without_injector_markers():
    payload = dict(src_ip='10.0.0.1', src_port=1000, dst_ip='10.0.0.2', dst_port=443, protocol='TCP')
    events = [ProvenanceEvent(uuid='a', timestamp=1, tier='Edge', event_type='Socket', payload=dict(payload, action='connect')),
              ProvenanceEvent(uuid='b', timestamp=2, tier='Fog', event_type='Socket', payload=dict(payload, action='accept', protocol='UDP'))]
    graph = graph_for(events)
    graph.add_edge('a', 'b', relation='cross_tier_network_flow')
    clean, report = ProvenanceInvariantShield().verify_and_shield(graph, events)
    assert report.forged_cross_tier_flows_dropped == 1
    assert not clean.has_edge('a', 'b') and graph.has_edge('a', 'b')


def test_shield_reports_missing_evidence_and_only_removes_marked_test_noise():
    graph = nx.DiGraph([('a', 'b')])
    injected, _ = AdversarialCamouflageSuite.inject_graph_inflation(graph, 10)
    clean, report = ProvenanceInvariantShield().verify_and_shield(injected)
    assert set(clean) == set(graph) and len(injected) == 12
    assert report.synthetic_inflation_nodes_pruned == 10
    assert report.graph_integrity_score_pct is None and not report.coverage_complete


def test_stix_exports_full_trajectory_relationships_and_mitre_evidence():
    steps = [{'uuid': f'event-{i}', 'tier': 'Edge', 'action': 'exec', 'host_id': 'fixture'} for i in range(14)]
    result = StixThreatIntelGenerator().generate_stix_bundle(steps, 'candidate',
        [{'evidence_uuid': 'event-13', 'technique_id': 'T1059'}])
    bundle = json.loads(result.stix_json_string)
    patterns = [o for o in bundle['objects'] if o['type'] == 'attack-pattern']
    assert len(patterns) == 14
    assert patterns[-1]['external_references'][0]['external_id'] == 'T1059'
    assert StixThreatIntelGenerator.validate_bundle_structure(bundle)
    relation = next(o for o in bundle['objects'] if o['type'] == 'relationship')
    relation['target_ref'] = 'attack-pattern--missing'
    with pytest.raises(ValueError, match='Dangling'):
        StixThreatIntelGenerator.validate_bundle_structure(bundle)


def test_stix_does_not_invent_an_incident_for_normal_input():
    bundle = json.loads(StixThreatIntelGenerator().generate_stix_bundle([]).stix_json_string)
    assert bundle['objects'] == []


def test_stream_consumes_actual_events_and_drops_out_of_order_late_records():
    received = []
    def events():
        for timestamp in [10, 12, 9, 7, 22]:
            received.append(timestamp)
            yield {'timestamp': timestamp}
    report = EventTimeStreamingEngine().process_events(events())
    assert len(received) == report.events_received == 5
    assert report.events_ingested == 4 and report.dropped_late_events == 1
    assert sum(report.window_counts.values()) == 4 and report.windows_processed == 3
    assert report.watermark_timestamp == 19 and report.watermark_delay_ms == 3000
    assert report.processing_time_ms >= 0


@pytest.mark.parametrize('count', [0, 25_000])
def test_stream_benchmark_counts_work_without_arbitrary_speed_threshold(count):
    report = EventTimeStreamingEngine().benchmark_stream_ingestion(count)
    assert report.events_received == report.events_ingested == count
    assert sum(report.window_counts.values()) == count


def test_hardware_native_round_trip_and_tamper_rejection():
    record = generate_hardware_event('File', 'write', '/var/log/sensor', host_id='probe')
    parsed, _ = DatasetNormalizerFactory().normalize(json.dumps([record]))
    assert parsed[0].compute_integrity_hash() == record['tamper_hash']
    record['payload']['entity'] = '/changed'
    with pytest.raises(ValueError, match='hash'):
        DatasetNormalizerFactory().normalize(json.dumps([record]))


def test_fog_gateway_accepts_canonical_probe_and_rejects_changed_payload():
    server = FogHardwareGatewayServer(host='127.0.0.1', port=0)
    server.clear_buffer()
    server.start_background()
    try:
        url = f'http://127.0.0.1:{server.server.server_port}/telemetry'
        record = generate_hardware_event('File', 'write', '/var/log/sensor', host_id='probe')
        def request():
            return urllib.request.Request(url, data=json.dumps(record).encode(),
                                          headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request(), timeout=3) as response:
            assert response.status == 200
        record['payload']['entity'] = '/changed'
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(), timeout=3)
        assert error.value.code == 400 and len(server.get_buffered_events()) == 1
    finally:
        server.stop()
        server.clear_buffer()


@pytest.mark.parametrize('name,count,state', [('normal', 16, 0), ('attack', 70, 3), ('repeated', 92, 3)])
def test_selected_dataset_advanced_contract(tmp_path, monkeypatch, name, count, state):
    import cloud_m7.bridge_api as api
    monkeypatch.setattr(api, 'ROOT_DIR', tmp_path)
    result = api.analyze_dataset(name)
    tracks = result['advanced_tracks']
    assert len([key for key in tracks if key.startswith('track')]) == 6
    stream = tracks['track6_stix_streaming']['streaming_metrics']
    assert stream['events_received'] == stream['events_ingested'] == count
    assert tracks['track3_rl_containment']['initial_state'].startswith(f'S{state}:')
    proof = tracks['track4_zk_provenance']
    assert proof['is_valid'] is False
    assert result['processing_time_ms'] >= tracks['processing_time_ms']
    assert tracks['track5_adversarial_shield']['graph_integrity_score_pct'] is None
    assert api.execute_sql('SELECT COUNT(*) AS n FROM provenance', result['dataset_id'])['rows'] == [{'n': count}]
    if name == 'normal':
        assert tracks['track6_stix_streaming']['stix_bundle']['objects'] == []
        assert proof['graph_cut_check']['status'] == 'not_applicable'
    else:
        assert proof['graph_cut_check']['sources_checked'] == 3
        assert proof['graph_cut_check']['contained_in_graph'] is True

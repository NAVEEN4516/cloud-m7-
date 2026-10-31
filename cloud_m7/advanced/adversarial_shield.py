"""Evidence checks and an isolated shield view; original evidence is untouched.

Adapted from DharshiniPES/cloud-m7 (23ba5ed). Missing evidence is reported as
unavailable. The checks do not establish authenticity or adversarial robustness.
"""
import math
from dataclasses import dataclass
from typing import List

import networkx as nx


@dataclass
class AdversarialAttackReport:
    attack_type: str
    injected_noise_count: int
    skew_delta_seconds: float
    target_tier: str
    evasion_intent: str


@dataclass
class InvariantShieldVerification:
    temporal_inversions_neutralized: int
    synthetic_inflation_nodes_pruned: int
    forged_cross_tier_flows_dropped: int
    graph_integrity_score_pct: float | None
    invariants_verified: List[str]
    checks: list
    findings: list
    coverage_complete: bool


class AdversarialCamouflageSuite:
    """Explicitly labelled perturbations for testing; not a real evasion model."""
    @staticmethod
    def inject_graph_inflation(graph, dummy_count=25):
        if dummy_count < 0:
            raise ValueError('dummy_count must be nonnegative')
        tampered = graph.copy()
        for i in range(dummy_count):
            name = f'dummy_fork_process_{i}'
            while name in tampered:
                name += '_'
            tampered.add_node(name, tier='Edge', is_synthetic_noise=True,
                              event_type='Process', action='simulated_fork')
            if graph:
                tampered.add_edge(next(iter(graph)), name, is_synthetic_noise=True)
        return tampered, AdversarialAttackReport(
            'SIMULATED_GRAPH_INFLATION', dummy_count, 0.0, 'Edge',
            'Explicitly marked test nodes; does not model unmarked malicious noise')

    @staticmethod
    def inject_timestamp_skewing(graph, skew_seconds=-45.0):
        tampered = graph.copy()
        affected = 0
        for node, data in tampered.nodes(data=True):
            if data.get('tier') == 'Fog' and 'timestamp' in data:
                data['timestamp'] += skew_seconds
                affected += 1
        return tampered, AdversarialAttackReport(
            'SIMULATED_CLOCK_SKEW', affected, skew_seconds, 'Fog',
            'Change actual node timestamps in a derived test graph')


class ProvenanceInvariantShield:
    INVARIANTS = ['Temporal order', 'Socket five-tuple', 'Canonical event digest',
                  'Process lineage']

    def verify_and_shield(self, graph: nx.DiGraph, events=None):
        clean = graph.copy()
        findings = []
        noise = [n for n, d in graph.nodes(data=True) if d.get('is_synthetic_noise')]
        clean.remove_nodes_from(noise)
        counts = {name: {'checked': 0, 'failed': 0, 'unavailable': 0}
                  for name in self.INVARIANTS}
        invalid_time, invalid_flows = set(), set()
        for u, v, attrs in graph.edges(data=True):
            if u in noise or v in noise:
                continue
            temporal = counts['Temporal order']
            before = graph.nodes[u].get('timestamp')
            after = graph.nodes[v].get('timestamp')
            if before is None or after is None:
                temporal['unavailable'] += 1
            else:
                temporal['checked'] += 1
                if not math.isfinite(before) or not math.isfinite(after) or after < before:
                    temporal['failed'] += 1
                    invalid_time.add((u, v))
                    findings.append({'check': 'Temporal order', 'edge': [u, v],
                                     'reason': 'Invalid or reversed event timestamps'})
            if attrs.get('relation') != 'cross_tier_network_flow':
                continue
            network = counts['Socket five-tuple']
            required = ('src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol')
            payloads = [graph.nodes[n].get('payload', {}) for n in (u, v)]
            if not all(all(key in p for key in required) for p in payloads):
                network['unavailable'] += 1
                continue
            network['checked'] += 1
            try:
                def socket_tuple(payload):
                    return (payload['src_ip'], int(payload['src_port']),
                            payload['dst_ip'], int(payload['dst_port']),
                            str(payload['protocol']).upper())
                tuples = [socket_tuple(p) for p in payloads]
                directions = (payloads[0].get('action') in ('connect', 'send', 'outbound')
                              and payloads[1].get('action') in ('accept', 'receive', 'inbound', 'recv'))
                valid = tuples[0] == tuples[1] and directions and all(
                    t[0] and t[2] and 1 <= t[1] <= 65535 and 1 <= t[3] <= 65535
                    for t in tuples) and graph.nodes[u].get('tier') != graph.nodes[v].get('tier')
            except (ValueError, TypeError):
                valid = False
            if not valid:
                network['failed'] += 1
                invalid_flows.add((u, v))
                findings.append({'check': 'Socket five-tuple', 'edge': [u, v],
                                 'reason': 'Socket tuple, direction or tier mismatch'})
        clean.remove_edges_from(invalid_time | invalid_flows)
        evidence = {event.uuid: event for event in events} if events is not None else {}
        hashes = counts['Canonical event digest']
        for node in graph:
            if node in noise:
                continue
            event = evidence.get(node)
            if event is None or not event.tamper_hash:
                hashes['unavailable'] += 1
                continue
            hashes['checked'] += 1
            # Compare the supplied record and the view actually being inspected.
            data = graph.nodes[node]
            expected = event.to_dict()
            valid = (event.tamper_hash == event.compute_integrity_hash()
                     and all(data.get(key) == expected[key] for key in
                             ('timestamp', 'tier', 'host_id', 'event_type', 'payload')))
            if not valid:
                hashes['failed'] += 1
                findings.append({'check': 'Canonical event digest', 'node': node,
                                 'reason': 'Digest or graph/evidence contents disagree'})
        # A PID/parent-PID correlation model is not implemented in this prototype.
        counts['Process lineage']['unavailable'] = len(graph)
        checks = []
        for name, values in counts.items():
            status = ('failed' if values['failed'] else 'incomplete' if values['unavailable']
                      else 'passed' if values['checked'] else 'not_applicable')
            checks.append({'name': name, 'status': status, **values})
        complete = not any(c['unavailable'] for c in checks)
        checked = sum(c['checked'] for c in checks)
        failed = sum(c['failed'] for c in checks)
        score = round(100 * (checked - failed) / checked, 2) if complete and checked else None
        return clean, InvariantShieldVerification(
            len(invalid_time), len(noise), len(invalid_flows), score,
            [c['name'] for c in checks if c['status'] == 'passed'],
            checks, findings, complete)

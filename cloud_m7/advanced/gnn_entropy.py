"""Experimental entropy reduction and label-free temporal graph scoring.

Adapted from DharshiniPES/cloud-m7, commit 23ba5ed. The scorer uses fixed
message-passing weights, not a trained neural network or calibrated detector.
"""
import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

import networkx as nx


@dataclass
class EntropyReductionResult:
    original_nodes: int
    original_edges: int
    pruned_nodes: int
    pruned_edges: int
    compression_ratio_pct: float
    information_entropy_bits: float
    attack_chain_preserved: bool
    reachability_preserved: bool
    removed_edges: List[Tuple[str, str]]


@dataclass
class GnnNodeAnomalyScore:
    node_id: str
    tier: str
    host_id: str
    anomaly_score: float
    embedding_norm: float
    is_topological_outlier: bool
    cluster_label: int


class EntropyGraphPruner:
    """Remove only repetitive edges with a surviving alternate causal path.

    All nodes and original evidence remain intact. Entropy proposes candidates;
    reachability decides whether each edge can be removed from a derived view.
    """
    def __init__(self, entropy_threshold: float = 0.45):
        if not math.isfinite(entropy_threshold) or entropy_threshold < 0:
            raise ValueError('entropy_threshold must be finite and nonnegative')
        self.entropy_threshold = entropy_threshold

    def calculate_action_entropy(self, actions: List[str]) -> float:
        total = len(actions)
        return round(-sum((n / total) * math.log2(n / total)
                          for n in Counter(actions).values()), 3) if total else 0.0

    @staticmethod
    def _edge_action(graph, source, target):
        return str(graph.edges[source, target].get('action')
                   or graph.nodes[source].get('action')
                   or graph.edges[source, target].get('relation', 'dependency'))

    def prune_dependency_explosion(self, graph: nx.DiGraph, attack_nodes: Set[str]):
        if not nx.is_directed_acyclic_graph(graph):
            raise ValueError('Entropy reduction requires a causal DAG')
        if not set(attack_nodes).issubset(graph):
            raise ValueError('Protected attack nodes must exist in the graph')
        pruned = graph.copy()
        removed = []
        for node in sorted(graph, key=str):
            if node in attack_nodes or graph.in_degree(node) <= 8:
                continue
            predecessors = sorted(graph.predecessors(node), key=str)
            actions = [self._edge_action(graph, u, node)
                       for u in predecessors]
            if self.calculate_action_entropy(actions) >= self.entropy_threshold:
                continue
            for parent in predecessors[2:]:
                if parent in attack_nodes:
                    continue
                attrs = dict(pruned.edges[parent, node])
                pruned.remove_edge(parent, node)
                if nx.has_path(pruned, parent, node):
                    removed.append((parent, node))
                else:
                    pruned.add_edge(parent, node, **attrs)
        # Each original edge survives or has a path in the final derived graph.
        # Identical nodes and no new edges then imply identical reachability.
        preserved = set(graph) == set(pruned) and all(
            nx.has_path(pruned, u, v) for u, v in removed)
        if not preserved:
            raise RuntimeError('Reduction did not preserve causal reachability')
        edge_count = graph.number_of_edges()
        report = EntropyReductionResult(
            len(graph), edge_count, len(pruned), pruned.number_of_edges(),
            round(100 * len(removed) / max(edge_count, 1), 2),
            self.calculate_action_entropy([self._edge_action(graph, u, v)
                                           for u, v in graph.edges]),
            preserved, preserved, removed,
        )
        return pruned, report


class TemporalGnnAnomalyScorer:
    """Fixed-weight temporal message-passing heuristic; labels are excluded.

    The historical class name is retained for teammate compatibility. Scores
    describe structure, not a learned probability of attack.
    """
    def __init__(self, embedding_dim: int = 16, time_decay_tau: float = 10.0):
        if embedding_dim < 4 or not math.isfinite(time_decay_tau) or time_decay_tau <= 0:
            raise ValueError('embedding_dim >= 4 and finite time_decay_tau > 0 required')
        self.embedding_dim = embedding_dim
        self.time_decay_tau = time_decay_tau

    def compute_node_embeddings(self, graph: nx.DiGraph) -> Dict[str, List[float]]:
        tiers = {'Edge': 0.25, 'Fog': 0.50, 'Cloud': 0.85}
        embeddings = {
            n: [tiers.get(d.get('tier'), 0.3), math.log1p(graph.in_degree(n)),
                math.log1p(graph.out_degree(n)),
                float(any(graph.nodes[u].get('tier') != d.get('tier')
                          for u in graph.predecessors(n)))]
               + [0.0] * (self.embedding_dim - 4)
            for n, d in graph.nodes(data=True)
        }
        for _ in range(2):
            updated = {}
            for n, data in graph.nodes(data=True):
                neighbors = [0.0] * self.embedding_dim
                for parent in graph.predecessors(n):
                    parent_time = graph.nodes[parent].get('timestamp')
                    child_time = data.get('timestamp')
                    if parent_time is None or child_time is None:
                        continue
                    delta = float(child_time) - float(parent_time)
                    if not math.isfinite(delta) or delta < 0:
                        continue
                    decay = math.exp(-delta / self.time_decay_tau)
                    for index, value in enumerate(embeddings[parent]):
                        neighbors[index] += value * decay
                scale = 1 / math.sqrt(max(graph.in_degree(n), 1))
                updated[n] = [max(0.0, 0.6 * value + 0.4 * neighbors[i] * scale)
                              for i, value in enumerate(embeddings[n])]
            embeddings = updated
        return embeddings

    def score_graph_anomalies(self, graph: nx.DiGraph) -> List[GnnNodeAnomalyScore]:
        embeddings = self.compute_node_embeddings(graph)
        scores = []
        for node, data in graph.nodes(data=True):
            norm = math.sqrt(sum(value * value for value in embeddings[node]))
            score = round(1 - math.exp(-norm / 4), 4)
            scores.append(GnnNodeAnomalyScore(
                node, data.get('tier', ''), data.get('host_id', ''), score,
                round(norm, 4), score >= 0.7, int(score >= 0.7)))
        return sorted(scores, key=lambda item: (-item.anomaly_score, str(item.node_id)))

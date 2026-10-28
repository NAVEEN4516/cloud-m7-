"""
Iterative Multi-Root Causal Forensic Discovery Engine (CLOUD-M7 Novelty).

Solves the single-path limitation of traditional forensic provenance.
In real-world APTs, adversaries exploit multiple entry points or deploy redundant
persistence mechanisms. This engine runs an iterative risk-guided causal loop
with configurable hyperparameters to discover all concurrent attack vectors,
comparing marginal impact gains across iterations until convergence.

Mathematical Formulation:
    - Hyperparameters:
        * K_max (max_iterations): Maximum search rounds (e.g. 3-10)
        * epsilon (impact_threshold): Convergence threshold on marginal impact gain (%)
        * lambda_decay (causal_attenuation): Hop distance decay factor in (0, 1]
    - Iteration k:
        * Identifies entry point R_k and associated attack trajectory P_k
        * Computes cumulative impact I_k = Sum_{v in V_k} w(v) * lambda^{dist(v, alert)}
        * Evaluates Delta I_k = (I_k - I_{k-1}) / I_{k-1}
        * Terminates if Delta I_k < epsilon or k == K_max
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from cloud_m7.fusion.causal_graph import ProvenanceGraphEngine
from cloud_m7.schema.types import EventType, TierType


@dataclass
class DiscoveredAttackVector:
    """Represents an attack vector discovered during an iteration."""
    iteration: int
    vector_id: str
    entry_point_uuid: str
    entry_tier: str
    entry_host: str
    entry_entity: str
    target_impact_uuid: str
    path_nodes: List[str]
    path_length: int
    vector_impact_score: float
    description: str


@dataclass
class IterationMetrics:
    """Metrics tracking impact gain and convergence for each iteration."""
    iteration: int
    new_nodes_discovered: int
    total_discovered_nodes: int
    cumulative_impact_score: float
    marginal_impact_gain_pct: float
    converged: bool
    reason: str


@dataclass
class IterativeDiscoveryResult:
    """Overall outcome of the iterative causal discovery process."""
    total_iterations_run: int
    max_iterations_hyperparameter: int
    impact_threshold_epsilon: float
    converged: bool
    convergence_reason: str
    discovered_vectors: List[DiscoveredAttackVector]
    iteration_history: List[IterationMetrics]
    all_attack_nodes: Set[str]
    all_attack_edges: Set[Tuple[str, str]]
    total_impact_score: float


class IterativeAttackDiscoveryEngine:
    """
    Iterative causal traversal engine that dynamically detects all concurrent
    attack entry points and lateral pathways across Edge, Fog, and Cloud tiers.
    """

    # Criticality weights for events based on action / payload severity
    ACTION_WEIGHTS = {
        "exfil_data": 10.0,
        "query_db": 8.0,
        "auth_login": 7.0,
        "write": 5.0,
        "exec": 6.0,
        "fork": 4.0,
        "read": 5.0,
        "connect": 4.0,
        "accept": 4.0,
        "send": 2.0,
    }

    def __init__(
        self,
        engine: ProvenanceGraphEngine,
        max_iterations: int = 5,
        impact_threshold_epsilon: float = 5.0,  # 5% marginal impact threshold
        causal_attenuation: float = 0.90,       # 10% attenuation per hop
    ):
        self.engine = engine
        self.graph = engine.global_graph
        self.max_iterations = max_iterations
        self.epsilon = impact_threshold_epsilon
        self.lambda_decay = causal_attenuation

    def _compute_node_weight(self, node_id: str) -> float:
        """Assigns an intrinsic risk weight based on node properties."""
        data = self.graph.nodes[node_id]
        action = data.get("action", "")
        base_w = self.ACTION_WEIGHTS.get(action, 2.0)
        
        # Attack events have multiplier
        if data.get("is_attack", False):
            base_w *= 2.0
            
        # Tier multiplier (Cloud data breach is high impact, Edge exploit is high severity entry)
        tier = data.get("tier", "")
        if tier == "Cloud":
            base_w *= 1.5
        elif tier == "Edge":
            base_w *= 1.2

        return round(base_w, 2)

    def _calculate_subgraph_impact(self, node_set: Set[str], alert_node: str) -> float:
        """
        Computes weighted impact score with causal attenuation distance from target alert.
        """
        total_impact = 0.0
        for node in node_set:
            w = self._compute_node_weight(node)
            try:
                # Hop distance to alert node
                dist = nx.shortest_path_length(self.graph, source=node, target=alert_node)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                dist = 1
            attenuation = (self.lambda_decay ** dist)
            total_impact += w * attenuation
        return round(total_impact, 2)

    def discover_all_attack_points(
        self,
        primary_alert_uuid: Optional[str] = None,
    ) -> IterativeDiscoveryResult:
        """
        Executes the iterative discovery loop across Edge, Fog, and Cloud.
        """
        if self.graph.number_of_nodes() == 0:
            self.graph = self.engine.fuse_global_graph()

        # Step 1: Identify target alert event in Cloud
        if primary_alert_uuid is None:
            candidates = [
                n for n, d in self.graph.nodes(data=True)
                if d.get("is_attack") and d.get("tier") == "Cloud"
            ]
            if not candidates:
                candidates = [n for n, d in self.graph.nodes(data=True) if d.get("is_attack")]
            if not candidates:
                # No attack nodes present
                return IterativeDiscoveryResult(
                    total_iterations_run=0,
                    max_iterations_hyperparameter=self.max_iterations,
                    impact_threshold_epsilon=self.epsilon,
                    converged=True,
                    convergence_reason="No attack alerts detected",
                    discovered_vectors=[],
                    iteration_history=[],
                    all_attack_nodes=set(),
                    all_attack_edges=set(),
                    total_impact_score=0.0,
                )
            # Pick latest event
            primary_alert_uuid = max(
                candidates, key=lambda n: self.graph.nodes[n].get("timestamp", 0)
            )

        discovered_nodes_cumulative: Set[str] = set()
        discovered_edges_cumulative: Set[Tuple[str, str]] = set()
        discovered_vectors: List[DiscoveredAttackVector] = []
        iteration_history: List[IterationMetrics] = []
        
        previous_impact = 0.0
        converged = False
        convergence_reason = f"Reached max_iterations limit ({self.max_iterations})"

        # Track already discovered roots so we search for alternative entry points
        visited_roots: Set[str] = set()

        for k in range(1, self.max_iterations + 1):
            # 1. Identify candidate roots for this iteration
            # Full ancestral causal cone of the alert
            all_ancestors = nx.ancestors(self.graph, primary_alert_uuid)
            all_ancestors.add(primary_alert_uuid)

            # Filter out roots already attributed to an existing vector
            unvisited_ancestors = all_ancestors - visited_roots

            # Candidate entry points: nodes in causal cone with no attack parents or in-degree 0
            candidate_roots = []
            for n in unvisited_ancestors:
                data = self.graph.nodes[n]
                # Check if it is an attack entry point or initial trigger
                if data.get("is_attack"):
                    # Check in-degree within the attack subgraph
                    preds = [p for p in self.graph.predecessors(n) if self.graph.nodes[p].get("is_attack")]
                    if len(preds) == 0:
                        candidate_roots.append(n)

            if not candidate_roots:
                converged = True
                convergence_reason = f"No further unvisited causal entry vectors remaining (Iteration {k})"
                iteration_history.append(
                    IterationMetrics(
                        iteration=k,
                        new_nodes_discovered=0,
                        total_discovered_nodes=len(discovered_nodes_cumulative),
                        cumulative_impact_score=previous_impact,
                        marginal_impact_gain_pct=0.0,
                        converged=True,
                        reason=convergence_reason,
                    )
                )
                break

            # Pick best candidate root (earliest timestamp or most distinctive path)
            chosen_root = min(
                candidate_roots,
                key=lambda n: self.graph.nodes[n].get("timestamp", float("inf"))
            )
            visited_roots.add(chosen_root)

            # 2. Extract path from this root to target alert
            try:
                path = nx.shortest_path(self.graph, source=chosen_root, target=primary_alert_uuid)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                # If no direct path to primary alert, connect to any discovered node
                path = [chosen_root]
                for disc in discovered_nodes_cumulative:
                    if nx.has_path(self.graph, chosen_root, disc):
                        path = nx.shortest_path(self.graph, chosen_root, disc)
                        break

            # Add path edges
            vector_edges = set()
            for i in range(len(path) - 1):
                edge = (path[i], path[i + 1])
                vector_edges.add(edge)
                discovered_edges_cumulative.add(edge)

            # Calculate impact of this new vector
            new_nodes = set(path) - discovered_nodes_cumulative
            discovered_nodes_cumulative.update(path)

            current_impact = self._calculate_subgraph_impact(
                discovered_nodes_cumulative, primary_alert_uuid
            )

            # 3. Calculate Marginal Impact Gain Delta I_k (%)
            if previous_impact == 0.0:
                marginal_gain_pct = 100.0  # Initial baseline
            else:
                marginal_gain_pct = round(
                    ((current_impact - previous_impact) / previous_impact) * 100.0, 2
                )

            # Metadata for this discovered vector
            root_data = self.graph.nodes[chosen_root]
            vector_obj = DiscoveredAttackVector(
                iteration=k,
                vector_id=f"Vector-{k:02d} ({'Primary' if k == 1 else 'Secondary/Concurrent'})",
                entry_point_uuid=chosen_root,
                entry_tier=root_data.get("tier", "Unknown"),
                entry_host=root_data.get("host_id", "Unknown"),
                entry_entity=root_data.get("entity", root_data.get("action", "Unknown")),
                target_impact_uuid=primary_alert_uuid,
                path_nodes=path,
                path_length=len(path),
                vector_impact_score=round(current_impact - previous_impact, 2) if previous_impact > 0 else current_impact,
                description=root_data.get("payload", {}).get(
                    "description", f"Entry via {root_data.get('action')} on {root_data.get('tier')}"
                ),
            )
            discovered_vectors.append(vector_obj)

            # Check convergence condition: Marginal gain < epsilon
            is_marginal_low = (k > 1 and marginal_gain_pct < self.epsilon)
            
            if is_marginal_low:
                converged = True
                convergence_reason = (
                    f"Marginal impact gain ({marginal_gain_pct}%) fell below threshold "
                    f"epsilon={self.epsilon}%"
                )

            iter_metric = IterationMetrics(
                iteration=k,
                new_nodes_discovered=len(new_nodes),
                total_discovered_nodes=len(discovered_nodes_cumulative),
                cumulative_impact_score=current_impact,
                marginal_impact_gain_pct=marginal_gain_pct,
                converged=converged,
                reason=convergence_reason if converged else "Significant impact expansion found, continuing loop",
            )
            iteration_history.append(iter_metric)

            previous_impact = current_impact

            if converged:
                break

        return IterativeDiscoveryResult(
            total_iterations_run=len(iteration_history),
            max_iterations_hyperparameter=self.max_iterations,
            impact_threshold_epsilon=self.epsilon,
            converged=converged,
            convergence_reason=convergence_reason,
            discovered_vectors=discovered_vectors,
            iteration_history=iteration_history,
            all_attack_nodes=discovered_nodes_cumulative,
            all_attack_edges=discovered_edges_cumulative,
            total_impact_score=previous_impact,
        )

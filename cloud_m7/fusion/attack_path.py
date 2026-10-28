"""
Attack Path Reconstruction and Causal Traversal Engine.

Performs backward and forward causal graph traversal on G_global to isolate
the minimal multi-hop attack path from initial entry to target impact.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from cloud_m7.fusion.causal_graph import ProvenanceGraphEngine
from cloud_m7.schema.event import ProvenanceEvent


@dataclass
class ReconstructedStep:
    """Represents an atomic stage along the attack path."""
    order: int
    uuid: str
    tier: str
    host_id: str
    timestamp: float
    event_type: str
    action: str
    entity: str
    description: str


@dataclass
class AttackPathResult:
    """Full forensic reconstruction result."""
    source_root_uuid: str
    target_impact_uuid: str
    path_length: int
    traversed_tiers: List[str]
    attack_steps: List[ReconstructedStep]
    subgraph_nodes_count: int
    reduction_percentage: float  # Percentage of noise nodes pruned out


class AttackPathReconstructor:
    """
    Traverses the unified provenance DAG to isolate multi-tier attack paths.
    """

    def __init__(self, engine: ProvenanceGraphEngine):
        self.engine = engine
        self.graph = engine.global_graph

    def backward_trace(self, target_uuid: str) -> Set[str]:
        """
        Backward causal traversal: identifies all causal predecessors / ancestors
        that influenced the target event.
        """
        if not self.graph.has_node(target_uuid):
            return set()
        ancestors = nx.ancestors(self.graph, target_uuid)
        ancestors.add(target_uuid)
        return ancestors

    def forward_trace(self, root_uuid: str) -> Set[str]:
        """
        Forward causal traversal: determines blast radius and all downstream entities
        impacted by the root compromise.
        """
        if not self.graph.has_node(root_uuid):
            return set()
        descendants = nx.descendants(self.graph, root_uuid)
        descendants.add(root_uuid)
        return descendants

    def reconstruct_attack_path(
        self,
        root_uuid: Optional[str] = None,
        target_uuid: Optional[str] = None,
    ) -> Optional[AttackPathResult]:
        """
        Isolates the minimal causal chain from root entry to target impact.
        If root_uuid or target_uuid are not provided, automatically discovers
        them from marked attack alerts or in-degree / out-degree endpoints.
        """
        # Ensure graph is fused
        if self.graph.number_of_nodes() == 0:
            self.graph = self.engine.fuse_global_graph()

        # Find target if not specified
        if target_uuid is None:
            # Look for cloud exfiltration or highest timestamp attack event
            candidates = [
                n for n, d in self.graph.nodes(data=True)
                if d.get("is_attack") and d.get("tier") == "Cloud"
            ]
            if not candidates:
                candidates = [
                    n for n, d in self.graph.nodes(data=True) if d.get("is_attack")
                ]
            if not candidates:
                return None
            target_uuid = max(
                candidates, key=lambda n: self.graph.nodes[n].get("timestamp", 0)
            )

        if target_uuid not in self.graph or (root_uuid is not None and root_uuid not in self.graph):
            return None

        # Backward trace from target
        causal_ancestors = self.backward_trace(target_uuid)

        # Find root if not specified
        if root_uuid is None:
            # Look for Edge compromise with in-degree 0 in the attack subgraph
            attack_sub = self.graph.subgraph(causal_ancestors)
            roots = [
                n for n in attack_sub.nodes()
                if attack_sub.in_degree(n) == 0 and attack_sub.nodes[n].get("is_attack")
            ]
            if not roots:
                roots = list(attack_sub.nodes())
            # Select earliest timestamp
            root_uuid = min(
                roots, key=lambda n: self.graph.nodes[n].get("timestamp", float("inf"))
            )

        # Find shortest causal path from root to target
        try:
            path_nodes = nx.shortest_path(self.graph, source=root_uuid, target=target_uuid)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

        steps: List[ReconstructedStep] = []
        traversed_tiers: List[str] = []

        for idx, node_id in enumerate(path_nodes, 1):
            data = self.graph.nodes[node_id]
            tier = data.get("tier", "Unknown")
            if tier not in traversed_tiers:
                traversed_tiers.append(tier)

            event = self.engine.events_by_id.get(node_id)
            payload = event.payload if event else data.get("payload", {})
            action = payload.get("action", data.get("action", "activity"))
            entity = payload.get("entity", data.get("entity", "unknown"))
            desc = payload.get(
                "description",
                f"[{tier}] {data.get('event_type')}: {action} on {entity}",
            )

            steps.append(
                ReconstructedStep(
                    order=idx,
                    uuid=node_id,
                    tier=tier,
                    host_id=data.get("host_id", ""),
                    timestamp=data.get("timestamp", 0.0),
                    event_type=data.get("event_type", ""),
                    action=action,
                    entity=entity,
                    description=desc,
                )
            )

        total_nodes = self.graph.number_of_nodes()
        attack_nodes_count = len(path_nodes)
        noise_reduction = 0.0
        if total_nodes > 0:
            noise_reduction = round((1.0 - (attack_nodes_count / total_nodes)) * 100.0, 2)

        return AttackPathResult(
            source_root_uuid=root_uuid,
            target_impact_uuid=target_uuid,
            path_length=len(path_nodes),
            traversed_tiers=traversed_tiers,
            attack_steps=steps,
            subgraph_nodes_count=attack_nodes_count,
            reduction_percentage=noise_reduction,
        )

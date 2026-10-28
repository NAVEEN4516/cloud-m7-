"""
Cross-Tier Causal Provenance Fusion Engine for CLOUD-M7.

Mathematical Specification (Equation 3):
    G_global = G_edge U G_fog U G_cloud U E_network

Where:
    - G_tier = (V_tier, E_tier) is the intra-tier provenance subgraph
    - E_network = {(u, v) : u in V_lower, v in V_upper,
                   correlates outbound socket flow u with inbound event v}
"""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from cloud_m7.schema.event import ProvenanceEvent
from cloud_m7.schema.types import EventType, TierType


class ProvenanceGraphEngine:
    """
    Constructs and stitches multi-tier provenance subgraphs into a unified causal DAG.
    """

    def __init__(self, time_window_seconds: float = 30.0):
        # Time tolerance window for network socket correlation
        self.time_window = time_window_seconds

        # Subgraphs per tier
        self.subgraphs: Dict[TierType, nx.DiGraph] = {
            TierType.EDGE: nx.DiGraph(),
            TierType.FOG: nx.DiGraph(),
            TierType.CLOUD: nx.DiGraph(),
        }

        # Global unified causal DAG
        self.global_graph: nx.DiGraph = nx.DiGraph()

        # Inverted index for fast lookup: UUID -> ProvenanceEvent
        self.events_by_id: Dict[str, ProvenanceEvent] = {}

    def add_event(self, event: ProvenanceEvent) -> None:
        """
        Adds a standardized provenance event to its designated tier subgraph.
        """
        if event.uuid in self.events_by_id:
            raise ValueError(f"Duplicate event UUID: {event.uuid}")
        self.global_graph = nx.DiGraph()
        self.events_by_id[event.uuid] = event
        tier_graph = self.subgraphs[event.tier]

        # Derive a readable endpoint description without changing hashed raw payloads.
        entity = event.payload.get("entity", "unknown")
        if entity == "unknown" and event.is_network_event:
            flow = event.network_tuple
            if flow:
                entity = f"{flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]} ({flow[4]})"
        # Add node with metadata attributes
        tier_graph.add_node(
            event.uuid,
            uuid=event.uuid,
            timestamp=event.timestamp,
            tier=event.tier.value,
            host_id=event.host_id,
            event_type=event.event_type.value,
            payload=event.payload,
            is_attack=event.payload.get("is_attack", False),
            action=event.payload.get("action", "unknown"),
            entity=entity,
        )

    def add_events(self, events: List[ProvenanceEvent]) -> None:
        """Batch ingestion of provenance events."""
        for event in events:
            self.add_event(event)

    def correlate_cross_tier_network(self) -> List[Tuple[str, str]]:
        """
        Identifies cross-tier socket flows and correlates outbound connections
        with incoming connection events at upstream nodes.
        Returns list of newly formed cross-tier edges E_network.
        """
        network_edges: List[Tuple[str, str]] = []

        # Find all socket events across all tiers
        socket_events: List[ProvenanceEvent] = [
            e for e in sorted(self.events_by_id.values(), key=lambda e: (e.timestamp, e.uuid)) if e.is_network_event
        ]

        # Partition into outbound (send / connect) and inbound (receive / accept)
        outbound_events = [
            e for e in socket_events
            if e.payload.get("action") in ["connect", "send", "outbound"]
        ]
        inbound_events = [
            e for e in socket_events
            if e.payload.get("action") in ["accept", "receive", "inbound", "recv"]
        ]

        # Correlate matching socket 5-tuples: (src_ip, src_port, dst_ip, dst_port, protocol)
        for out_e in outbound_events:
            out_tuple = out_e.network_tuple
            if not out_tuple:
                continue
            src_ip, src_port, dst_ip, dst_port, proto = out_tuple

            for in_e in inbound_events:
                # Ensure causal temporal order: out_e occurs at or before in_e
                time_delta = in_e.timestamp - out_e.timestamp
                if 0.0 <= time_delta <= self.time_window:
                    in_tuple = in_e.network_tuple
                    if not in_tuple:
                        continue
                    in_src_ip, in_src_port, in_dst_ip, in_dst_port, in_proto = in_tuple

                    # Check IP/port alignment and differing tiers
                    ip_match = (src_ip == in_src_ip and dst_ip == in_dst_ip)
                    port_match = (src_port == in_src_port and dst_port == in_dst_port)
                    protocol_match = (str(proto).upper() == str(in_proto).upper())
                    different_tiers = (out_e.tier != in_e.tier)

                    if ip_match and port_match and protocol_match and different_tiers and src_ip and dst_ip and src_port and dst_port:
                        network_edges.append((out_e.uuid, in_e.uuid))

        return network_edges

    def fuse_global_graph(self) -> nx.DiGraph:
        """
        Constructs G_global = G_edge U G_fog U G_cloud U E_network.
        Returns the unified causal DAG.
        """
        self.global_graph = nx.DiGraph()

        # Register every node first, then resolve dependencies independent of arrival order.
        for event in sorted(self.events_by_id.values(), key=lambda e: (e.timestamp, e.uuid)):
            attrs = dict(self.subgraphs[event.tier].nodes[event.uuid])
            for key in ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "pid", "process"):
                if key in event.payload:
                    attrs[key] = event.payload[key]
            self.global_graph.add_node(event.uuid, **attrs)
        errors = []
        for event in sorted(self.events_by_id.values(), key=lambda e: (e.timestamp, e.uuid)):
            for parent_id in sorted(event.parents):
                parent = self.events_by_id.get(parent_id)
                if parent is None:
                    errors.append(f"Event {event.uuid}: missing parent {parent_id}")
                elif parent_id == event.uuid or parent.timestamp > event.timestamp:
                    errors.append(f"Event {event.uuid}: invalid causal dependency on {parent_id}")
                else:
                    self.global_graph.add_edge(parent_id, event.uuid, relation="causal_dependency")
        if errors:
            raise ValueError("; ".join(errors))

        # 2. Add cross-tier network edges E_network
        cross_tier_edges = self.correlate_cross_tier_network()
        for u, v in cross_tier_edges:
            self.global_graph.add_edge(
                u,
                v,
                relation="cross_tier_network_flow",
                latency_delta=round(
                    self.events_by_id[v].timestamp - self.events_by_id[u].timestamp, 4
                ),
            )

        if not nx.is_directed_acyclic_graph(self.global_graph):
            raise ValueError("Causal dependencies contain a cycle")
        # Keep tier views consistent with the resolved graph.
        for tier in self.subgraphs:
            self.subgraphs[tier] = self.global_graph.subgraph(
                [e.uuid for e in self.events_by_id.values() if e.tier == tier]
            ).copy()
        return self.global_graph

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Returns structural statistics of the multi-tier graph."""
        if self.global_graph.number_of_nodes() == 0:
            self.fuse_global_graph()

        node_tiers = {"Edge": 0, "Fog": 0, "Cloud": 0}
        attack_nodes_count = 0
        for node, data in self.global_graph.nodes(data=True):
            tier = data.get("tier", "Unknown")
            if tier in node_tiers:
                node_tiers[tier] += 1
            if data.get("is_attack", False):
                attack_nodes_count += 1

        cross_tier_edges_count = sum(
            1
            for _, _, data in self.global_graph.edges(data=True)
            if data.get("relation") == "cross_tier_network_flow"
        )

        return {
            "total_nodes": self.global_graph.number_of_nodes(),
            "total_edges": self.global_graph.number_of_edges(),
            "nodes_per_tier": node_tiers,
            "attack_nodes_count": attack_nodes_count,
            "cross_tier_edges_count": cross_tier_edges_count,
            "is_directed_acyclic_graph": nx.is_directed_acyclic_graph(self.global_graph),
        }

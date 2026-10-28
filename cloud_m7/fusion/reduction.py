"""Conservative dependency-preserving folding; raw event evidence is never deleted."""
from dataclasses import dataclass
import hashlib
import json
import time

import networkx as nx


@dataclass
class ReductionResult:
    graph: nx.DiGraph
    membership: dict
    original_to_reduced: dict
    metrics: dict


def fold_repeated_reads(graph, protected_nodes=()):
    start = time.perf_counter()
    if not nx.is_directed_acyclic_graph(graph):
        raise ValueError("Reduction requires a causal DAG")
    protected = set(protected_nodes)

    def signature(node):
        data = graph.nodes[node]
        payload = data.get("payload", {})
        if (node in protected or data.get("event_type") != "File"
                or payload.get("action") != "read" or not payload.get("entity")
                or not (payload.get("pid") or payload.get("process"))
                or graph.in_degree(node) != 1 or graph.out_degree(node) != 1):
            return None
        return (data.get("host_id"), data.get("tier"), json.dumps(payload, sort_keys=True))

    membership, mapping = {}, {}
    for node in nx.lexicographical_topological_sort(graph, key=str):
        if node in mapping:
            continue
        chain, sig, current = [node], signature(node), node
        if sig is not None:
            while True:
                nxt = next(iter(graph.successors(current)))
                if nxt in mapping or signature(nxt) != sig:
                    break
                chain.append(nxt)
                current = nxt
        reduced_id = node if len(chain) == 1 else "fold-" + hashlib.sha256("|".join(chain).encode()).hexdigest()[:16]
        membership[reduced_id] = chain
        mapping.update({member: reduced_id for member in chain})
    reduced = nx.DiGraph()
    for reduced_id, members in membership.items():
        attrs = dict(graph.nodes[members[0]])
        attrs.update(member_uuids=members, folded_count=len(members))
        reduced.add_node(reduced_id, **attrs)
    for u, v, attrs in graph.edges(data=True):
        if mapping[u] != mapping[v]:
            reduced.add_edge(mapping[u], mapping[v], **attrs)
    # Compare every source/sink pair, including disconnected normal components.
    sources = [n for n in graph if graph.in_degree(n) == 0]
    sinks = [n for n in graph if graph.out_degree(n) == 0]
    sink_set = set(sinks)
    reduced_sink_set = {mapping[n] for n in sinks}
    preserved = all(
        {mapping[n] for n in ((nx.descendants(graph, source) | {source}) & sink_set)}
        == ((nx.descendants(reduced, mapping[source]) | {mapping[source]}) & reduced_sink_set)
        for source in sources
    )
    return ReductionResult(reduced, membership, mapping, {
        "original_nodes": len(graph), "reduced_nodes": len(reduced),
        "original_edges": graph.number_of_edges(), "reduced_edges": reduced.number_of_edges(),
        "node_reduction_pct": round(100 * (1 - len(reduced) / max(len(graph), 1)), 2),
        "folded_groups": sum(len(m) > 1 for m in membership.values()),
        "source_target_reachability_preserved": preserved,
        "execution_time_ms": round((time.perf_counter() - start) * 1000, 3),
        "method": "Consecutive identical read folding; complete original evidence retained",
    })

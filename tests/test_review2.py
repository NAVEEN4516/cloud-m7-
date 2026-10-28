"""Review 2 contracts: input evidence, causal validity, folding and dataset isolation."""
import json
import random
from pathlib import Path

import networkx as nx
import pytest

from cloud_m7.adapters.factory import DatasetNormalizerFactory
from cloud_m7.fusion.causal_graph import ProvenanceGraphEngine
from cloud_m7.fusion.attack_path import AttackPathReconstructor
from cloud_m7.fusion.interconnected_paths import InterconnectedAttackPathEngine
from cloud_m7.fusion.reduction import fold_repeated_reads
from cloud_m7.schema.event import ProvenanceEvent

DEMO = Path(__file__).resolve().parents[1] / "data" / "demo"


def graph_for(events):
    engine = ProvenanceGraphEngine(15)
    engine.add_events(events)
    engine.fuse_global_graph()
    return engine


@pytest.mark.parametrize("name", ["normal", "attack", "repeated"])
def test_fixture_json_csv_equivalence_and_manifest(name):
    factory = DatasetNormalizerFactory()
    json_events, _ = factory.normalize(str(DEMO / f"{name}.json"))
    csv_events, _ = factory.normalize(str(DEMO / f"{name}.csv"))
    assert [e.to_dict() for e in json_events] == [e.to_dict() for e in csv_events]
    engine = graph_for(json_events)
    other = graph_for(csv_events)
    assert set(engine.global_graph.edges) == set(other.global_graph.edges)
    expected = json.loads((DEMO / "manifest.json").read_text())["datasets"][name]
    path = AttackPathReconstructor(engine).reconstruct_attack_path()
    reduced = fold_repeated_reads(engine.global_graph)
    assert len(json_events) == expected["events"]
    assert engine.global_graph.number_of_edges() == expected["edges"]
    assert engine.get_summary_statistics()["cross_tier_edges_count"] == expected["cross_tier_flows"]
    assert (path.path_length if path else 0) == expected["primary_path_events"]
    assert len(reduced.graph) == expected["reduced_nodes"]
    assert sorted(InterconnectedAttackPathEngine(engine).analyze_interconnected_attack_graph().originating_sensors) == expected["originating_sensors"]


def test_shuffled_parent_resolution_and_three_sources():
    events, _ = DatasetNormalizerFactory().normalize(str(DEMO / "attack.json"))
    baseline = graph_for(events)
    random.Random(42).shuffle(events)
    shuffled = graph_for(events)
    assert set(shuffled.global_graph.edges) == set(baseline.global_graph.edges)
    before = AttackPathReconstructor(baseline).reconstruct_attack_path()
    after = AttackPathReconstructor(shuffled).reconstruct_attack_path()
    assert [e.uuid for e in before.attack_steps] == [e.uuid for e in after.attack_steps]
    for source in ("atk-edge-01-exploit", "atk2-edge-01-fw-exploit", "atk3-edge-01-plc-exploit"):
        assert nx.has_path(shuffled.global_graph, source, "atk-cloud-05-exfil-c2")


@pytest.mark.parametrize("changed,value", [("src_port", 1234), ("dst_port", 999), ("protocol", "UDP"), ("src_ip", "10.9.9.9"), ("dst_ip", "10.8.8.8")])
def test_network_requires_complete_five_tuple(changed, value):
    payload = {"action": "connect", "src_ip": "10.0.0.1", "src_port": 2000, "dst_ip": "10.0.0.2", "dst_port": 443, "protocol": "TCP"}
    incoming = dict(payload, action="accept")
    incoming[changed] = value
    engine = graph_for([ProvenanceEvent(uuid="out", timestamp=1, tier="Edge", event_type="Socket", payload=payload),
        ProvenanceEvent(uuid="in", timestamp=2, tier="Fog", event_type="Socket", payload=incoming)])
    assert not engine.global_graph.has_edge("out", "in")


@pytest.mark.parametrize("incoming_time", [0.5, 100.0])
def test_network_window_is_forward_and_bounded(incoming_time):
    common = dict(src_ip="10.0.0.1", src_port=2000, dst_ip="10.0.0.2", dst_port=443, protocol="TCP")
    engine = graph_for([ProvenanceEvent(uuid="out", timestamp=1, tier="Edge", event_type="Socket", payload=dict(common, action="connect")),
        ProvenanceEvent(uuid="in", timestamp=incoming_time, tier="Fog", event_type="Socket", payload=dict(common, action="accept"))])
    assert not engine.global_graph.edges


def test_invalid_dependencies_and_disconnected_path():
    with pytest.raises(ValueError, match="missing parent"):
        graph_for([ProvenanceEvent(uuid="child", parents=["absent"])])
    with pytest.raises(ValueError, match="invalid causal"):
        graph_for([ProvenanceEvent(uuid="early", timestamp=1, parents=["later"]), ProvenanceEvent(uuid="later", timestamp=2)])
    with pytest.raises(ValueError, match="cycle"):
        graph_for([ProvenanceEvent(uuid="a", timestamp=1, parents=["b"]), ProvenanceEvent(uuid="b", timestamp=1, parents=["a"])])
    engine = graph_for([ProvenanceEvent(uuid="a", timestamp=1), ProvenanceEvent(uuid="b", timestamp=2)])
    assert AttackPathReconstructor(engine).reconstruct_attack_path("a", "b") is None


@pytest.mark.parametrize("mutation,expected", [
    (lambda rows: rows[0].pop("timestamp"), "Row 1.*timestamp"),
    (lambda rows: rows[0].update(tamper_hash="0" * 64), "Row 1.*hash"),
    (lambda rows: rows[0].update(parents=["absent"]), "Row 1.*missing parent"),
    (lambda rows: rows.append(rows[0]), "Duplicate UUID"),
    (lambda rows: rows[0].update(payload="broken"), "payload must"),
])
def test_native_validation_has_row_errors(mutation, expected):
    rows = json.loads((DEMO / "normal.json").read_text())
    # A changed field should first be checked for structure, not a stale test hash.
    for row in rows:
        row.pop("tamper_hash", None)
    mutation(rows)
    with pytest.raises(ValueError, match=expected):
        DatasetNormalizerFactory().normalize(json.dumps(rows))


def test_missing_and_unsupported_input():
    for content in [str(DEMO / "absent.json"), "nonsense\nnot,an,event", "[]", ""]:
        with pytest.raises(ValueError):
            DatasetNormalizerFactory().normalize(content)


def test_folding_is_expandable_and_preserves_all_reachability():
    events, _ = DatasetNormalizerFactory().normalize(str(DEMO / "repeated.json"))
    original = graph_for(events).global_graph
    result = fold_repeated_reads(original)
    assert len(original) == 92 and len(result.graph) == 73
    groups = [members for members in result.membership.values() if len(members) > 1]
    assert groups == [[f"repeated-read-{i:02d}" for i in range(20)]]
    assert set(sum(result.membership.values(), [])) == set(original)
    assert result.metrics["source_target_reachability_preserved"]
    # Every relation between distinct groups is preserved; a folded chain is ordered evidence.
    for u in original:
        for v in original:
            if result.original_to_reduced[u] != result.original_to_reduced[v]:
                assert nx.has_path(original, u, v) == nx.has_path(result.graph, result.original_to_reduced[u], result.original_to_reduced[v])
    for n, d in original.nodes(data=True):
        if d["event_type"] == "Socket" or original.in_degree(n) != 1 or original.out_degree(n) != 1:
            assert result.membership[result.original_to_reduced[n]] == [n]
    assert original.number_of_nodes() == 92  # Input evidence is unmodified.


@pytest.fixture(scope="module")
def analyses(tmp_path_factory):
    import cloud_m7.bridge_api as api
    patch = pytest.MonkeyPatch()
    patch.setattr(api, "ROOT_DIR", tmp_path_factory.mktemp("review2"))
    results = {name: api.analyze_dataset(name) for name in ("normal", "attack", "repeated")}
    yield api, results
    patch.undo()


def test_sql_tracks_selection_and_survives_reload(analyses):
    api, results = analyses
    for name in ("attack", "normal", "repeated", "attack"):
        record = results[name]
        result = api.execute_sql("SELECT COUNT(*) AS n FROM provenance", record["dataset_id"])
        assert result["rows"] == [{"n": record["summary"]["total_events"]}]
    persisted = api.analyze_dataset(results["attack"]["dataset_id"])
    assert persisted["dataset_id"] == results["attack"]["dataset_id"]
    csv = api.analyze_dataset(str(DEMO / "attack.csv"))
    assert csv["dataset_id"] == results["attack"]["dataset_id"]
    assert api.execute_sql("SELECT 1")["status"] == "error"
    assert api.execute_sql("DELETE FROM provenance", csv["dataset_id"])["status"] == "error"


def test_analysis_evidence_and_model_labels(analyses):
    _, results = analyses
    assert not results["normal"]["reconstructed_timeline"]
    repeated = results["repeated"]
    assert len(repeated["events"]) == 92
    assert len(next(iter(repeated["folded_evidence"].values()))) == 20
    assert len(repeated["novelty2_chokepoints"]["originating_sensors"]) == 3
    assert len(repeated["novelty1_iterative"]["vectors"]) == 3
    assert "estimates" in repeated["placement"]["measurement_kind"]
    assert repeated["placement"]["adaptive"]["is_feasible"]

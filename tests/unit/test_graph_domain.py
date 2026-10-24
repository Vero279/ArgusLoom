from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import GraphNode


def test_graph_node_defaults_are_backward_compatible() -> None:
    node = GraphNode(id="node-1", kind=NodeKind.COMPUTE, name="Worker", source="manual")

    assert node.cves == []
    assert node.mitre_techniques == []
    assert node.cvss_max == 0.0
    assert node.criticality == Criticality.LOW
    assert node.exposure == 0.0

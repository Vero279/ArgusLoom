from pathlib import Path
from argusloom.graph.store import GraphStore
from argusloom.analysis.threat_model import analyze_graph

graph = GraphStore(Path("data/graph.json")).load()
findings = analyze_graph(graph)

print("=== risk_score por nó (analyze_graph) ===")
for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
    node = next(n for n in graph.nodes if n.id == f.node_id)
    print(f"{f.node_id:40s} risk={f.risk_score:.2f}  kind={node.kind.value:10s} exposure={node.exposure:.1f}  cvss={node.cvss_max:.1f}")
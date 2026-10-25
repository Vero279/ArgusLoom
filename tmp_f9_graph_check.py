from pathlib import Path
from argusloom.ingestion.graph_builder import build_graph

root = Path.cwd()
graph = build_graph(
    terraform_path=root / 'data/fixtures/terraform',
    k8s_path=root / 'data/fixtures/k8s',
    output_path=None,
)
print(f'Generated: {len(graph.nodes)} nodes, {len(graph.edges)} edges')
for n in graph.nodes:
    print(f'  {n.id} ({n.kind.value})')
for e in graph.edges:
    print(f'  {e.source} -> {e.target} ({e.relation})')

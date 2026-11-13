import type { BlastRadiusResponse, GraphData, GraphNode } from '../api';
import { getStride, scoreMap } from '../security';
import RiskBadge from './RiskBadge';
import StrideBadge from './StrideBadge';

interface BlastRadiusPanelProps {
  result: BlastRadiusResponse;
  graph: GraphData;
  onClose: () => void;
  onSelectNode: (id: string) => void;
}

export default function BlastRadiusPanel({ result, graph, onClose, onSelectNode }: BlastRadiusPanelProps) {
  const graphNodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const affected = new Map<string, GraphNode>();
  result.nodes.forEach((node) => affected.set(node.id, node));
  const root = graphNodes.get(result.root_id);
  if (root) affected.set(root.id, root);
  const scores = scoreMap(graph);
  const ordered = [...affected.values()].sort((a, b) =>
    (result.depth_map[a.id] ?? 0) - (result.depth_map[b.id] ?? 0) || a.id.localeCompare(b.id),
  );
  const affectedCount = ordered.filter((node) => node.id !== result.root_id).length;
  const criticalCount = ordered.filter((node) => node.id !== result.root_id && node.criticality === 'critical').length;
  const sentence = `Se ${result.root_id} for comprometido, ${affectedCount} nós ficam expostos até profundidade ${result.max_depth}. O risco agregado é ${result.risk_score.toFixed(2)}.`;

  return (
    <aside className="panel result-panel" aria-labelledby="blast-heading">
      <div className="panel-heading result-panel-heading">
        <div><p className="eyebrow">Impacto do comprometimento</p><h2 id="blast-heading">Blast radius</h2></div>
        <button className="icon-button" type="button" onClick={onClose} aria-label="Fechar resultado blast radius">×</button>
      </div>
      <p className="result-summary" aria-live="polite">{sentence}</p>
      <div className="blast-metrics">
        <div><span>Nós afetados</span><strong>{affectedCount}</strong></div>
        <div><span>Críticos</span><strong>{criticalCount}</strong></div>
        <div><span>Risco agregado</span><strong>{result.risk_score.toFixed(2)}</strong></div>
      </div>
      <p className="table-footnote">Score ponderado: nós mais distantes contribuem menos (decay 0.7 por nível).</p>
      <h3 className="result-list-heading">Ativos por profundidade</h3>
      <ol className="blast-node-list">
        {ordered.map((node) => {
          const depth = result.depth_map[node.id] ?? 0;
          return (
            <li className="blast-node" key={node.id}>
              <span className="depth-marker" aria-label={`Profundidade ${depth}`}>{depth}</span>
              <div className="blast-node-content">
                <div className="blast-node-heading">
                  <button className="table-link" type="button" onClick={() => onSelectNode(node.id)}><code>{node.id}</code></button>
                  <RiskBadge value={node.criticality} />
                </div>
                <span className="kind-label">{node.kind} · risco local {(scores.get(node.id) ?? 0).toFixed(2)}</span>
                <div className="stride-inline">{getStride(node).map((value) => <StrideBadge key={value} value={value} inferred={!node.stride?.length} />)}</div>
              </div>
            </li>
          );
        })}
      </ol>
    </aside>
  );
}

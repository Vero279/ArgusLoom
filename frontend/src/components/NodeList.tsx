import type { GraphNode } from '../api';
import { getStride } from '../security';
import { deriveFamily, deriveRisk, familyLabels, riskLabels } from '../visualEncoding';
import StrideBadge from './StrideBadge';

interface NodeListProps {
  nodes: GraphNode[];
  onSelect: (nodeId: string) => void;
  selectedNodeId: string | null;
}

export default function NodeList({ nodes, onSelect, selectedNodeId }: NodeListProps) {
  return (
    <div className="table-scroll">
      <table className="node-table">
        <caption className="visually-hidden">Nós do grafo de infraestrutura</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Tipo</th>
            <th scope="col">Risco</th>
            <th scope="col">Família</th>
            <th scope="col">Exposição</th>
            <th scope="col">CVEs</th>
            <th scope="col">STRIDE</th>
            <th scope="col">Ações</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((node) => {
            const risk = deriveRisk(node);
            const family = deriveFamily(node);
            return (
              <tr className={selectedNodeId === node.id ? 'selected-row' : undefined} key={node.id}>
                <th scope="row"><code>{node.id}</code></th>
                <td>{node.kind}</td>
                <td>
                  <span className={`risk-label risk-${risk}`}>
                    <span>{riskLabels[risk]}</span>
                  </span>
                </td>
                <td>{familyLabels[family]}</td>
                <td>{node.exposure.toFixed(2)}</td>
                <td>{node.cves.length}</td>
                <td><div className="stride-inline">{getStride(node).map((value) => <StrideBadge key={value} value={value} inferred={!node.stride?.length} />)}</div></td>
                <td>
                  <button
                    className="button button-small button-secondary"
                    type="button"
                    aria-label={`Selecionar ${node.id}`}
                    aria-pressed={selectedNodeId === node.id}
                    onClick={() => onSelect(node.id)}
                  >
                    Selecionar
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {nodes.length === 0 && <p className="empty-state">Nenhum nó corresponde aos filtros atuais.</p>}
    </div>
  );
}

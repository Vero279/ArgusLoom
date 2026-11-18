import type { AttackPathResponse, GraphData, GraphNode } from '../api';
import { cveById, techniqueById } from '../data/threatIntel';
import { getStride, incidentConfidence, scoreNode, severityForCvss } from '../security';
import {
  deriveFamily,
  deriveRisk,
  familyLabels,
  hasCheckovFinding,
  isPoisonedNode,
  riskLabels,
} from '../visualEncoding';
import ConfidenceBar from './ConfidenceBar';
import CTICard from './CTICard';
import RiskBadge from './RiskBadge';
import StrideBadge from './StrideBadge';

interface DetailPanelProps {
  node: GraphNode | null;
  graph: GraphData;
  onBlastRadius: () => void;
  onOpenAttackPaths: () => void;
  attackResult: AttackPathResponse | null;
  actionError: string | null;
  isBusy: boolean;
}

function attackPathReason(path: AttackPathResponse['paths'][number], graph: GraphData): string {
  if (path.edges.length === 0) return 'Origem e destino são o mesmo ativo; não há ligações a percorrer.';
  const edge = path.edges[0];
  const source = graph.nodes.find((node) => node.id === edge.source);
  const target = graph.nodes.find((node) => node.id === edge.target);
  const evidence = source && target
    ? `A relação ${edge.relation} de ${source.id} para ${target.id} combina cvss_max=${source.cvss_max.toFixed(1)} na origem${source.cves.length ? ` (${source.cves.length} CVE(s) associadas)` : ''} com exposure=${target.exposure.toFixed(2)} no destino`
    : `A relação ${edge.relation} tem custo base porque um dos ativos não tem dados de risco`;
  const mitreCount = path.edges.filter((item) => item.metadata?.mitre_technique).length;
  const mitreContext = mitreCount
    ? `; ${mitreCount} relação(ões) também têm técnica MITRE associada, apresentada na cadeia abaixo`
    : '';
  const relationDiscount = ['iam', 'network', 'lateral'].includes(edge.relation)
    ? '; esta relação também recebe o desconto definido pelo modelo de caminhos'
    : '';
  return `${evidence}; o custo diminui quando esta combinação aumenta${relationDiscount}${mitreContext}. O score do caminho soma os custos das relações.`;
}

function PathResults({ result, graph }: { result: AttackPathResponse; graph: GraphData }) {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  return (
    <section className="analysis-results" aria-labelledby="attack-results-heading" aria-live="polite">
      <h3 id="attack-results-heading">Caminhos encontrados</h3>
      {result.paths.length === 0 && <p className="muted-copy">Nenhum caminho encontrado entre estes ativos.</p>}
      {result.paths.map((path, pathIndex) => (
        <article className="path-result-card" key={`${path.nodes.join('-')}-${pathIndex}`}>
          <div className="path-result-heading">
            <h4>{result.strategy === 'dijkstra' ? 'Melhor caminho' : `Caminho ${pathIndex + 1}${pathIndex === 0 ? ' (melhor)' : ''}`}</h4>
            <strong className="path-score">Score {path.score.toFixed(2)}</strong>
          </div>
          <p className="path-score-help">
            {`Score ${path.score.toFixed(2)} (menor = mais fácil de explorar). ${attackPathReason(path, graph)}`}
          </p>
          <ol className="attack-steps">
            {path.nodes.map((nodeId, index) => {
              const node = nodeById.get(nodeId);
              const relation = path.edges[index];
              return (
                <li className="attack-step" key={`${nodeId}-${index}`}>
                  <div className="attack-step-node">
                    <span className="step-number">{index + 1}</span>
                    <div><code>{nodeId}</code><span>{node?.kind ?? 'ativo externo'}</span></div>
                    {node && <RiskBadge value={node.criticality} />}
                  </div>
                  {relation && (
                    <div className="attack-edge-card">
                      <span aria-hidden="true">↓</span>
                      <span>Relação: <strong>{relation.relation}</strong></span>
                      {relation.confidence !== undefined && <span>Confiança {Math.round(relation.confidence * 100)}%</span>}
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
          <div className="mitre-chain">
            <h5>Cadeia MITRE</h5>
            {path.mitre_chain.length
              ? path.mitre_chain.map((id) => <a className="technique-pill" key={id} href={id.startsWith('AML.') ? `https://atlas.mitre.org/techniques/${id}` : `https://attack.mitre.org/techniques/${id}/`} target="_blank" rel="noreferrer">{id}</a>)
              : <span className="muted-copy">Sem técnica MITRE associada às ligações.</span>}
          </div>
        </article>
      ))}
    </section>
  );
}

export default function DetailPanel({
  node,
  graph,
  onBlastRadius,
  onOpenAttackPaths,
  attackResult,
  actionError,
  isBusy,
}: DetailPanelProps) {
  if (!node) {
    return (
      <aside className="panel detail-panel" aria-labelledby="detail-heading">
        <div className="panel-heading"><p className="eyebrow">Seleção</p><h2 id="detail-heading">Detalhes do ativo</h2></div>
        <p className="empty-state detail-empty">Seleciona um ativo na tabela ou no grafo. Ctrl+K abre a paleta de comandos.</p>
      </aside>
    );
  }

  const incoming = graph.edges.filter((edge) => edge.target === node.id);
  const outgoing = graph.edges.filter((edge) => edge.source === node.id);
  const stride = getStride(node);
  const inferredStride = !node.stride?.length;
  const cves = node.cves.map((id) => cveById.get(id)).filter((record) => record !== undefined);
  const techniques = node.mitre_techniques.map((id) => techniqueById.get(id)).filter((record) => record !== undefined);
  const countAtlas = techniques.filter((record) => record.id.startsWith('AML.')).length;
  const countAttack = techniques.length - countAtlas;
  const unknownCves = node.cves.filter((id) => !cveById.has(id));
  const unknownTechniques = node.mitre_techniques.filter((id) => !techniqueById.has(id));
  const exposureText = node.exposure > 0.7 ? 'exposto' : 'com exposição limitada';
  const visualRisk = deriveRisk(node);
  const family = deriveFamily(node);
  const poisoned = isPoisonedNode(node);
  const hasFinding = hasCheckovFinding(node);
  const rationale = `Este ativo tem exposure=${node.exposure.toFixed(2)} (${exposureText}), criticality=${node.criticality}, ${node.cves.length} CVE(s) e cvss_max=${node.cvss_max.toFixed(1)}. Recebe ${incoming.length} ligação(ões) e emite ${outgoing.length}. STRIDE: ${stride.map((value) => value.replace(/_/g, ' ')).join(', ')}${inferredStride ? ' (inferido pelo tipo)' : ''}. O score local do modelo é ${scoreNode(node, graph).toFixed(2)}.`;
  const confidence = incidentConfidence(node, graph);

  return (
    <aside className="panel detail-panel" aria-labelledby="detail-heading">
      <div className="panel-heading">
        <p className="eyebrow">Análise contextual</p>
        <h2 id="detail-heading">Detalhes do ativo</h2>
      </div>
      <div className="detail-title">
        <code>{node.id}</code>
        <div className="node-badges"><span className="kind-badge">{node.kind}</span><RiskBadge value={visualRisk} /></div>
      </div>
      <dl className="detail-grid">
        <div><dt>Exposição</dt><dd>{node.exposure.toFixed(2)}</dd></div>
        <div><dt>Risco visual</dt><dd>{riskLabels[visualRisk]}</dd></div>
        <div><dt>Família</dt><dd>{familyLabels[family]}</dd></div>
        <div><dt>CVSS máximo</dt><dd><span className={`severity-chip severity-${severityForCvss(node.cvss_max).toLowerCase()}`}>{node.cvss_max.toFixed(1)}</span></dd></div>
        <div><dt>Ligações recebidas</dt><dd>{incoming.length}</dd></div>
        <div><dt>Ligações emitidas</dt><dd>{outgoing.length}</dd></div>
      </dl>
      {(poisoned || hasFinding) && (
        <section className="detail-section" aria-label="Proveniência de segurança">
          {poisoned && <p className="error-message" role="status">Documento CTI sintético/poisoned associado a este ativo.</p>}
          {hasFinding && <p className="error-message" role="status">Este ativo tem findings Checkov associados.</p>}
        </section>
      )}

      <section className="detail-section" aria-labelledby="risk-rationale-heading">
        <h3 id="risk-rationale-heading">Porquê este risco?</h3>
        <p className="rationale-copy">{rationale}</p>
      </section>

      <section className="detail-section" aria-labelledby="stride-heading">
        <div className="section-title-row"><h3 id="stride-heading">Categorias STRIDE</h3><span className="kind-label">{inferredStride ? 'inferidas pelo tipo' : 'do grafo'}</span></div>
        <div className="badge-wrap">{stride.map((value) => <StrideBadge key={value} value={value} inferred={inferredStride} />)}</div>
      </section>

      <ConfidenceBar value={confidence} />

      <section className="detail-section" aria-labelledby="cve-cards-heading">
        <div className="section-title-row"><h3 id="cve-cards-heading">Vulnerabilidades</h3><span className="section-count">{node.cves.length}</span></div>
        <div className="cti-card-grid">
          {cves.map((record) => <CTICard type="cve" record={record} key={record.id} />)}
        </div>
        {unknownCves.map((id) => <article className="cti-card cti-card-compact" key={id}><a className="mono-link" href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer">{id}</a><p>O grafo referencia esta CVE, mas não há descrição no fixture local.</p></article>)}
        {!node.cves.length && <p className="muted-copy">Sem CVEs associadas a este ativo.</p>}
      </section>

      <section className="detail-section" aria-labelledby="technique-cards-heading">
        <div className="section-title-row"><h3 id="technique-cards-heading">Inteligência de ameaça</h3><span className="kind-label">{countAttack} ATT&amp;CK · {countAtlas} ATLAS</span></div>
        <div className="cti-card-grid">
          {techniques.map((record) => <CTICard type={record.id.startsWith('AML.') ? 'atlas' : 'attack'} record={record} key={record.id} />)}
        </div>
        {unknownTechniques.map((id) => <article className="cti-card cti-card-compact" key={id}><code>{id}</code><p>Técnica sem metadados no fixture local.</p></article>)}
        {!node.mitre_techniques.length && <p className="muted-copy">Sem técnicas associadas a este ativo.</p>}
      </section>

      <div className="detail-actions">
        <button className="button button-primary" type="button" onClick={onBlastRadius} disabled={isBusy}>Ver blast radius</button>
        <button className="button button-secondary" type="button" onClick={onOpenAttackPaths} disabled={isBusy}>Ver caminhos de ataque</button>
      </div>

      {actionError && <p className="error-message" role="alert">{actionError}</p>}
      {attackResult && <PathResults result={attackResult} graph={graph} />}
    </aside>
  );
}

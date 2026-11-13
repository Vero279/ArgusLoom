import { useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import type { GraphData, RagResponse } from '../api';
import { cveById, cveRecords, techniqueById } from '../data/threatIntel';
import { getStride, scoreMap, severityForCvss } from '../security';
import GraphCanvas from './GraphCanvas';
import RiskBadge from './RiskBadge';
import StrideBadge from './StrideBadge';

export type Screen = 'overview' | 'explorer';

interface OverviewScreenProps {
  graph: GraphData;
  reducedMotion: boolean;
  onSelectNode: (id: string) => void;
  onAskGraph: (query: string) => Promise<RagResponse>;
  onReenrich: () => void;
  isEnriching: boolean;
  enrichmentMessage: string | null;
  enrichmentError: string | null;
}

export default function OverviewScreen({
  graph,
  reducedMotion,
  onSelectNode,
  onAskGraph,
  onReenrich,
  isEnriching,
  enrichmentMessage,
  enrichmentError,
}: OverviewScreenProps) {
  const [query, setQuery] = useState('');
  const [ragResult, setRagResult] = useState<RagResponse | null>(null);
  const [ragError, setRagError] = useState<string | null>(null);
  const [isAsking, setIsAsking] = useState(false);
  const scores = useMemo(() => scoreMap(graph), [graph]);

  const rankedNodes = useMemo(
    () => [...graph.nodes].sort((a, b) => b.exposure - a.exposure || (scores.get(b.id) ?? 0) - (scores.get(a.id) ?? 0)),
    [graph.nodes, scores],
  );
  const exposedNodes = rankedNodes;
  const cveRows = useMemo(() => {
    const affected = new Map<string, string[]>();
    graph.nodes.forEach((node) => node.cves.forEach((id) => {
      affected.set(id, [...(affected.get(id) ?? []), node.id]);
    }));
    return [...affected.entries()]
      .map(([id, nodes]) => ({ record: cveById.get(id), id, nodes }))
      .sort((a, b) => (b.record?.cvss_score ?? 0) - (a.record?.cvss_score ?? 0))
      .slice(0, 5);
  }, [graph.nodes]);
  const techniqueRows = useMemo(() => {
    const counts = new Map<string, number>();
    graph.nodes.forEach((node) => node.mitre_techniques.forEach((id) =>
      counts.set(id, (counts.get(id) ?? 0) + 1),
    ));
    return [...counts.entries()]
      .map(([id, count]) => ({ id, count, record: techniqueById.get(id) }))
      .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
      .slice(0, 3);
  }, [graph.nodes]);
  const maxCvss = Math.max(0, ...graph.nodes.map((node) => node.cvss_max));
  const maxRisk = Math.max(0, ...scores.values());
  const cveCount = new Set(graph.nodes.flatMap((node) => node.cves)).size;
  const exposedCount = graph.nodes.filter((node) => node.exposure > 0.7).length;
  const decorativeGraph = useMemo<GraphData>(() => {
    const ids = new Set(graph.nodes.map((node) => node.id));
    return {
      nodes: graph.nodes,
      edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)),
    };
  }, [graph]);

  async function submitQuery(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!query.trim()) return;
    setIsAsking(true);
    setRagError(null);
    try {
      setRagResult(await onAskGraph(query.trim()));
    } catch (error) {
      setRagError(error instanceof Error ? error.message : 'Não foi possível consultar o grafo.');
    } finally {
      setIsAsking(false);
    }
  }

  return (
    <section className="screen-stack" aria-labelledby="overview-heading">
      <header className="screen-heading">
        <div>
          <p className="eyebrow">01 / Attack surface</p>
          <h2 id="overview-heading">Visão geral de risco</h2>
          <p className="screen-summary">Concentração de exposição, vulnerabilidades e técnicas observadas no grafo.</p>
        </div>
        <button className="button button-secondary" type="button" onClick={onReenrich} disabled={isEnriching}>
          {isEnriching ? 'A enriquecer…' : 'Reenriquecer CTI'}
        </button>
      </header>

      <section className="kpi-grid" aria-label="Indicadores da superfície de ataque">
        <article className="kpi-card"><span>Total de nós</span><strong>{graph.nodes.length}</strong><small>ativos no grafo</small></article>
        <article className="kpi-card"><span>Nós com CVEs</span><strong>{graph.nodes.filter((node) => node.cves.length > 0).length}</strong><small>{cveCount} CVEs únicas</small></article>
        <article className="kpi-card"><span>Nós expostos</span><strong>{exposedCount}</strong><small>exposure superior a 0.7</small></article>
        <article className="kpi-card"><span>CVSS máximo</span><strong>{maxCvss.toFixed(1)}</strong><small>maior score observado</small></article>
        <article className="kpi-card kpi-risk"><span>Maior risco local</span><strong>{maxRisk.toFixed(2)}</strong><small>score do modelo de ameaça</small></article>
      </section>

      {(enrichmentMessage || enrichmentError) && (
        <p className={enrichmentError ? 'inline-alert' : 'inline-success'} role={enrichmentError ? 'alert' : 'status'}>
          {enrichmentError ?? enrichmentMessage}
        </p>
      )}

      <div className="overview-grid">
        <section className="overview-card exposed-card" aria-labelledby="exposed-heading">
          <div className="section-title-row">
            <div><p className="eyebrow">Prioridade por exposição</p><h3 id="exposed-heading">Top 5 ativos expostos</h3></div>
            <span className="section-count">{rankedNodes.slice(0, 5).length} ativos</span>
          </div>
          <div className="table-scroll">
            <table className="data-table exposed-table">
              <caption className="visually-hidden">Os cinco nós com maior exposição e risco no grafo</caption>
              <thead><tr><th scope="col">Ativo</th><th scope="col">Exposição</th><th scope="col">CVSS</th><th scope="col">STRIDE</th><th scope="col">Risco</th></tr></thead>
              <tbody>
                {exposedNodes.slice(0, 5).map((node) => (
                  <tr key={node.id}>
                    <th scope="row">
                      <button className="table-link" type="button" onClick={() => onSelectNode(node.id)}>
                        <code>{node.id}</code>
                      </button>
                      <span className="kind-label">{node.kind}</span>
                    </th>
                    <td>{node.exposure.toFixed(2)}</td>
                    <td>{node.cvss_max.toFixed(1)}</td>
                    <td><div className="stride-inline">{getStride(node).map((item) => <StrideBadge key={item} value={item} inferred={!node.stride?.length} />)}</div></td>
                    <td><RiskBadge value={node.criticality} /></td>
                  </tr>
                ))}
                {exposedNodes.length === 0 && <tr><td colSpan={5}>Não existem ativos no grafo.</td></tr>}
              </tbody>
            </table>
          </div>
          <p className="table-footnote">Categorias STRIDE sem valor explícito são inferidas pelo tipo do ativo. Score local calculado segundo o modelo do backend.</p>
        </section>

        <section className="overview-card minimap-card" aria-labelledby="minimap-heading">
          <div className="section-title-row">
            <div><p className="eyebrow">Contexto</p><h3 id="minimap-heading">Mapa da infraestrutura</h3></div>
            <span className="section-count">{graph.edges.length} relações</span>
          </div>
          <div className="overview-minimap" aria-hidden="true">
            <GraphCanvas
              nodes={decorativeGraph.nodes}
              edges={decorativeGraph.edges}
              highlight={null}
              reducedMotion={reducedMotion}
              onSelect={() => undefined}
              decorative
            />
          </div>
          <p className="table-footnote">Mapa apenas visual. Abre o Explorador para selecionar ativos e analisar relações.</p>
        </section>

        <section className="overview-card" aria-labelledby="cves-heading">
          <div className="section-title-row">
            <div><p className="eyebrow">Vulnerabilidades</p><h3 id="cves-heading">Top 5 CVEs por severidade</h3></div>
          </div>
          <div className="table-scroll">
            <table className="data-table">
              <caption className="visually-hidden">Cinco CVEs com maior score CVSS e os ativos afetados</caption>
              <thead><tr><th scope="col">CVE</th><th scope="col">CVSS</th><th scope="col">Ativo(s) afetado(s)</th></tr></thead>
              <tbody>
                {cveRows.map(({ id, record, nodes }) => (
                  <tr key={id}>
                    <th scope="row"><a className="mono-link" href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer">{id}</a></th>
                    <td><span className={`severity-chip severity-${severityForCvss(record?.cvss_score ?? 0).toLowerCase()}`}>{record?.cvss_score.toFixed(1) ?? '—'}</span></td>
                    <td>{nodes.map((nodeId) => <button className="table-link" type="button" key={nodeId} onClick={() => onSelectNode(nodeId)}><code>{nodeId}</code></button>)}</td>
                  </tr>
                ))}
                {cveRows.length === 0 && <tr><td colSpan={3}>Nenhuma CVE associada aos ativos.</td></tr>}
              </tbody>
            </table>
          </div>
          {cveRows.some((row) => !row.record) && <p className="table-footnote">{cveRecords.length} registos locais; algumas CVEs não têm metadados no fixture.</p>}
        </section>

        <section className="overview-card" aria-labelledby="techniques-heading">
          <div className="section-title-row">
            <div><p className="eyebrow">Comportamento adversário</p><h3 id="techniques-heading">Técnicas MITRE mais presentes</h3></div>
          </div>
          <div className="table-scroll">
            <table className="data-table technique-table">
              <caption className="visually-hidden">Três técnicas MITRE ATT&amp;CK ou ATLAS associadas a mais ativos</caption>
              <thead><tr><th scope="col">Técnica</th><th scope="col">Tática</th><th scope="col">Ativos</th></tr></thead>
              <tbody>
                {techniqueRows.map(({ id, count, record }) => (
                  <tr key={id}>
                    <th scope="row"><a className="mono-link" href={id.startsWith('AML.') ? `https://atlas.mitre.org/techniques/${id}` : `https://attack.mitre.org/techniques/${id}/`} target="_blank" rel="noreferrer">{id}</a><span className="kind-label">{record?.name ?? 'Técnica sem metadados no fixture'}</span></th>
                    <td>{record?.tactic ?? '—'}</td>
                    <td>{count}</td>
                  </tr>
                ))}
                {techniqueRows.length === 0 && <tr><td colSpan={3}>Sem técnicas MITRE associadas.</td></tr>}
              </tbody>
            </table>
          </div>
          <p className="table-footnote">As técnicas ATLAS são identificadas pelo prefixo AML e ligadas ao catálogo ATLAS.</p>
        </section>
      </div>

      <section className="overview-card rag-card" aria-labelledby="rag-heading">
        <div><p className="eyebrow">Pesquisa</p><h3 id="rag-heading">Pesquisar no grafo</h3><p className="screen-summary">Consulta semântica sobre ativos, exposição e contexto de ameaça.</p></div>
        <p className="table-footnote">Esta pesquisa encontra ativos por similaridade semântica com a tua pergunta. Não navega arestas nem calcula caminhos — para isso, usa 'Blast radius' ou 'Caminhos de ataque'.</p>
        <form className="rag-form" onSubmit={(event) => void submitQuery(event)}>
          <label className="visually-hidden" htmlFor="rag-query">Pergunta sobre a infraestrutura</label>
          <input id="rag-query" className="text-input" value={query} onChange={(event) => setQuery(event.currentTarget.value)} maxLength={500} placeholder="Ex.: Que ativos estão mais expostos?" required />
          <button className="button button-primary" type="submit" disabled={isAsking || !query.trim()}>{isAsking ? 'A pesquisar…' : 'Perguntar'}</button>
        </form>
        {ragError && <p className="inline-alert" role="alert">{ragError}</p>}
        {ragResult && (
          <div className="rag-results" aria-live="polite">
            {ragResult.hits.map((hit) => <article className="rag-hit" key={hit.id}><strong>{hit.id}</strong><p>{hit.text}</p><small>Relevância {Math.round(hit.score * 100)}%</small></article>)}
            {ragResult.hits.length === 0 && <p className="muted-copy">Sem resultados para esta pergunta.</p>}
          </div>
        )}
      </section>
    </section>
  );
}

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import * as Tooltip from '@radix-ui/react-tooltip';
import {
  activateScenario,
  getBlastRadius,
  getCurrentScenario,
  getGraph,
  getHealth,
  listScenarios,
  postAttackPaths,
  postCtiEnrichment,
  postRagQuery,
} from './api';
import type {
  AttackPathRequest,
  AttackPathResponse,
  AttackPathSelection,
  BlastRadiusResponse,
  Criticality,
  CurrentScenario,
  GraphData,
  GraphEdge,
  HealthResponse,
  NodeKind,
  RagResponse,
  Scenario,
  ScenarioId,
} from './api';
import CommandPalette from './components/CommandPalette';
import GraphExplorer from './components/GraphExplorer';
import type { GraphHighlight, ScenarioPositionCache } from './components/GraphCanvas';
import OverviewScreen from './components/OverviewScreen';
import type { Screen } from './components/OverviewScreen';
import { getStride } from './security';

const allKinds: NodeKind[] = ['compute', 'storage', 'network', 'iam', 'data', 'external'];
type ScenarioNotice = { kind: 'success' | 'error' | 'warning'; message: string };

function useReducedMotion(): boolean {
  const [reducedMotion, setReducedMotion] = useState(() =>
    window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReducedMotion(query.matches);
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  return reducedMotion;
}

function edgeKey(edge: GraphEdge, index: number): string {
  return `${edge.source}::${edge.target}::${index}`;
}

export default function App() {
  const [graph, setGraph] = useState<GraphData>({ nodes: [], edges: [] });
  const scenarioPositionCacheRef = useRef<ScenarioPositionCache>(new Map());
  const [scenarioOptions, setScenarioOptions] = useState<Scenario[] | null>(null);
  const [currentScenario, setCurrentScenario] = useState<CurrentScenario>({ id: 'unknown' });
  const [switchingScenarioId, setSwitchingScenarioId] = useState<ScenarioId | null>(null);
  const [scenarioNotice, setScenarioNotice] = useState<ScenarioNotice | null>(null);
  const [selectedKinds, setSelectedKinds] = useState<NodeKind[]>(allKinds);
  const [selectedStride, setSelectedStride] = useState<string[]>([]);
  const [severity, setSeverity] = useState<'all' | Criticality>('all');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>('overview');
  const [highlight, setHighlight] = useState<GraphHighlight | null>(null);
  const [blastResult, setBlastResult] = useState<BlastRadiusResponse | null>(null);
  const [attackResult, setAttackResult] = useState<AttackPathResponse | null>(null);
  const [attackPathSelection, setAttackPathSelection] = useState<AttackPathSelection>({
    sourceId: '',
    targetId: '',
    strategy: 'dijkstra',
  });
  const [actionError, setActionError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [status, setStatus] = useState('A carregar a superfície de ataque…');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isEnriching, setIsEnriching] = useState(false);
  const [isBusy, setIsBusy] = useState(false);
  const [attackDialogOpen, setAttackDialogOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [enrichmentMessage, setEnrichmentMessage] = useState<string | null>(null);
  const [enrichmentError, setEnrichmentError] = useState<string | null>(null);
  const reducedMotion = useReducedMotion();
  const scenarioControlAvailable = useRef(false);
  const hasLoadedGraphRef = useRef(false);
  const isSwitchingScenario = switchingScenarioId !== null;
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId) ?? null;

  const filteredNodes = useMemo(() => graph.nodes.filter((node) => {
    const kindMatch = selectedKinds.includes(node.kind);
    const strideMatch = selectedStride.length === 0 || getStride(node).some((item) => selectedStride.includes(item));
    const severityMatch = severity === 'all' || node.criticality === severity;
    return kindMatch && strideMatch && severityMatch;
  }), [graph.nodes, selectedKinds, selectedStride, severity]);

  const loadGraph = useCallback(async () => {
    setIsRefreshing(true);
    if (!hasLoadedGraphRef.current) setLoadError(null);
    try {
      const data = await getGraph();
      setGraph(data);
      hasLoadedGraphRef.current = true;
      setLoadError(null);
      setSelectedNodeId((current) => current && data.nodes.some((node) => node.id === current) ? current : null);
      setStatus(`Superfície atualizada: ${data.nodes.length} nós e ${data.edges.length} relações.`);
      if (scenarioControlAvailable.current) {
        try {
          setCurrentScenario(await getCurrentScenario());
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Erro ao identificar o cenário atual.';
          setStatus(`Grafo atualizado. Não foi possível identificar o cenário: ${message}`);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Erro inesperado ao carregar o grafo.';
      if (!hasLoadedGraphRef.current) setLoadError(message);
      setStatus(`Falha ao carregar o grafo. ${message}`);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void loadGraph();
    listScenarios()
      .then((scenarios) => {
        scenarioControlAvailable.current = scenarios.length > 0;
        setScenarioOptions(scenarios.length > 0 ? scenarios : null);
      })
      .catch(() => {
        scenarioControlAvailable.current = false;
        setScenarioOptions(null);
      });
    getCurrentScenario()
      .then(setCurrentScenario)
      .catch(() => setCurrentScenario({ id: 'unknown' }));
    getHealth()
      .then(setHealth)
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : 'Erro ao verificar a API.';
        setStatus((current) => `${current} API indisponível: ${message}`);
      });
  }, [loadGraph]);

  useEffect(() => {
    if (!scenarioNotice || scenarioNotice.kind === 'error') return;
    const timer = window.setTimeout(() => setScenarioNotice(null), 5000);
    return () => window.clearTimeout(timer);
  }, [scenarioNotice]);

  async function switchScenario(id: ScenarioId) {
    if (isSwitchingScenario) return;
    setSwitchingScenarioId(id);
    setIsRefreshing(true);
    setScenarioNotice(null);
    try {
      const activated = await activateScenario(id);
      const [newGraph, activeScenario] = await Promise.all([
        getGraph(),
        getCurrentScenario(),
      ]);
      setGraph(newGraph);
      hasLoadedGraphRef.current = true;
      setCurrentScenario(activeScenario);
      setSelectedNodeId(null);
      setBlastResult(null);
      setAttackResult(null);
      setHighlight(null);
      setActionError(null);
      setEnrichmentMessage(null);
      setEnrichmentError(null);
      setAttackPathSelection({ sourceId: '', targetId: '', strategy: 'dijkstra' });
      setSelectedKinds(allKinds);
      setSelectedStride([]);
      setSeverity('all');
      setLoadError(null);
      const notice = activated.nodes === 0
        ? {
          kind: 'warning' as const,
          message: `Cenário vazio — verifique o ficheiro data/graph_${id}.json`,
        }
        : {
          kind: 'success' as const,
          message: `Cenário ${id} carregado (${activated.nodes} nós, ${activated.edges} relações)`,
        };
      setScenarioNotice(notice);
      setStatus(notice.message);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Não foi possível carregar o cenário.';
      setScenarioNotice({ kind: 'error', message: `Falha ao mudar de cenário: ${message}` });
      setStatus(`Falha ao mudar de cenário: ${message}`);
    } finally {
      setSwitchingScenarioId(null);
      setIsRefreshing(false);
    }
  }

  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener('keydown', onShortcut);
    return () => window.removeEventListener('keydown', onShortcut);
  }, []);

  function selectNode(id: string) {
    setSelectedNodeId(id);
    setScreen('explorer');
    setBlastResult(null);
    setAttackResult(null);
    setHighlight(null);
    setActionError(null);
    setStatus(`Ativo selecionado: ${id}.`);
  }

  function changeKind(kind: NodeKind, checked: boolean) {
    if (!checked && selectedNode?.kind === kind) setSelectedNodeId(null);
    setSelectedKinds((current) => checked ? [...current, kind] : current.filter((value) => value !== kind));
  }

  function changeStride(stride: string, checked: boolean) {
    setSelectedStride((current) => checked ? [...current, stride] : current.filter((value) => value !== stride));
  }

  async function runBlastRadius(nodeId = selectedNodeId) {
    if (!nodeId) {
      setActionError('Seleciona um ativo antes de calcular o blast radius.');
      setScreen('explorer');
      setStatus('Seleciona um ativo antes de calcular o blast radius.');
      return;
    }
    setScreen('explorer');
    setSelectedNodeId(nodeId);
    setIsBusy(true);
    setActionError(null);
    setAttackResult(null);
    try {
      const result = await getBlastRadius(nodeId, 3, true);
      const nodeIds = [...new Set([result.root_id, ...result.nodes.map((node) => node.id)])];
      const affected = new Set(nodeIds);
      const edgeIds = graph.edges.flatMap((edge, index) =>
        affected.has(edge.source) && affected.has(edge.target) ? [edgeKey(edge, index)] : [],
      );
      setBlastResult(result);
      setHighlight({
        kind: 'blast',
        nodeIds,
        edgeIds,
        rootNodeId: result.root_id,
        depths: result.depth_map,
      });
      setStatus(`Blast radius: ${result.nodes.length} nós, risco agregado ${result.risk_score.toFixed(2)}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Erro ao calcular o blast radius.';
      setActionError(message);
      setStatus(message);
    } finally {
      setIsBusy(false);
    }
  }

  async function runAttackPaths(request: AttackPathRequest) {
    setIsBusy(true);
    setActionError(null);
    setBlastResult(null);
    try {
      const result = await postAttackPaths(request);
      setAttackResult(result);
      setSelectedNodeId(request.source_id);
      setAttackDialogOpen(false);
      const firstPath = result.paths[0];
      const steps: Record<string, number> = {};
      firstPath?.nodes.forEach((id, index) => { steps[id] = index + 1; });
      const pathNodes = [...new Set(result.paths.flatMap((path) => path.nodes))];
      const pathEdgeIds = new Set<string>();
      const edgeSteps: Record<string, number> = {};
      result.paths.forEach((path) => path.edges.forEach((pathEdge, edgeIndex) => {
        const index = graph.edges.findIndex((edge) =>
          edge.source === pathEdge.source &&
          edge.target === pathEdge.target &&
          edge.relation === pathEdge.relation,
        );
        if (index >= 0) {
          const id = edgeKey(graph.edges[index], index);
          pathEdgeIds.add(id);
          if (path === firstPath) edgeSteps[id] = edgeIndex + 1;
        }
      }));
      setHighlight(pathNodes.length
        ? { kind: 'path', nodeIds: pathNodes, edgeIds: [...pathEdgeIds], steps, edgeSteps }
        : null);
      setScreen('explorer');
      setStatus(`Caminhos calculados: ${result.paths.length} entre ${result.source_id} e ${result.target_id}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Erro ao calcular caminhos de ataque.';
      setActionError(message);
      setStatus(message);
    } finally {
      setIsBusy(false);
    }
  }

  async function reenrich() {
    setIsEnriching(true);
    setEnrichmentMessage(null);
    setEnrichmentError(null);
    try {
      const response = await postCtiEnrichment(graph);
      setGraph(response.graph);
      setEnrichmentMessage(`CTI atualizado para ${response.enriched_count} ativos.`);
      setStatus(`Reenriquecimento CTI concluído para ${response.enriched_count} ativos.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Erro ao reenriquecer o grafo.';
      setEnrichmentError(message);
      setStatus(message);
    } finally {
      setIsEnriching(false);
    }
  }

  async function askGraph(query: string): Promise<RagResponse> {
    setStatus('A pesquisar contexto no grafo…');
    try {
      const response = await postRagQuery({ query, top_k: 5, include_llm_answer: false });
      setStatus(`Pesquisa concluída: ${response.hits.length} resultados.`);
      return response;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Erro ao pesquisar contexto.';
      setStatus(message);
      throw error;
    }
  }

  function openAttackPathDialog() {
    setActionError(null);
    if (selectedNodeId) {
      setAttackPathSelection((current) =>
        current.sourceId ? current : { ...current, sourceId: selectedNodeId },
      );
    }
    setAttackDialogOpen(true);
  }

  function clearBlast() {
    setBlastResult(null);
    setHighlight(null);
    setStatus('Resultado do blast radius fechado.');
  }

  return (
    <Tooltip.Provider>
      <div className="app">
        <header className="app-header">
          <div className="brand-mark" aria-hidden="true">A</div>
          <div className="header-title"><p className="eyebrow">Threat modeling console</p><h1>ArgusLoom</h1></div>
          <div className="header-meta">
            <span className="service-status"><span className={`service-indicator ${health?.status === 'ok' ? 'is-healthy' : ''}`} aria-hidden="true" />{health?.status === 'ok' ? 'API operacional' : 'A verificar API'}</span>
            <span className="count-summary">
              {graph.nodes.length} nós <span aria-hidden="true">·</span> {graph.edges.length} relações
            </span>
            {isRefreshing && <span className="refreshing-label" role="status">A atualizar…</span>}
            {scenarioOptions ? (
              <div className="scenario-control">
                <span className="scenario-label">Cenário:</span>
                <div className="scenario-segmented" role="group" aria-label="Selecionar cenário de demonstração">
                  {scenarioOptions.map((scenario) => (
                    <button
                      className="scenario-button"
                      key={scenario.id}
                      type="button"
                      aria-pressed={currentScenario.id === scenario.id}
                      aria-label={`Ativar cenário ${scenario.id}`}
                      disabled={isSwitchingScenario}
                      onClick={() => void switchScenario(scenario.id)}
                    >
                      {switchingScenarioId === scenario.id
                        ? <><span className="scenario-spinner" aria-hidden="true" />{scenario.id}<span className="sr-only">A carregar cenário</span></>
                        : scenario.id}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <span className="scenario-cli-label">Cenário controlado por CLI</span>
            )}
            <button className="button button-secondary shortcut-button" type="button" onClick={() => setPaletteOpen(true)} aria-keyshortcuts="Control+K Meta+K"><kbd>Ctrl K</kbd><span>Comandos</span></button>
          </div>
        </header>

        {scenarioNotice && (
          <div className={`scenario-notice scenario-notice-${scenarioNotice.kind}`} role={scenarioNotice.kind === 'error' ? 'alert' : 'status'}>
            {scenarioNotice.message}
            <button type="button" className="scenario-notice-close" aria-label="Fechar mensagem" onClick={() => setScenarioNotice(null)}>×</button>
          </div>
        )}

        <main className={`main-content${isRefreshing ? ' is-refreshing' : ''}`} aria-busy={isRefreshing}>
          <Tabs.Root value={screen} onValueChange={(value) => setScreen(value as Screen)}>
            <Tabs.List className="screen-tabs" aria-label="Ecrãs da consola">
              <Tabs.Trigger className="screen-tab" value="overview">Attack surface</Tabs.Trigger>
              <Tabs.Trigger className="screen-tab" value="explorer">Graph Explorer</Tabs.Trigger>
            </Tabs.List>
            {loadError ? (
              <div className="load-error" role="alert">
                <h2>Dados do grafo indisponíveis</h2><p>{loadError}</p>
                <button className="button button-primary" type="button" onClick={() => void loadGraph()}>Tentar novamente</button>
              </div>
            ) : (
              <>
                <Tabs.Content className="screen-content" value="overview">
                  <OverviewScreen
                    graph={graph}
                    reducedMotion={reducedMotion}
                    onSelectNode={selectNode}
                    onAskGraph={askGraph}
                    onReenrich={() => void reenrich()}
                    isEnriching={isEnriching}
                    enrichmentMessage={enrichmentMessage}
                    enrichmentError={enrichmentError}
                  />
                </Tabs.Content>
                <Tabs.Content className="screen-content" value="explorer">
                  <GraphExplorer
                    scenarioId={currentScenario.id}
                    positionCache={scenarioPositionCacheRef.current}
                    graph={graph}
                    nodes={filteredNodes}
                    selectedKinds={selectedKinds}
                    onKindChange={changeKind}
                    selectedStride={selectedStride}
                    onStrideChange={changeStride}
                    severity={severity}
                    onSeverityChange={setSeverity}
                    selectedNode={selectedNode}
                    onSelectNode={selectNode}
                    onRefresh={() => void loadGraph()}
                    isRefreshing={isRefreshing}
                    isBusy={isBusy}
                    onBlastRadius={() => void runBlastRadius()}
                    blastResult={blastResult}
                    onClearBlast={clearBlast}
                    onOpenAttackPaths={openAttackPathDialog}
                    attackDialogOpen={attackDialogOpen}
                    onAttackDialogOpenChange={setAttackDialogOpen}
                    attackPathSelection={attackPathSelection}
                    setAttackPathSelection={setAttackPathSelection}
                    onCalculateAttackPaths={runAttackPaths}
                    attackResult={attackResult}
                    actionError={actionError}
                    highlight={highlight}
                    reducedMotion={reducedMotion}
                  />
                </Tabs.Content>
              </>
            )}
          </Tabs.Root>
        </main>

        <footer className="status-bar">
          <span className="status-dot" aria-hidden="true" />
          <p role="status" aria-live="polite" aria-atomic="true">{status}</p>
          {loadError && <span className="status-error">Dados indisponíveis</span>}
        </footer>

        <CommandPalette
          nodes={graph.nodes}
          open={paletteOpen}
          onOpenChange={setPaletteOpen}
          onSelectNode={selectNode}
          onBlastRadius={() => void runBlastRadius()}
          onOpenAttackPaths={() => {
            setScreen('explorer');
            openAttackPathDialog();
          }}
          onRefresh={() => void loadGraph()}
        />
      </div>
    </Tooltip.Provider>
  );
}

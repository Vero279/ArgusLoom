import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import type cytoscape from 'cytoscape';
import type { GraphEdge, GraphNode } from '../api';
import {
  deriveFamily,
  deriveRisk,
  familyLabels,
  familySymbols,
  hasCheckovFinding,
  isPoisonedNode,
} from '../visualEncoding';

export interface GraphHighlight {
  kind: 'blast' | 'path';
  nodeIds: string[];
  edgeIds: string[];
  rootNodeId?: string;
  depths?: Record<string, number>;
  steps?: Record<string, number>;
  edgeSteps?: Record<string, number>;
}

export type ScenarioPositionCache = Map<string, Map<string, cytoscape.Position>>;

interface GraphCanvasProps {
  positionCache?: ScenarioPositionCache;
  scenarioId?: string;
  nodes: GraphNode[];
  visibleNodeIds?: string[];
  edges: GraphEdge[];
  highlight: GraphHighlight | null;
  reducedMotion: boolean;
  onSelect: (nodeId: string) => void;
  focusNodeId?: string | null;
  decorative?: boolean;
}

function token(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

export default function GraphCanvas({
  positionCache,
  scenarioId = 'default',
  nodes,
  visibleNodeIds,
  edges,
  highlight,
  reducedMotion,
  onSelect,
  focusNodeId = null,
  decorative = false,
}: GraphCanvasProps) {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const activeLayoutRef = useRef<cytoscape.Layouts | null>(null);
  const localPositionCacheRef = useRef<ScenarioPositionCache>(new Map());
  const positionsByScenario = positionCache ?? localPositionCacheRef.current;
  const activeScenarioIdRef = useRef(scenarioId);
  const lastScenarioIdRef = useRef<string | null>(null);
  const previousVisibleIdsRef = useRef<Set<string> | null>(null);
  const [graphReady, setGraphReady] = useState(false);
  const [tooltip, setTooltip] = useState<{ text: string; x: number; y: number } | null>(null);
  activeScenarioIdRef.current = scenarioId;
  const visibleIds = useMemo(
    () => new Set(visibleNodeIds ?? nodes.map((node) => node.id)),
    [nodes, visibleNodeIds],
  );
  const elements = useMemo<cytoscape.ElementDefinition[]>(() => [
    ...nodes.map((node) => ({
      data: {
        id: node.id,
        label: familySymbols[deriveFamily(node)],
        family: deriveFamily(node),
        risk: deriveRisk(node),
        fullId: node.id,
        kind: node.kind,
        criticality: node.criticality,
        cvss: node.cvss_max,
        exposure: node.exposure,
        poisoned: isPoisonedNode(node),
        checkovFinding: hasCheckovFinding(node),
      },
    })),
    ...edges.map((edge, index) => ({
      data: {
        id: edge.id ?? `${edge.source}::${edge.target}::${index}`,
        source: edge.source,
        target: edge.target,
        relation: edge.relation,
        label: '',
      },
    })),
  ], [edges, nodes]);

  const stylesheet = useMemo<cytoscape.StylesheetJson>(() => [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        width: 'mapData(cvss, 0, 10, 20, 60)',
        height: 'mapData(cvss, 0, 10, 20, 60)',
        'background-color': token('--risk-low', '#6B7280'),
        color: token('--text-primary', '#E8EAED'),
        'font-size': '14px',
        'min-zoomed-font-size': '10px',
        'text-valign': 'center',
        'text-halign': 'center',
        'border-width': 2,
        'border-color': token('--bg-surface', '#1A1D27'),
        'border-style': 'solid',
      },
    },
    { selector: 'node[exposure > 0.7]', style: { 'border-style': 'dashed', 'border-width': 3 } },
    { selector: 'node[checkovFinding = true]', style: { 'border-color': '#FF5A5F', 'border-width': 4, 'border-style': 'dashed' } },
    { selector: 'node[poisoned = true]', style: { 'border-color': '#D946EF', 'border-width': 5, 'border-style': 'double' } },
    { selector: 'node[risk="critical"]', style: { shape: 'ellipse', 'background-color': '#FF5A5F' } },
    { selector: 'node[risk="high"]', style: { shape: 'hexagon', 'background-color': '#FFB020' } },
    { selector: 'node[risk="medium"]', style: { shape: 'rectangle', 'background-color': '#4A9EFF' } },
    { selector: 'node[risk="low"]', style: { shape: 'triangle', 'background-color': '#6B7280' } },
    { selector: 'node[family="network"]', style: { label: '▼' } },
    { selector: 'node[family="compute"]', style: { label: '◆' } },
    { selector: 'node[family="data"]', style: { label: '★' } },
    {
      selector: 'edge',
      style: {
        width: 1,
        'line-style': 'solid',
        'line-color': '#6B7280',
        'target-arrow-color': '#6B7280',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        label: 'data(label)',
        color: token('--text-primary', '#E8EAED'),
        'font-size': '9px',
        'text-background-color': token('--bg-surface', '#1A1D27'),
        'text-background-opacity': 1,
        'text-background-padding': '3px',
      },
    },
    { selector: 'edge[relation="exposes"]', style: { 'line-style': 'dashed', width: 2, 'line-color': '#FF5A5F', 'target-arrow-color': '#FF5A5F' } },
    { selector: 'edge[relation="attached_to"]', style: { 'line-style': 'solid', width: 1, 'line-color': '#9AA0A6', 'target-arrow-color': '#9AA0A6' } },
    { selector: 'edge[relation="depends_on"]', style: { 'line-style': 'dotted', width: 1, 'line-color': '#6B7280', 'target-arrow-color': '#6B7280' } },
    { selector: 'edge[relation="uses_role"]', style: { 'line-style': 'solid', width: 4, 'line-color': '#FFB020', 'target-arrow-color': '#FFB020' } },
    // Cytoscape accepts solid, dotted, and dashed; this custom dash pattern renders dash-dot.
    { selector: 'edge[relation="selects"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [8, 4, 2, 4], width: 2, 'line-color': '#4A9EFF', 'target-arrow-color': '#4A9EFF' } },
    { selector: '.dimmed', style: { opacity: 0.2 } },
    {
      selector: '.blast-highlight',
      style: {
        opacity: 1,
        'border-width': 4,
        'border-color': '#FFB020',
        'line-color': '#FFB020',
        'target-arrow-color': '#FFB020',
        width: '4px',
      },
    },
    { selector: '.blast-root', style: { 'background-color': '#FF5A5F', 'border-color': '#FFFFFF' } },
    { selector: '.blast-depth-1', style: { 'background-color': '#FFB020' } },
    { selector: '.blast-depth-2', style: { 'background-color': '#E88E27' } },
    { selector: '.blast-depth-3', style: { 'background-color': '#C9712B' } },
    {
      selector: '.path-highlight',
      style: {
        opacity: 1,
        'border-width': 4,
        'border-color': token('--focus-ring', '#FFD700'),
        'line-color': token('--focus-ring', '#FFD700'),
        'target-arrow-color': token('--focus-ring', '#FFD700'),
        width: '5px',
      },
    },
  ], []);

  const layoutOptions = useMemo<cytoscape.LayoutOptions>(() => ({
    name: 'cose',
    animate: false,
    fit: true,
    animationDuration: 0,
    nodeRepulsion: () => 4500,
    idealEdgeLength: () => 100,
    padding: 28,
  }), []);
  const presetLayout = useMemo<cytoscape.LayoutOptions>(() => ({ name: 'preset' }), []);

  const rememberPositions = useCallback((cy: cytoscape.Core, forScenarioId: string) => {
    if (forScenarioId !== activeScenarioIdRef.current) return;
    const positions = new Map<string, cytoscape.Position>();
    cy.nodes().forEach((node) => {
      positions.set(node.id(), { ...node.position() });
    });
    positionsByScenario.set(forScenarioId, positions);
  }, [positionsByScenario]);

  const stopActiveLayout = useCallback(() => {
    const activeLayout = activeLayoutRef.current;
    if (!activeLayout) return;
    activeLayoutRef.current = null;
    activeLayout.stop();
  }, []);

  const runLayout = useCallback((forScenarioId = activeScenarioIdRef.current) => {
    const cy = cyRef.current;
    if (!cy) return;
    stopActiveLayout();
    const activeLayout = cy.layout(layoutOptions);
    activeLayoutRef.current = activeLayout;
    activeLayout.one('layoutstop', () => {
      if (activeLayoutRef.current !== activeLayout) return;
      rememberPositions(cy, forScenarioId);
      activeLayoutRef.current = null;
    });
    activeLayout.run();
  }, [layoutOptions, rememberPositions, stopActiveLayout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graphReady || cy.nodes().length === 0) return;
    if (lastScenarioIdRef.current === scenarioId) return;

    stopActiveLayout();
    lastScenarioIdRef.current = scenarioId;
    const savedPositions = positionsByScenario.get(scenarioId);
    if (savedPositions) {
      cy.batch(() => {
        cy.nodes().forEach((node) => {
          const position = savedPositions.get(node.id());
          if (position) node.position(position);
        });
      });
      cy.fit(cy.elements(), 28);
      return;
    }

    runLayout(scenarioId);
  }, [graphReady, nodes, positionsByScenario, runLayout, scenarioId, stopActiveLayout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graphReady) return;

    const previousVisibleIds = previousVisibleIdsRef.current;
    if (!previousVisibleIds) {
      const allNodeIds = new Set(cy.nodes().map((node) => node.id()));
      previousVisibleIdsRef.current = allNodeIds;
      if (allNodeIds.size === visibleIds.size && [...allNodeIds].every((id) => visibleIds.has(id))) return;
    }
    if (
      previousVisibleIds &&
      previousVisibleIds.size === visibleIds.size &&
      [...previousVisibleIds].every((id) => visibleIds.has(id))
    ) return;

    stopActiveLayout();

    cy.batch(() => {
      cy.nodes().forEach((node) => {
        node.style('display', visibleIds.has(node.id()) ? 'element' : 'none');
      });
      cy.edges().forEach((edge) => {
        const endpointsVisible = visibleIds.has(edge.source().id()) && visibleIds.has(edge.target().id());
        edge.style('display', endpointsVisible ? 'element' : 'none');
      });
    });

    previousVisibleIdsRef.current = visibleIds;
  }, [graphReady, visibleIds]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.nodes().forEach((node) => {
      node.data('displayLabel', node.data('label'));
      node.removeClass('blast-root blast-depth-1 blast-depth-2 blast-depth-3');
    });
    cy.edges().forEach((edge) => {
      edge.data('pathLabel', '');
      edge.data('label', '');
    });
    cy.elements().removeClass('dimmed blast-highlight path-highlight');
    if (!highlight) return;

    cy.elements().addClass('dimmed');
    const highlighted = cy.collection();
    highlight.nodeIds.forEach((id) => {
      const element = cy.getElementById(id);
      if (element.length > 0) highlighted.merge(element);
    });
    highlight.edgeIds.forEach((id) => {
      const element = cy.getElementById(id);
      if (element.length > 0) highlighted.merge(element);
    });
    if (highlight.kind === 'blast') {
      highlight.nodeIds.forEach((id) => {
        const node = cy.getElementById(id);
        const depth = highlight.depths?.[id] ?? (id === highlight.rootNodeId ? 0 : 1);
        if (id === highlight.rootNodeId) node.addClass('blast-root');
        else node.addClass(`blast-depth-${Math.min(depth, 3)}`);
      });
    }
    if (highlight.steps) {
      Object.entries(highlight.steps).forEach(([id, step]) => {
        const node = cy.getElementById(id);
        if (node.length > 0) node.data('displayLabel', `${step}. ${node.data('label')}`);
      });
    }
    if (highlight.edgeSteps) {
      Object.entries(highlight.edgeSteps).forEach(([id, step]) => {
        const edge = cy.getElementById(id);
        if (edge.length > 0) {
          const label = `${step}. ${edge.data('relation')}`;
          edge.data('pathLabel', label);
          edge.data('label', label);
        }
      });
    }
    highlighted.removeClass('dimmed').addClass(
      highlight.kind === 'blast' ? 'blast-highlight' : 'path-highlight',
    );

    if (highlight.kind === 'path' && !reducedMotion) {
      const pathEdges = highlight.edgeIds.map((id) => cy.getElementById(id)).filter((edge) => edge.length > 0);
      const pulseAt = (index: number) => {
        if (index >= pathEdges.length || cyRef.current !== cy) return;
        pathEdges[index].animate(
          { style: { opacity: 0.2 } },
          {
            duration: 260,
            complete: () => pathEdges[index].animate({ style: { opacity: 1 } }, {
              duration: 260,
              complete: () => pulseAt(index + 1),
            }),
          },
        );
      };
      pulseAt(0);
    }

    return () => {
      cy.stop(true);
    };
  }, [highlight, reducedMotion]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !focusNodeId) return;
    const node = cy.getElementById(focusNodeId);
    if (node.length > 0) {
      if (reducedMotion) cy.center(node);
      else cy.animate({ center: { eles: node } }, { duration: 320 });
    }
  }, [focusNodeId, reducedMotion, nodes]);

  function registerGraph(instance: cytoscape.Core) {
    if (cyRef.current === instance) return;
    cyRef.current = instance;
    setGraphReady(true);
    if (!decorative) {
      instance.on('dragfree', 'node', (event) => {
        const node = event.target;
        const currentScenarioId = activeScenarioIdRef.current;
        const positions = positionsByScenario.get(currentScenarioId) ?? new Map(
          instance.nodes().map((currentNode) => [currentNode.id(), { ...currentNode.position() }]),
        );
        positions.set(node.id(), { ...node.position() });
        positionsByScenario.set(currentScenarioId, positions);
      });
      instance.on('tap', 'node', (event) => onSelect(event.target.id()));
      instance.on('mouseover', 'edge', (event) => {
        event.target.data('label', event.target.data('relation'));
      });
      instance.on('mouseout', 'edge', (event) => {
        event.target.data('label', event.target.data('pathLabel') ?? '');
      });
      instance.on('mouseover', 'node', (event) => {
        const position = event.renderedPosition ?? event.position;
        const nodeData = event.target.data();
        const family = deriveFamily({ kind: nodeData.kind });
        setTooltip({
          text: `${nodeData.fullId} · ${nodeData.kind} · ${familyLabels[family]}${nodeData.poisoned ? ' · CTI envenenada' : ''}${nodeData.checkovFinding ? ' · finding Checkov' : ''}`,
          x: position.x,
          y: position.y,
        });
      });
      instance.on('mouseout', 'node', () => setTooltip(null));
    }
  }

  return (
    <div
      className={`graph-canvas${decorative ? ' graph-canvas-decorative' : ''}`}
      role={decorative ? undefined : 'group'}
      aria-label={decorative ? undefined : 'Grafo visual; use o modo Lista para navegar por teclado'}
      aria-hidden={decorative ? true : undefined}
    >
      <CytoscapeComponent
        elements={elements}
        stylesheet={stylesheet}
        layout={presetLayout}
        cy={registerGraph}
        minZoom={0.3}
        maxZoom={2.5}
        userZoomingEnabled={!decorative}
        userPanningEnabled={!decorative}
        style={{ width: '100%', height: '100%' }}
      />
      {!decorative && (
        <button className="button button-secondary relayout-button" type="button" onClick={() => runLayout()}>
          Re-layout
        </button>
      )}
      {nodes.length === 0 && <p className="empty-state graph-empty">Nenhum nó corresponde aos filtros atuais.</p>}
      {tooltip && !decorative && <div className="graph-tooltip" style={{ left: tooltip.x, top: tooltip.y }}>{tooltip.text}</div>}
    </div>
  );
}

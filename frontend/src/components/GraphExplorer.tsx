import { useMemo, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import type {
  AttackPathRequest,
  AttackPathResponse,
  AttackPathSelection,
  BlastRadiusResponse,
  Criticality,
  GraphData,
  GraphNode,
  NodeKind,
} from '../api';
import AttackPathDialog from './AttackPathDialog';
import BlastRadiusPanel from './BlastRadiusPanel';
import DetailPanel from './DetailPanel';
import GraphCanvas from './GraphCanvas';
import type { GraphHighlight, ScenarioPositionCache } from './GraphCanvas';
import NodeList from './NodeList';
import Sidebar from './Sidebar';

interface GraphExplorerProps {
  scenarioId: string;
  positionCache: ScenarioPositionCache;
  graph: GraphData;
  nodes: GraphNode[];
  selectedKinds: NodeKind[];
  onKindChange: (kind: NodeKind, checked: boolean) => void;
  selectedStride: string[];
  onStrideChange: (stride: string, checked: boolean) => void;
  severity: 'all' | Criticality;
  onSeverityChange: (severity: 'all' | Criticality) => void;
  selectedNode: GraphNode | null;
  onSelectNode: (id: string) => void;
  onRefresh: () => void;
  isRefreshing: boolean;
  isBusy: boolean;
  onBlastRadius: () => void;
  blastResult: BlastRadiusResponse | null;
  onClearBlast: () => void;
  onOpenAttackPaths: () => void;
  attackDialogOpen: boolean;
  onAttackDialogOpenChange: (open: boolean) => void;
  attackPathSelection: AttackPathSelection;
  setAttackPathSelection: Dispatch<SetStateAction<AttackPathSelection>>;
  onCalculateAttackPaths: (request: AttackPathRequest) => Promise<void>;
  attackResult: AttackPathResponse | null;
  actionError: string | null;
  highlight: GraphHighlight | null;
  reducedMotion: boolean;
}

export default function GraphExplorer(props: GraphExplorerProps) {
  const [view, setView] = useState('graph');
  const visibleIds = useMemo(() => new Set(props.nodes.map((node) => node.id)), [props.nodes]);
  const visibleNodeIds = useMemo(() => [...visibleIds], [visibleIds]);
  const graphNodeIds = useMemo(() => new Set(props.graph.nodes.map((node) => node.id)), [props.graph.nodes]);
  const edges = useMemo(
    () => props.graph.edges.flatMap((edge, index) =>
      graphNodeIds.has(edge.source) && graphNodeIds.has(edge.target)
        ? [{ ...edge, id: `${edge.source}::${edge.target}::${index}` }]
        : [],
    ),
    [props.graph.edges, graphNodeIds],
  );

  return (
    <section className="explorer-layout" aria-label="Explorador de attack paths">
      <Sidebar
        selectedKinds={props.selectedKinds}
        onKindChange={props.onKindChange}
        selectedStride={props.selectedStride}
        onStrideChange={props.onStrideChange}
        severity={props.severity}
        onSeverityChange={props.onSeverityChange}
        onRefresh={props.onRefresh}
        isRefreshing={props.isRefreshing}
      />
      <section className="workspace explorer-workspace" aria-labelledby="explorer-heading">
        <div className="workspace-toolbar">
          <div>
            <p className="eyebrow">02 / Attack paths</p>
            <h2 id="explorer-heading">Explorador de relações</h2>
          </div>
          <Tabs.Root className="view-tabs" value={view} onValueChange={setView}>
            <Tabs.List className="tabs-list" aria-label="Modo de visualização">
              <Tabs.Trigger className="tab-trigger" value="graph">Grafo</Tabs.Trigger>
              <Tabs.Trigger className="tab-trigger" value="list">Lista</Tabs.Trigger>
            </Tabs.List>
            <Tabs.Content className="view-content" value="graph">
              <div className="visual-panel">
                <GraphCanvas
                  positionCache={props.positionCache}
                  scenarioId={props.scenarioId}
                  nodes={props.graph.nodes}
                  visibleNodeIds={visibleNodeIds}
                  edges={edges}
                  highlight={props.highlight}
                  reducedMotion={props.reducedMotion}
                  onSelect={props.onSelectNode}
                  focusNodeId={props.selectedNode?.id}
                />
              </div>
            </Tabs.Content>
            <Tabs.Content className="view-content" value="list">
              <div className="visual-panel list-panel">
                <NodeList nodes={props.nodes} onSelect={props.onSelectNode} selectedNodeId={props.selectedNode?.id ?? null} />
              </div>
            </Tabs.Content>
          </Tabs.Root>
          {(props.highlight?.kind === 'blast' || props.highlight?.kind === 'path') && (
            <p className="canvas-legend" aria-live="polite">
              {props.highlight.kind === 'blast'
                ? 'Cores por profundidade do impacto'
                : 'Passos numerados no caminho'}
            </p>
          )}
        </div>
      </section>
      {props.blastResult ? (
        <BlastRadiusPanel result={props.blastResult} graph={props.graph} onClose={props.onClearBlast} onSelectNode={props.onSelectNode} />
      ) : (
        <DetailPanel
          node={props.selectedNode}
          graph={props.graph}
          onBlastRadius={props.onBlastRadius}
          onOpenAttackPaths={props.onOpenAttackPaths}
          attackResult={props.attackResult}
          actionError={props.actionError}
          isBusy={props.isBusy}
        />
      )}
      <AttackPathDialog
        graph={props.graph}
        attackPathSelection={props.attackPathSelection}
        setAttackPathSelection={props.setAttackPathSelection}
        onCalculate={props.onCalculateAttackPaths}
        isCalculating={props.isBusy}
        open={props.attackDialogOpen}
        onOpenChange={props.onAttackDialogOpenChange}
      />
    </section>
  );
}

import { useEffect, useMemo, useState } from 'react';
import type { Dispatch, FormEvent, SetStateAction } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import * as Select from '@radix-ui/react-select';
import type { AttackPathRequest, AttackPathSelection, GraphData, GraphNode } from '../api';
import { getReachableNodeIds, getSourceNodeIds } from '../graphReachability';

interface AttackPathDialogProps {
  graph: GraphData;
  attackPathSelection: AttackPathSelection;
  setAttackPathSelection: Dispatch<SetStateAction<AttackPathSelection>>;
  onCalculate: (request: AttackPathRequest) => Promise<void>;
  isCalculating: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const ANY_SOURCE = '__argusloom_any_source__';
const ANY_TARGET = '__argusloom_any_target__';
const NO_REACHABLE_SOURCE = '__argusloom_no_reachable_source__';
const NO_REACHABLE_TARGET = '__argusloom_no_reachable_target__';
const SOURCE_HINT = 'Nenhuma origem alcançável';
const TARGET_HINT = 'Nenhum destino alcançável';

function NodeSelect({
  id,
  label,
  anyLabel,
  value,
  nodes,
  emptyNodesLabel,
  emptyNodesReason,
  onValueChange,
}: {
  id: string;
  label: string;
  anyLabel: string;
  value: string;
  nodes: GraphNode[];
  emptyNodesLabel: string;
  emptyNodesReason: string;
  onValueChange: (value: string) => void;
}) {
  const anyValue = id === 'source' ? ANY_SOURCE : ANY_TARGET;
  const selectedValue = value || anyValue;

  return (
    <div className="form-field">
      <span className="form-label" id={`${id}-label`}>{label}</span>
      <Select.Root
        value={selectedValue}
        onValueChange={(nextValue) => onValueChange(nextValue === anyValue ? '' : nextValue)}
      >
        <Select.Trigger className="select-trigger" aria-labelledby={`${id}-label`}>
          <Select.Value placeholder={anyLabel} />
          <Select.Icon aria-hidden="true">⌄</Select.Icon>
        </Select.Trigger>
        <Select.Portal>
          <Select.Content className="select-content" position="popper">
            <Select.Viewport>
              <Select.Item className="select-item select-any-item" value={anyValue}>
                <Select.ItemText>{anyLabel}</Select.ItemText>
              </Select.Item>
              {nodes.length === 0 && (
                <Select.Item
                  className="select-item select-item-disabled"
                  value={id === 'source' ? NO_REACHABLE_SOURCE : NO_REACHABLE_TARGET}
                  disabled
                  title={emptyNodesReason}
                >
                  <Select.ItemText>{emptyNodesLabel}</Select.ItemText>
                  <span className="select-option-help" aria-hidden="true" title={emptyNodesReason}>ⓘ</span>
                </Select.Item>
              )}
              {nodes.map((node) => (
                <Select.Item className="select-item" key={node.id} value={node.id}>
                  <Select.ItemText>{node.id}</Select.ItemText>
                </Select.Item>
              ))}
            </Select.Viewport>
          </Select.Content>
        </Select.Portal>
      </Select.Root>
      {nodes.length === 0 && <span className="form-hint">{emptyNodesReason}</span>}
    </div>
  );
}

export default function AttackPathDialog({
  graph,
  attackPathSelection,
  setAttackPathSelection,
  onCalculate,
  isCalculating,
  open,
  onOpenChange,
}: AttackPathDialogProps) {
  const [topK, setTopK] = useState(3);
  const [selectionHint, setSelectionHint] = useState('');
  const { sourceId, targetId, strategy } = attackPathSelection;
  const sourceIdsForTarget = useMemo(
    () => targetId ? getSourceNodeIds(graph, targetId) : null,
    [graph, targetId],
  );
  const targetIdsForSource = useMemo(
    () => sourceId ? getReachableNodeIds(graph, sourceId) : null,
    [graph, sourceId],
  );
  const sourceOptions = useMemo(
    () => graph.nodes.filter((node) => !sourceIdsForTarget || sourceIdsForTarget.has(node.id)),
    [graph.nodes, sourceIdsForTarget],
  );
  const targetOptions = useMemo(
    () => graph.nodes.filter((node) => !targetIdsForSource || targetIdsForSource.has(node.id)),
    [graph.nodes, targetIdsForSource],
  );

  useEffect(() => {
    if (!selectionHint) return;
    const timer = window.setTimeout(() => setSelectionHint(''), 3500);
    return () => window.clearTimeout(timer);
  }, [selectionHint]);

  function changeSource(nextSourceId: string) {
    const shouldClearTarget = Boolean(
      targetId &&
      nextSourceId &&
      !getReachableNodeIds(graph, nextSourceId).has(targetId),
    );
    setAttackPathSelection((current) => ({
      ...current,
      sourceId: nextSourceId,
      targetId: shouldClearTarget ? '' : current.targetId,
    }));
    setSelectionHint('');
    if (shouldClearTarget) {
      setSelectionHint('O destino anterior não é alcançável a partir desta origem');
    }
  }

  function changeTarget(nextTargetId: string) {
    const shouldClearSource = Boolean(
      nextTargetId &&
      sourceId &&
      !getSourceNodeIds(graph, nextTargetId).has(sourceId),
    );
    setAttackPathSelection((current) => ({
      ...current,
      targetId: nextTargetId,
      sourceId: shouldClearSource ? '' : current.sourceId,
    }));
    setSelectionHint('');
    if (shouldClearSource) {
      setSelectionHint('A origem anterior não alcança este destino');
    }
  }

  function handleOpenChange(nextOpen: boolean) {
    if (nextOpen) setSelectionHint('');
    onOpenChange(nextOpen);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!sourceId || !targetId) return;
    await onCalculate({
      source_id: sourceId,
      target_id: targetId,
      strategy,
      top_k: strategy === 'dijkstra' ? 1 : topK,
    });
  }

  const sourceReason = targetId
    ? 'Não existem nós no grafo que alcancem o destino selecionado.'
    : 'Seleciona um destino para filtrar as origens alcançáveis.';
  const targetReason = sourceId
    ? 'A origem selecionada não tem destinos alcançáveis no grafo.'
    : 'Seleciona uma origem para filtrar os destinos alcançáveis.';

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="dialog-content" aria-describedby="attack-dialog-description">
          <div className="dialog-heading">
            <div><p className="eyebrow">Percurso de exploração</p><Dialog.Title className="dialog-title">Caminhos de ataque</Dialog.Title></div>
            <Dialog.Close asChild><button className="icon-button" type="button" aria-label="Fechar diálogo">×</button></Dialog.Close>
          </div>
          <Dialog.Description id="attack-dialog-description" className="dialog-description">
            Define origem e destino. As opções são limitadas a ativos ligados por um caminho no grafo.
          </Dialog.Description>
          <form className="dialog-form" onSubmit={(event) => void submit(event)}>
            <NodeSelect
              id="source"
              label="Ativo de origem"
              anyLabel="— Qualquer origem —"
              value={sourceId}
              nodes={sourceOptions}
              emptyNodesLabel={SOURCE_HINT}
              emptyNodesReason={sourceReason}
              onValueChange={changeSource}
            />
            <NodeSelect
              id="target"
              label="Ativo de destino"
              anyLabel="— Qualquer destino —"
              value={targetId}
              nodes={targetOptions}
              emptyNodesLabel={TARGET_HINT}
              emptyNodesReason={targetReason}
              onValueChange={changeTarget}
            />
            {selectionHint && <p className="selection-hint" role="status">{selectionHint}</p>}
            <fieldset className="strategy-fieldset">
              <legend>Estratégia de caminhos</legend>
              <div className="strategy-toggle">
                <button className="strategy-option" type="button" aria-pressed={strategy === 'dijkstra'} onClick={() => setAttackPathSelection((current) => ({ ...current, strategy: 'dijkstra' }))}>Dijkstra (melhor caminho)</button>
                <button className="strategy-option" type="button" aria-pressed={strategy === 'yen'} onClick={() => setAttackPathSelection((current) => ({ ...current, strategy: 'yen' }))}>Yen (K melhores caminhos)</button>
              </div>
            </fieldset>
            {strategy === 'yen' ? (
              <label className="form-field">
                <span className="form-label">Número máximo de caminhos (1–10)</span>
                <input className="text-input" type="number" min={1} max={10} value={topK} onChange={(event) => setTopK(Number(event.currentTarget.value))} required />
              </label>
            ) : (
              <p className="form-hint" title="Dijkstra devolve sempre 1 caminho">Número de caminhos: 1 — Dijkstra devolve sempre 1 caminho.</p>
            )}
            <p className="form-hint" aria-live="polite">
              {!sourceId || !targetId ? 'Selecione origem e destino para calcular' : 'O par selecionado tem um caminho no grafo.'}
            </p>
            <div className="dialog-actions">
              <Dialog.Close asChild><button className="button button-secondary" type="button">Cancelar</button></Dialog.Close>
              <button className="button button-primary" type="submit" disabled={!sourceId || !targetId || (strategy === 'yen' && (topK < 1 || topK > 10)) || isCalculating}>
                {isCalculating ? 'A calcular…' : 'Calcular'}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

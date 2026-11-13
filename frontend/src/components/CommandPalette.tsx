import { useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import type { GraphNode } from '../api';

interface CommandPaletteProps {
  nodes: GraphNode[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelectNode: (id: string) => void;
  onBlastRadius: () => void;
  onOpenAttackPaths: () => void;
  onRefresh: () => void;
}

export default function CommandPalette({
  nodes,
  open,
  onOpenChange,
  onSelectNode,
  onBlastRadius,
  onOpenAttackPaths,
  onRefresh,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const matches = useMemo(() => {
    const term = query.trim().toLowerCase();
    return term ? nodes.filter((node) => node.id.toLowerCase().includes(term)).slice(0, 8) : nodes.slice(0, 8);
  }, [nodes, query]);

  useEffect(() => {
    if (!open) setQuery('');
  }, [open]);

  function run(action: () => void) {
    onOpenChange(false);
    action();
  }

  function onInputKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter' && matches.length > 0) {
      event.preventDefault();
      run(() => onSelectNode(matches[0].id));
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay palette-overlay" />
        <Dialog.Content className="command-dialog" aria-describedby="command-description" onOpenAutoFocus={(event) => {
          event.preventDefault();
          inputRef.current?.focus();
        }}>
          <div className="command-heading">
            <Dialog.Title className="visually-hidden">Paleta de comandos</Dialog.Title>
            <label className="visually-hidden" htmlFor="command-search">Pesquisar ativo ou comando</label>
            <input
              ref={inputRef}
              id="command-search"
              className="command-input"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
              onKeyDown={onInputKeyDown}
              placeholder="Pesquisar ativo ou comando…"
              autoComplete="off"
            />
            <Dialog.Close asChild><button className="icon-button" type="button" aria-label="Fechar paleta">×</button></Dialog.Close>
          </div>
          <Dialog.Description id="command-description" className="visually-hidden">
            Pesquisa nós e ações. Usa as setas e Enter para selecionar.
          </Dialog.Description>
          <div className="command-list">
            <p className="command-group-title">Ativos</p>
            {matches.map((node) => (
              <button className="command-item" key={node.id} type="button" onClick={() => run(() => onSelectNode(node.id))}>
                <code>{node.id}</code><span>{node.kind} · {node.criticality}</span>
              </button>
            ))}
            {matches.length === 0 && <p className="muted-copy command-empty">Nenhum ativo corresponde à pesquisa.</p>}
            <p className="command-group-title">Ações</p>
            <button className="command-item" type="button" onClick={() => run(onBlastRadius)}>Ir para: Blast Radius</button>
            <button className="command-item" type="button" onClick={() => run(onOpenAttackPaths)}>Ir para: Attack Paths</button>
            <button className="command-item" type="button" onClick={() => run(onRefresh)}>Atualizar grafo</button>
          </div>
          <p className="command-hint"><kbd>Ctrl</kbd> + <kbd>K</kbd> para abrir <span aria-hidden="true">·</span> <kbd>Esc</kbd> para fechar</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

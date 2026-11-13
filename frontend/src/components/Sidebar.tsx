import * as Select from '@radix-ui/react-select';
import type { Criticality, NodeKind } from '../api';

const nodeKinds: { kind: NodeKind; label: string }[] = [
  { kind: 'compute', label: 'Computação' },
  { kind: 'storage', label: 'Armazenamento' },
  { kind: 'network', label: 'Rede' },
  { kind: 'iam', label: 'Identidade e acesso' },
  { kind: 'data', label: 'Dados' },
  { kind: 'external', label: 'Externo' },
];

const strideKinds = [
  ['spoofing', 'Spoofing'],
  ['tampering', 'Tampering'],
  ['repudiation', 'Repudiation'],
  ['information_disclosure', 'Information disclosure'],
  ['denial_of_service', 'Denial of service'],
  ['elevation_of_privilege', 'Elevation of privilege'],
];

const riskLegend = [
  ['critical', 'ellipse', 'Crítica — elipse, vermelho'],
  ['high', 'hexagon', 'Alta — hexágono, âmbar'],
  ['medium', 'rectangle', 'Média — retângulo, azul'],
  ['low', 'triangle', 'Baixa — triângulo, cinzento'],
] as const;

const familyLegend = [
  ['network', '▼', 'Rede / externo — network, external'],
  ['compute', '◆', 'Computação / armazenamento — compute, storage'],
  ['data', '★', 'Dados / identidade e acesso — data, iam'],
] as const;

interface SidebarProps {
  selectedKinds: NodeKind[];
  onKindChange: (kind: NodeKind, checked: boolean) => void;
  selectedStride: string[];
  onStrideChange: (stride: string, checked: boolean) => void;
  severity: 'all' | Criticality;
  onSeverityChange: (severity: 'all' | Criticality) => void;
  onRefresh: () => void;
  isRefreshing: boolean;
}

export default function Sidebar({
  selectedKinds,
  onKindChange,
  selectedStride,
  onStrideChange,
  severity,
  onSeverityChange,
  onRefresh,
  isRefreshing,
}: SidebarProps) {
  return (
    <aside className="panel sidebar-panel" aria-labelledby="filters-heading">
      <div className="panel-heading">
        <p className="eyebrow">Attack surface</p>
        <h2 id="filters-heading">Filtros</h2>
      </div>
      <fieldset className="filter-fieldset">
        <legend>Tipo de ativo</legend>
        {nodeKinds.map(({ kind, label }) => (
          <label className="checkbox-row" key={kind}>
            <input type="checkbox" checked={selectedKinds.includes(kind)} onChange={(event) => onKindChange(kind, event.currentTarget.checked)} />
            <span>{label}</span>
          </label>
        ))}
      </fieldset>
      <fieldset className="filter-fieldset stride-filters">
        <legend>STRIDE</legend>
        {strideKinds.map(([kind, label]) => (
          <label className="checkbox-row" key={kind}>
            <input type="checkbox" checked={selectedStride.includes(kind)} onChange={(event) => onStrideChange(kind, event.currentTarget.checked)} />
            <span>{label}</span>
          </label>
        ))}
      </fieldset>
      <div className="form-field severity-filter">
        <span className="form-label" id="severity-label">Severidade</span>
        <Select.Root value={severity} onValueChange={(value) => onSeverityChange(value as 'all' | Criticality)}>
          <Select.Trigger className="select-trigger" aria-labelledby="severity-label">
            <Select.Value />
            <Select.Icon aria-hidden="true">⌄</Select.Icon>
          </Select.Trigger>
          <Select.Portal>
            <Select.Content className="select-content" position="popper">
              <Select.Viewport>
                <Select.Item className="select-item" value="all"><Select.ItemText>Todas</Select.ItemText></Select.Item>
                <Select.Item className="select-item" value="critical"><Select.ItemText>Crítica</Select.ItemText></Select.Item>
                <Select.Item className="select-item" value="high"><Select.ItemText>Alta</Select.ItemText></Select.Item>
                <Select.Item className="select-item" value="medium"><Select.ItemText>Média</Select.ItemText></Select.Item>
                <Select.Item className="select-item" value="low"><Select.ItemText>Baixa</Select.ItemText></Select.Item>
              </Select.Viewport>
            </Select.Content>
          </Select.Portal>
        </Select.Root>
      </div>
      <button className="button button-secondary refresh-button" type="button" onClick={onRefresh} disabled={isRefreshing}>
        <span aria-hidden="true">↻</span>
        {isRefreshing ? 'A atualizar…' : 'Atualizar grafo'}
      </button>
      <section className="visual-legend" aria-label="Legenda do grafo">
        <div>
          <h3>Risco</h3>
          {riskLegend.map(([risk, shape, label]) => (
            <dl className="legend-entry" key={risk}>
              <dt aria-hidden="true"><span className={`risk-shape risk-shape-${shape} risk-shape-${risk}`} /></dt>
              <dd>{label}</dd>
            </dl>
          ))}
          <dl className="legend-entry">
            <dt aria-hidden="true"><span className="relation-swatch exposure-swatch exposure-dashed" /></dt>
            <dd>Borda tracejada — exposição acima de 0,7</dd>
          </dl>
          <dl className="legend-entry">
            <dt aria-hidden="true"><span className="relation-swatch exposure-swatch exposure-solid" /></dt>
            <dd>Borda sólida — exposição igual ou abaixo de 0,7</dd>
          </dl>
        </div>
        <div>
          <h3>Tipo</h3>
          {familyLegend.map(([family, symbol, label]) => (
            <dl className="legend-entry" key={family}>
              <dt aria-hidden="true"><span className="family-symbol">{symbol}</span></dt>
              <dd>{label}</dd>
            </dl>
          ))}
        </div>
        <div>
          <h3>Relações</h3>
          <dl className="legend-entry"><dt aria-hidden="true"><span className="relation-swatch relation-exposes" /></dt><dd>Exposes — tracejado vermelho, 2 px</dd></dl>
          <dl className="legend-entry"><dt aria-hidden="true"><span className="relation-swatch relation-attached" /></dt><dd>Attached to — contínuo cinzento, 1 px</dd></dl>
          <dl className="legend-entry"><dt aria-hidden="true"><span className="relation-swatch relation-depends" /></dt><dd>Depends on — pontilhado cinzento, 1 px</dd></dl>
          <dl className="legend-entry"><dt aria-hidden="true"><span className="relation-swatch relation-role" /></dt><dd>Uses role — contínuo âmbar, 4 px</dd></dl>
          <dl className="legend-entry"><dt aria-hidden="true"><span className="relation-swatch relation-selects" /></dt><dd>Selects — traço-ponto azul, 2 px</dd></dl>
        </div>
      </section>
    </aside>
  );
}

import * as Tooltip from '@radix-ui/react-tooltip';
import { strideExplanations, strideLabels } from '../security';

export default function StrideBadge({
  value,
  inferred = false,
}: {
  value: string;
  inferred?: boolean;
}) {
  const label = strideLabels[value] ?? value.replace(/_/g, ' ');
  const explanation = strideExplanations[value] ?? 'Categoria de ameaça STRIDE associada ao ativo.';
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <span className="stride-badge" tabIndex={0}>
          {label}
          {inferred && <span className="inferred-mark" aria-label="inferida pelo tipo de nó">~</span>}
        </span>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className="tooltip-content" side="top">
          {explanation}{inferred ? ' Inferida pelo tipo de nó.' : ''}
          <Tooltip.Arrow className="tooltip-arrow" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

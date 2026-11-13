import type { Criticality } from '../api';
import { criticalityCopy } from '../security';

export default function RiskBadge({ value }: { value: Criticality }) {
  const { label, icon } = criticalityCopy[value];
  return (
    <span className={`risk-label risk-${value}`}>
      <span aria-hidden="true">{icon}</span>
      <span>{label}</span>
    </span>
  );
}

import type { Criticality, GraphNode, NodeKind } from './api';

export type VisualRisk = Criticality;
export type NodeFamily = 'network' | 'compute' | 'data';

export const riskLabels: Record<VisualRisk, string> = {
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Média',
  low: 'Baixa',
};

export const familyLabels: Record<NodeFamily, string> = {
  network: 'Rede e externo',
  compute: 'Computação e armazenamento',
  data: 'Dados e identidade/acesso',
};

export const familySymbols: Record<NodeFamily, string> = {
  network: '▼',
  compute: '◆',
  data: '★',
};

export function deriveRisk(node: Pick<GraphNode, 'cvss_max' | 'criticality'>): VisualRisk {
  // A positive CVSS score takes precedence; criticality is the fallback without one.
  if (node.cvss_max > 0) {
    if (node.cvss_max >= 9.0) return 'critical';
    if (node.cvss_max >= 7.0) return 'high';
    if (node.cvss_max >= 4.0) return 'medium';
    return 'low';
  }
  return node.criticality;
}

export function deriveFamily(node: Pick<GraphNode, 'kind'>): NodeFamily {
  const kind: NodeKind = node.kind;
  if (kind === 'network' || kind === 'external') return 'network';
  if (kind === 'compute' || kind === 'storage') return 'compute';
  return 'data';
}

export function isPoisonedNode(node: Pick<GraphNode, 'metadata'>): boolean {
  return node.metadata?.poisoned === true;
}

export function hasCheckovFinding(node: Pick<GraphNode, 'metadata'>): boolean {
  const findings = node.metadata?.checkov_findings;
  return Array.isArray(findings) && findings.length > 0;
}

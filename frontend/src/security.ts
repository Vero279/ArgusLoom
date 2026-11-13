import type {
  Criticality,
  GraphData,
  GraphNode,
  TechniqueRecord,
} from './api';

export const criticalityCopy: Record<Criticality, { label: string; icon: string }> = {
  critical: { label: 'Crítica', icon: '⬤' },
  high: { label: 'Alta', icon: '▲' },
  medium: { label: 'Média', icon: '◆' },
  low: { label: 'Baixa', icon: '●' },
};

export const strideLabels: Record<string, string> = {
  spoofing: 'Spoofing',
  tampering: 'Tampering',
  repudiation: 'Repudiation',
  information_disclosure: 'Information disclosure',
  denial_of_service: 'Denial of service',
  elevation_of_privilege: 'Elevation of privilege',
};

export const strideExplanations: Record<string, string> = {
  spoofing: 'Identidade ou credenciais podem ser falsificadas.',
  tampering: 'A integridade dos dados ou configurações pode ser alterada.',
  repudiation: 'Ações podem não deixar evidências auditáveis suficientes.',
  information_disclosure: 'Dados podem ser expostos a utilizadores não autorizados.',
  denial_of_service: 'O serviço pode ficar indisponível ou degradado.',
  elevation_of_privilege: 'Um atacante pode obter permissões superiores.',
};

const defaultStride: Record<GraphNode['kind'], string[]> = {
  network: ['information_disclosure', 'tampering', 'denial_of_service'],
  data: ['tampering', 'information_disclosure', 'repudiation'],
  storage: ['information_disclosure', 'tampering'],
  iam: ['spoofing', 'elevation_of_privilege'],
  compute: ['denial_of_service', 'elevation_of_privilege'],
  external: ['information_disclosure'],
};

const criticalityWeight: Record<Criticality, number> = {
  low: 1,
  medium: 2.5,
  high: 4,
  critical: 5.5,
};

const kindWeight: Record<GraphNode['kind'], number> = {
  compute: 1.2,
  data: 2.8,
  storage: 2.5,
  network: 1.8,
  iam: 1.7,
  external: 0.8,
};

export function getStride(node: GraphNode): string[] {
  return node.stride?.length ? node.stride : defaultStride[node.kind] ?? [];
}

export function scoreNode(node: GraphNode, graph: GraphData): number {
  const inbound = graph.edges.filter((edge) =>
    edge.target === node.id && ['exposes', 'depends_on', 'attached_to'].includes(edge.relation),
  ).length;
  const outbound = graph.edges.filter((edge) => edge.source === node.id).length;
  const dataBias = ['data', 'storage'].includes(node.kind) ? 2.5 : 0;
  const networkBias = node.kind === 'network' && node.exposure > 0.7 ? 1.5 : 0;

  return criticalityWeight[node.criticality] +
    kindWeight[node.kind] +
    node.exposure * 3 +
    dataBias +
    networkBias +
    0.8 * inbound +
    0.4 * outbound;
}

export function scoreMap(graph: GraphData): Map<string, number> {
  return new Map(graph.nodes.map((node) => [node.id, scoreNode(node, graph)]));
}

export function incidentConfidence(node: GraphNode, graph: GraphData): number | null {
  const related = graph.edges.filter((edge) => edge.source === node.id || edge.target === node.id);
  if (related.length === 0) return null;
  return related.reduce((sum, edge) => sum + (edge.confidence ?? 1), 0) / related.length;
}

export function severityForCvss(score: number): string {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

export function techniqueUrl(technique: TechniqueRecord, atlas: boolean): string {
  return atlas
    ? `https://atlas.mitre.org/techniques/${encodeURIComponent(technique.id)}`
    : `https://attack.mitre.org/techniques/${encodeURIComponent(technique.id)}/`;
}

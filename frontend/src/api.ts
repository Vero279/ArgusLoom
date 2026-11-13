export type NodeKind = 'compute' | 'storage' | 'network' | 'iam' | 'data' | 'external';
export type Criticality = 'critical' | 'high' | 'medium' | 'low';
export type AttackStrategy = 'dijkstra' | 'yen';
export type ScenarioId = 'A' | 'B' | 'C';
export type Scenario = { id: ScenarioId; nodes: number; edges: number };
export type CurrentScenario = Scenario | { id: 'unknown' };

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface GraphNode {
  id: string;
  kind: NodeKind;
  name: string;
  source: string;
  criticality: Criticality;
  exposure: number;
  cves: string[];
  mitre_techniques: string[];
  cvss_max: number;
  stride?: string[];
  metadata?: Record<string, unknown>;
}

export interface GraphEdge {
  id?: string;
  source: string;
  target: string;
  relation: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface BlastRadiusResponse extends GraphData {
  root_id: string;
  depth_map: Record<string, number>;
  risk_score: number;
  max_depth: number;
}

export interface AttackPath {
  nodes: string[];
  edges: GraphEdge[];
  score: number;
  mitre_chain: string[];
  length: number;
}

export interface CVERecord {
  id: string;
  description: string;
  cvss_score: number;
  severity: string;
  published?: string;
  keywords?: string[];
}

export interface TechniqueRecord {
  id: string;
  name: string;
  tactic: string;
  description?: string;
}

export interface RagHit {
  id: string;
  text: string;
  metadata: Record<string, unknown>;
  score: number;
}

export interface RagResponse {
  query: string;
  hits: RagHit[];
  llm_answer?: string | null;
}

export interface CTIEnrichmentResponse {
  graph: GraphData;
  enriched_count: number;
}

export interface AttackPathResponse {
  source_id: string;
  target_id: string;
  strategy: AttackStrategy;
  paths: AttackPath[];
}

export interface HealthResponse {
  status?: string;
  version?: string;
  phase?: number;
}

export interface AttackPathRequest {
  source_id: string;
  target_id: string;
  strategy: AttackStrategy;
  top_k: number;
}

export interface AttackPathSelection {
  sourceId: string;
  targetId: string;
  strategy: AttackStrategy;
}

export interface RagRequest {
  query: string;
  top_k: number;
  include_llm_answer: boolean;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000').replace(/\/$/, '');
const SCENARIO_API_BASE_URL = import.meta.env.DEV ? '' : API_BASE_URL;

async function request<T>(
  path: string,
  init?: RequestInit,
  baseUrl = API_BASE_URL,
): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const body = await response.text();
    throw new ApiError(
      `Pedido à API falhou (${response.status}): ${body || response.statusText}`,
      response.status,
    );
  }

  return response.json() as Promise<T>;
}

export function getGraph(): Promise<GraphData> {
  return request<GraphData>('/graph');
}

export function listScenarios(): Promise<Scenario[]> {
  return request<Scenario[]>('/dev/scenarios', undefined, SCENARIO_API_BASE_URL);
}

export function getCurrentScenario(): Promise<CurrentScenario> {
  return request<CurrentScenario>('/dev/scenarios/current', undefined, SCENARIO_API_BASE_URL);
}

export function activateScenario(id: ScenarioId): Promise<Scenario> {
  return request<Scenario>(
    `/dev/scenarios/${id}/activate`,
    { method: 'POST' },
    SCENARIO_API_BASE_URL,
  );
}

export function getBlastRadius(
  nodeId: string,
  maxDepth = 3,
  weighted = true,
): Promise<BlastRadiusResponse> {
  const query = new URLSearchParams({
    max_depth: String(maxDepth),
    weighted: String(weighted),
  });
  return request<BlastRadiusResponse>(`/nodes/${encodeURIComponent(nodeId)}/blast-radius?${query}`);
}

export function postAttackPaths(payload: AttackPathRequest): Promise<AttackPathResponse> {
  return request<AttackPathResponse>('/attack-paths', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export function postRagQuery(payload: RagRequest): Promise<RagResponse> {
  return request<RagResponse>('/rag/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function postCtiEnrichment(graph: GraphData): Promise<CTIEnrichmentResponse> {
  return request<CTIEnrichmentResponse>('/cti/enrich', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ graph }),
  });
}

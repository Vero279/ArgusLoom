import { describe, expect, it } from 'vitest';
import type { GraphData, GraphNode } from './api';
import { getReachableNodeIds, getSourceNodeIds } from './graphReachability';

const ids = ['A', 'B', 'C', 'D', 'E'];
const nodes: GraphNode[] = ids.map((id) => ({
  id,
  kind: 'compute',
  name: id,
  source: 'test',
  criticality: 'low',
  exposure: 0,
  cves: [],
  mitre_techniques: [],
  cvss_max: 0,
}));

const graph: GraphData = {
  nodes,
  edges: [
    { source: 'A', target: 'B', relation: 'depends_on' },
    { source: 'A', target: 'C', relation: 'depends_on' },
    { source: 'B', target: 'D', relation: 'depends_on' },
    { source: 'D', target: 'A', relation: 'depends_on' },
    { source: 'E', target: 'missing', relation: 'depends_on' },
  ],
};

describe('graph reachability', () => {
  it('finds forward reachable nodes without including the source or dangling endpoints', () => {
    expect(getReachableNodeIds(graph, 'A')).toEqual(new Set(['B', 'C', 'D']));
  });

  it('finds nodes that can reach a target using incoming edges', () => {
    expect(getSourceNodeIds(graph, 'D')).toEqual(new Set(['A', 'B']));
  });

  it('returns no reachable nodes for an isolated node or empty start ID', () => {
    expect(getReachableNodeIds(graph, 'E')).toEqual(new Set());
    expect(getReachableNodeIds(graph, '')).toEqual(new Set());
    expect(getSourceNodeIds(graph, 'E')).toEqual(new Set());
  });
});

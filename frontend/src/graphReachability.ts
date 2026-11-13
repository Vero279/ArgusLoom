import type { GraphData } from './api';

function getReachableIds(graph: GraphData, startId: string, reverse: boolean): Set<string> {
  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const adjacent = new Map<string, string[]>();

  graph.edges.forEach((edge) => {
    const from = reverse ? edge.target : edge.source;
    const to = reverse ? edge.source : edge.target;
    if (!nodeIds.has(from) || !nodeIds.has(to)) return;
    const neighbors = adjacent.get(from);
    if (neighbors) neighbors.push(to);
    else adjacent.set(from, [to]);
  });

  const visited = new Set([startId]);
  const reachable = new Set<string>();
  const queue = [startId];

  for (let index = 0; index < queue.length; index += 1) {
    const currentId = queue[index];
    for (const neighborId of adjacent.get(currentId) ?? []) {
      if (visited.has(neighborId)) continue;
      visited.add(neighborId);
      reachable.add(neighborId);
      queue.push(neighborId);
    }
  }

  return reachable;
}

export function getReachableNodeIds(graph: GraphData, sourceId: string): Set<string> {
  return getReachableIds(graph, sourceId, false);
}

export function getSourceNodeIds(graph: GraphData, targetId: string): Set<string> {
  return getReachableIds(graph, targetId, true);
}

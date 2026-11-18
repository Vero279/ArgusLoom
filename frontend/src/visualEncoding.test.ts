import { describe, expect, it } from 'vitest';
import type { NodeKind } from './api';
import {
  deriveFamily,
  deriveRisk,
  hasCheckovFinding,
  isPoisonedNode,
} from './visualEncoding';

describe('graph visual encoding', () => {
  it('uses positive CVSS thresholds before criticality', () => {
    expect(deriveRisk({ cvss_max: 9, criticality: 'low' })).toBe('critical');
    expect(deriveRisk({ cvss_max: 7, criticality: 'low' })).toBe('high');
    expect(deriveRisk({ cvss_max: 4, criticality: 'low' })).toBe('medium');
    expect(deriveRisk({ cvss_max: 3.9, criticality: 'critical' })).toBe('low');
    expect(deriveRisk({ cvss_max: 0, criticality: 'high' })).toBe('high');
  });

  it('groups node kinds into the three legend families', () => {
    const kinds: NodeKind[] = ['network', 'external', 'compute', 'storage', 'data', 'iam'];
    const families = kinds.map((kind) => deriveFamily({ kind }));

    expect(families).toEqual(['network', 'network', 'compute', 'compute', 'data', 'data']);
  });

  it('recognises poisoned nodes and Checkov findings from metadata', () => {
    expect(isPoisonedNode({ metadata: { poisoned: true } })).toBe(true);
    expect(
      hasCheckovFinding({ metadata: { checkov_findings: [{ check_id: 'CKV_X' }] } }),
    ).toBe(true);
    expect(isPoisonedNode({ metadata: {} })).toBe(false);
    expect(hasCheckovFinding({ metadata: { checkov_findings: [] } })).toBe(false);
  });
});

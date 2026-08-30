import { describe, it, expect } from 'vitest';
import { PolicyEvaluator } from '../policies/evaluator.js';
import { Evidence } from '../types/policy.js';

describe('PolicyEvaluator', () => {
  it('registers and evaluates rules', () => {
    const evaluator = new PolicyEvaluator();

    evaluator.registerRule('TEST-1', (evidence: Evidence[]) => {
      const passed = evidence.some(e => (e.rawPayload as { ok?: boolean })?.ok);
      return {
        status: passed ? 'COMPLIANT' : 'NON_COMPLIANT',
        findings: passed ? ['All good'] : ['Failed'],
      };
    });

    const evidence: Evidence[] = [
      {
        id: 'ev-1',
        controlId: 'TEST-1',
        sourceAdapter: 'test',
        timestamp: new Date(),
        rawPayload: { ok: true },
      },
    ];

    const results = evaluator.evaluateAll(
      [{ id: 'TEST-1', category: 'SECURITY', title: 'Test', description: 'Test', tscReference: 'T1', severity: 'HIGH', isAutomated: true }],
      evidence
    );

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('COMPLIANT');
    expect(results[0].findings).toContain('All good');
  });

  it('returns NOT_EVALUATED when no rule matches', () => {
    const evaluator = new PolicyEvaluator();
    const results = evaluator.evaluateAll(
      [{ id: 'UNKNOWN', category: 'SECURITY', title: 'Unknown', description: 'Unknown', tscReference: 'U1', severity: 'LOW', isAutomated: true }],
      []
    );

    expect(results[0].status).toBe('NOT_EVALUATED');
  });
});

import { BaseAdapter } from '../adapters/base.adapter.js';
import { PolicyEvaluator } from '../policies/evaluator.js';
import { SOC2Control, EvaluationResult, Evidence } from '../types/policy.js';

export interface AuditReport {
  timestamp: Date;
  summary: {
    totalControls: number;
    compliantCount: number;
    nonCompliantCount: number;
    notEvaluatedCount: number;
  };
  results: EvaluationResult[];
}

export class AuditAgent {
  private adapters: BaseAdapter[] = [];
  private evaluator: PolicyEvaluator;
  private controls: SOC2Control[] = [];

  constructor(evaluator: PolicyEvaluator) {
    this.evaluator = evaluator;
  }

  public registerAdapter(adapter: BaseAdapter): void {
    this.adapters.push(adapter);
  }

  public registerControls(controls: SOC2Control[]): void {
    this.controls.push(...controls);
  }

  public async executeAudit(): Promise<AuditReport> {
    const collectedEvidence: Evidence[] = [];

    for (const adapter of this.adapters) {
      try {
        const health = await adapter.checkHealth();
        if (!health.healthy) continue;
        const evidence = await adapter.fetchEvidence();
        collectedEvidence.push(...evidence);
      } catch (err) {
        // Continuous failure recovery per individual adapter
      }
    }

    const results = this.evaluator.evaluateAll(this.controls, collectedEvidence);

    const summary = results.reduce(
      (acc, res) => {
        if (res.status === 'COMPLIANT') acc.compliantCount++;
        else if (res.status === 'NON_COMPLIANT') acc.nonCompliantCount++;
        else acc.notEvaluatedCount++;
        return acc;
      },
      {
        totalControls: this.controls.length,
        compliantCount: 0,
        nonCompliantCount: 0,
        notEvaluatedCount: 0,
      }
    );

    return {
      timestamp: new Date(),
      summary,
      results,
    };
  }
}
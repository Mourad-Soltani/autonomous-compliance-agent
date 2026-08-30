import { BaseAdapter } from '../adapters/base.adapter.js';
import { PolicyEvaluator } from '../policies/evaluator.js';
import { PolicyRemediator, RemediationOutcome } from '../policies/remediator.js';
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
  remediations?: Map<string, RemediationOutcome>;
}

export class AuditAgent {
  private adapters: BaseAdapter[] = [];
  private evaluator: PolicyEvaluator;
  private remediator?: PolicyRemediator;
  private controls: SOC2Control[] = [];

  constructor(evaluator: PolicyEvaluator, remediator?: PolicyRemediator) {
    this.evaluator = evaluator;
    this.remediator = remediator;
  }

  public registerAdapter(adapter: BaseAdapter): void {
    this.adapters.push(adapter);
  }

  public registerControls(controls: SOC2Control[]): void {
    this.controls.push(...controls);
  }

  public async executeAudit(autoRemediate = false): Promise<AuditReport> {
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

    const report: AuditReport = {
      timestamp: new Date(),
      summary,
      results,
    };

    // Autonomous remediation
    if (autoRemediate && this.remediator) {
      console.log('[+] Auto-remediation enabled — fixing non-compliant controls...');
      const remediationOutcomes = await this.remediator.remediateAll(this.controls, results);
      report.remediations = remediationOutcomes;

      const fixedCount = Array.from(remediationOutcomes.values()).filter((o) => o.success).length;
      console.log(`[+] Remediation complete. ${fixedCount} controls fixed.`);
    }

    return report;
  }
}
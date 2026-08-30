import { EvaluationResult, SOC2Control } from '../types/policy.js';

export interface RemediationOutcome {
  success: boolean;
  message: string;
  actionTaken: string;
  error?: string;
}

export type RemediationFunction = (
  control: SOC2Control,
  evaluation: EvaluationResult
) => Promise<RemediationOutcome>;

export class PolicyRemediator {
  private remediations: Map<string, RemediationFunction> = new Map();

  public registerRemediation(controlId: string, fn: RemediationFunction): void {
    this.remediations.set(controlId, fn);
  }

  public async remediate(
    control: SOC2Control,
    evaluation: EvaluationResult
  ): Promise<RemediationOutcome> {
    if (evaluation.status === 'COMPLIANT') {
      return {
        success: true,
        message: 'Control already compliant — no action needed.',
        actionTaken: 'none',
      };
    }

    const remediationFn = this.remediations.get(control.id);
    if (!remediationFn) {
      return {
        success: false,
        message: `No automated remediation registered for control ${control.id}.`,
        actionTaken: 'none',
        error: 'Remediation rule not found.',
      };
    }

    try {
      const outcome = await remediationFn(control, evaluation);
      return outcome;
    } catch (err) {
      return {
        success: false,
        message: `Remediation failed for ${control.id}.`,
        actionTaken: 'attempted',
        error: (err as Error).message,
      };
    }
  }

  public async remediateAll(
    controls: SOC2Control[],
    evaluations: EvaluationResult[]
  ): Promise<Map<string, RemediationOutcome>> {
    const outcomes = new Map<string, RemediationOutcome>();

    for (const evaluation of evaluations) {
      const control = controls.find((c) => c.id === evaluation.controlId);
      if (!control) continue;

      const outcome = await this.remediate(control, evaluation);
      outcomes.set(evaluation.controlId, outcome);
    }

    return outcomes;
  }
}
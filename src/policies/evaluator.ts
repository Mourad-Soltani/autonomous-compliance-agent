import { SOC2Control, Evidence, EvaluationResult } from '../types/policy.js';

export type RuleEvaluationFunction = (evidence: Evidence[]) => {
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'NOT_EVALUATED';
  findings: string[];
  remediationSteps?: string[];
};

export class PolicyEvaluator {
  private rules: Map<string, RuleEvaluationFunction> = new Map();

  public registerRule(controlId: string, fn: RuleEvaluationFunction): void {
    this.rules.set(controlId, fn);
  }

  public evaluateControl(control: SOC2Control, evidenceList: Evidence[]): EvaluationResult {
    const relevantEvidence = evidenceList.filter((e) => e.controlId === control.id);
    const ruleFn = this.rules.get(control.id);

    if (!ruleFn || relevantEvidence.length === 0) {
      return {
        controlId: control.id,
        status: 'NOT_EVALUATED',
        evaluatedAt: new Date(),
        findings: ['Insufficient evidence collected or missing evaluation rule.'],
        remediationSteps: ['Configure target infrastructure adapter to supply log streams.'],
        evidenceIds: relevantEvidence.map((e) => e.id),
      };
    }

    const outcome = ruleFn(relevantEvidence);

    return {
      controlId: control.id,
      status: outcome.status,
      evaluatedAt: new Date(),
      findings: outcome.findings,
      remediationSteps: outcome.remediationSteps ?? [],
      evidenceIds: relevantEvidence.map((e) => e.id),
    };
  }

  public evaluateAll(controls: SOC2Control[], evidenceList: Evidence[]): EvaluationResult[] {
    return controls.map((control) => this.evaluateControl(control, evidenceList));
  }
}
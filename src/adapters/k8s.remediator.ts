import { RemediationFunction, RemediationOutcome } from '../policies/remediator.js';
import { SOC2Control, EvaluationResult } from '../types/policy.js';

export const k8sRemediations: Record<string, RemediationFunction> = {
  'CC6.1': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC6.1 — K8s MOCK: Simulating RBAC hardening...');
    return {
      success: true,
      message: '[MOCK] K8s RBAC hardened. Removed overly permissive bindings.',
      actionTaken: '[MOCK] Removed wildcard ClusterRoles; restricted cluster-admin bindings.',
    };
  },

  'CC6.6': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC6.6 — K8s MOCK: Simulating secret cleanup...');
    return {
      success: true,
      message: '[MOCK] K8s secrets cleaned up.',
      actionTaken: '[MOCK] Removed default service account tokens from default namespace.',
    };
  },

  'CC6.7': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC6.7 — K8s MOCK: Simulating NetworkPolicy creation...');
    return {
      success: true,
      message: '[MOCK] K8s NetworkPolicies applied.',
      actionTaken: '[MOCK] Created default-deny NetworkPolicy for all namespaces with pods.',
    };
  },

  'CC7.2': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC7.2 — K8s MOCK: Simulating pod security enforcement...');
    return {
      success: true,
      message: '[MOCK] K8s Pod Security Standards enforced.',
      actionTaken: '[MOCK] Dropped ALL capabilities; set runAsNonRoot; removed privileged mode.',
    };
  },
};

export function registerK8sRemediations(remediator: { registerRemediation: (id: string, fn: RemediationFunction) => void }): void {
  for (const [controlId, fn] of Object.entries(k8sRemediations)) {
    remediator.registerRemediation(controlId, fn);
  }
}

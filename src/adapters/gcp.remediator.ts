import { RemediationFunction, RemediationOutcome } from '../policies/remediator.js';
import { SOC2Control, EvaluationResult } from '../types/policy.js';

export const gcpRemediations: Record<string, RemediationFunction> = {
  'CC6.1': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC6.1 — GCP MOCK: Simulating IAM policy hardening...');
    return {
      success: true,
      message: '[MOCK] GCP IAM policy hardened. Removed overly permissive bindings.',
      actionTaken: '[MOCK] Restricted Editor/Owner roles; enabled data access audit logging for all services.',
    };
  },

  'CC6.6': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC6.6 — GCP MOCK: Simulating storage hardening...');
    return {
      success: true,
      message: '[MOCK] GCP Storage buckets hardened.',
      actionTaken: '[MOCK] Enabled uniform bucket-level access; enforced public access prevention; applied CMEK; enabled versioning.',
    };
  },

  'CC6.7': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC6.7 — GCP MOCK: Simulating firewall hardening...');
    return {
      success: true,
      message: '[MOCK] GCP Firewall rules hardened.',
      actionTaken: '[MOCK] Restricted ingress to private IP ranges; deleted default-allow rules.',
    };
  },

  'CC7.2': async (
    _control: SOC2Control,
    _evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    console.log('[REMEDIATE] CC7.2 — GCP MOCK: Simulating KMS hardening...');
    return {
      success: true,
      message: '[MOCK] GCP KMS keys hardened.',
      actionTaken: '[MOCK] Created default compliance key ring with HSM protection.',
    };
  },
};

export function registerGCPRemediations(remediator: { registerRemediation: (id: string, fn: RemediationFunction) => void }): void {
  for (const [controlId, fn] of Object.entries(gcpRemediations)) {
    remediator.registerRemediation(controlId, fn);
  }
}

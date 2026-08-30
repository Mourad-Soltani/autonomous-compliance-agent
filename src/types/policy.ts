import { z } from 'zod';

export const SOC2CategorySchema = z.enum([
  'SECURITY',
  'AVAILABILITY',
  'PROCESSING_INTEGRITY',
  'CONFIDENTIALITY',
  'PRIVACY',
]);
export type SOC2Category = z.infer<typeof SOC2CategorySchema>;

export const PolicySeveritySchema = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFORMATIONAL',
]);
export type PolicySeverity = z.infer<typeof PolicySeveritySchema>;

export const ComplianceStatusSchema = z.enum([
  'COMPLIANT',
  'NON_COMPLIANT',
  'NOT_EVALUATED',
  'NOT_APPLICABLE',
  'PARTIALLY_COMPLIANT',
]);
export type ComplianceStatus = z.infer<typeof ComplianceStatusSchema>;

export const SOC2ControlSchema = z.object({
  id: z.string(),
  category: SOC2CategorySchema,
  title: z.string(),
  description: z.string(),
  tscReference: z.string(),
  severity: PolicySeveritySchema,
  isAutomated: z.boolean().default(true),
});
export type SOC2Control = z.infer<typeof SOC2ControlSchema>;

export const EvidenceSchema = z.object({
  id: z.string().uuid(),
  controlId: z.string(),
  sourceAdapter: z.string(),
  timestamp: z.date(),
  rawPayload: z.record(z.unknown()),
  resourceArn: z.string().optional(),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const EvaluationResultSchema = z.object({
  controlId: z.string(),
  status: ComplianceStatusSchema,
  evaluatedAt: z.date(),
  findings: z.array(z.string()),
  remediationSteps: z.array(z.string()).optional(),
  evidenceIds: z.array(z.string().uuid()),
});
export type EvaluationResult = z.infer<typeof EvaluationResultSchema>;
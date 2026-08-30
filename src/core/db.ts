import { PrismaClient } from '@prisma/client';
import { AuditReport } from '../agents/audit.agent.js';
import { SOC2Control, Evidence } from '../types/policy.js';

export const prisma = new PrismaClient();

export async function syncControls(controls: SOC2Control[]): Promise<void> {
  for (const control of controls) {
    await prisma.control.upsert({
      where: { id: control.id },
      update: {
        category: control.category,
        title: control.title,
        description: control.description,
        tscReference: control.tscReference,
        severity: control.severity,
        isAutomated: control.isAutomated,
      },
      create: {
        id: control.id,
        category: control.category,
        title: control.title,
        description: control.description,
        tscReference: control.tscReference,
        severity: control.severity,
        isAutomated: control.isAutomated,
      },
    });
  }
}

/**
 * Persist evidence records to the database before linking them to evaluations.
 */
export async function saveEvidence(evidenceList: Evidence[]): Promise<void> {
  for (const ev of evidenceList) {
    await prisma.evidence.upsert({
      where: { id: ev.id },
      update: {
        controlId: ev.controlId,
        sourceAdapter: ev.sourceAdapter,
        timestamp: ev.timestamp,
        rawPayload: ev.rawPayload,
        resourceArn: ev.resourceArn ?? null,
      },
      create: {
        id: ev.id,
        controlId: ev.controlId,
        sourceAdapter: ev.sourceAdapter,
        timestamp: ev.timestamp,
        rawPayload: ev.rawPayload,
        resourceArn: ev.resourceArn ?? null,
      },
    });
  }
}

export async function saveAuditReport(report: AuditReport): Promise<string> {
  // First persist all evidence so foreign keys resolve
  const allEvidence: Evidence[] = [];
  for (const res of report.results) {
    // evidenceIds should reference already-saved evidence, but collect any new ones
    // In practice, adapters should call saveEvidence() before this function
  }
  // Note: evidence is expected to be pre-saved by the caller (AuditAgent)

  const createdRun = await prisma.auditRun.create({
    data: {
      timestamp: report.timestamp,
      totalControls: report.summary.totalControls,
      compliantCount: report.summary.compliantCount,
      nonCompliantCount: report.summary.nonCompliantCount,
      notEvaluatedCount: report.summary.notEvaluatedCount,
      results: {
        create: report.results.map((res) => ({
          controlId: res.controlId,
          status: res.status,
          evaluatedAt: res.evaluatedAt,
          findings: res.findings,
          remediationSteps: res.remediationSteps ?? [],
          evidenceList: {
            connect: res.evidenceIds.map((id) => ({ id })),
          },
        })),
      },
    },
  });

  return createdRun.id;
}

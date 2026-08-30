import { PrismaClient } from '@prisma/client';
import { AuditReport } from '../agents/audit.agent.js';
import { SOC2Control } from '../types/policy.js';

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

export async function saveAuditReport(report: AuditReport): Promise<string> {
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
#!/usr/bin/env tsx
/**
 * Autonomous Compliance Agent — Demo Data Seeder
 * Populates the database with realistic audit runs, findings, evidence,
 * and controls for demonstration and development.
 */

import { PrismaClient } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';

const prisma = new PrismaClient();

// ============================================
// Demo Data Definitions
// ============================================

const DEMO_CONTROLS = [
  {
    id: 'CC6.1',
    title: 'Logical and Physical Access Controls',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.',
    category: 'SECURITY',
    soc2Mapping: 'CC6.1',
    severity: 'critical',
    automated: true,
    adapter: 'aws',
    status: 'ACTIVE',
  },
  {
    id: 'CC6.6',
    title: 'Encryption and Data Protection',
    description: 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
    category: 'SECURITY',
    soc2Mapping: 'CC6.6',
    severity: 'high',
    automated: true,
    adapter: 'aws',
    status: 'ACTIVE',
  },
  {
    id: 'CC6.7',
    title: 'Network Security and Hardening',
    description: 'The entity restricts access to protected information assets to authorized users.',
    category: 'SECURITY',
    soc2Mapping: 'CC6.7',
    severity: 'high',
    automated: true,
    adapter: 'aws',
    status: 'ACTIVE',
  },
  {
    id: 'A1.1',
    title: 'System Availability Monitoring',
    description: 'The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand.',
    category: 'AVAILABILITY',
    soc2Mapping: 'A1.1',
    severity: 'medium',
    automated: true,
    adapter: 'azure',
    status: 'ACTIVE',
  },
  {
    id: 'C1.1',
    title: 'Data Classification and Handling',
    description: 'The entity identifies and maintains confidential information to meet the entity\'s objectives related to confidentiality.',
    category: 'CONFIDENTIALITY',
    soc2Mapping: 'C1.1',
    severity: 'medium',
    automated: false,
    adapter: 'github',
    status: 'ACTIVE',
  },
  {
    id: 'P1.1',
    title: 'Privacy Notice and Consent',
    description: 'The entity provides notice about the collection, use, retention, and disposal of personal information.',
    category: 'PRIVACY',
    soc2Mapping: 'P1.1',
    severity: 'high',
    automated: false,
    adapter: 'custom',
    status: 'ACTIVE',
  },
];

const DEMO_AUDIT_RUNS = [
  {
    id: uuidv4(),
    name: 'Q3 2026 Full Compliance Scan',
    status: 'COMPLETED',
    startedAt: new Date('2026-07-15T09:00:00Z'),
    completedAt: new Date('2026-07-15T09:23:47Z'),
    totalControls: 25,
    passedControls: 19,
    failedControls: 4,
    errorControls: 2,
    findingsCount: 12,
    adapters: ['aws', 'azure', 'github'],
  },
  {
    id: uuidv4(),
    name: 'AWS Security Deep Dive',
    status: 'COMPLETED',
    startedAt: new Date('2026-08-01T14:30:00Z'),
    completedAt: new Date('2026-08-01T14:42:15Z'),
    totalControls: 14,
    passedControls: 11,
    failedControls: 2,
    errorControls: 1,
    findingsCount: 5,
    adapters: ['aws'],
  },
  {
    id: uuidv4(),
    name: 'Azure Infrastructure Review',
    status: 'RUNNING',
    startedAt: new Date('2026-08-30T10:00:00Z'),
    completedAt: null,
    totalControls: 8,
    passedControls: 5,
    failedControls: 2,
    errorControls: 0,
    findingsCount: 3,
    adapters: ['azure'],
  },
  {
    id: uuidv4(),
    name: 'GCP Pilot Assessment',
    status: 'COMPLETED',
    startedAt: new Date('2026-08-20T08:00:00Z'),
    completedAt: new Date('2026-08-20T08:18:33Z'),
    totalControls: 6,
    passedControls: 4,
    failedControls: 1,
    errorControls: 1,
    findingsCount: 2,
    adapters: ['gcp'],
  },
  {
    id: uuidv4(),
    name: 'Pre-Audit Readiness Check',
    status: 'FAILED',
    startedAt: new Date('2026-08-25T16:00:00Z'),
    completedAt: new Date('2026-08-25T16:05:12Z'),
    totalControls: 25,
    passedControls: 0,
    failedControls: 0,
    errorControls: 25,
    findingsCount: 0,
    adapters: ['aws', 'azure', 'gcp', 'github'],
  },
];

const DEMO_FINDINGS = [
  {
    id: `finding-${uuidv4()}`,
    controlId: 'CC6.1',
    title: 'IAM Password Policy Does Not Enforce Minimum Length',
    description: 'The AWS account password policy is configured with a minimum password length of 8 characters. SOC 2 CC6.1 requires a minimum of 14 characters.',
    severity: 'high',
    status: 'OPEN',
    resource: 'arn:aws:iam::123456789012:account-password-policy',
    adapter: 'aws',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'CC6.1',
    title: 'Root Account MFA Not Enabled',
    description: 'The AWS root account does not have multi-factor authentication enabled. This is a critical security control.',
    severity: 'critical',
    status: 'OPEN',
    resource: 'arn:aws:iam::123456789012:root',
    adapter: 'aws',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'CC6.6',
    title: 'S3 Bucket Public Access Block Not Configured',
    description: 'The S3 bucket "compliance-reports" does not have public access blocks configured. This could lead to accidental data exposure.',
    severity: 'high',
    status: 'REMEDIATED',
    resource: 'arn:aws:s3:::compliance-reports',
    adapter: 'aws',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'CC6.6',
    title: 'S3 Bucket Missing Server-Side Encryption',
    description: 'The S3 bucket "audit-logs-2026" does not have default server-side encryption enabled.',
    severity: 'medium',
    status: 'OPEN',
    resource: 'arn:aws:s3:::audit-logs-2026',
    adapter: 'aws',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'CC6.7',
    title: 'Security Group Allows SSH from 0.0.0.0/0',
    description: 'Security group sg-0a1b2c3d allows inbound SSH (port 22) from any IP address (0.0.0.0/0).',
    severity: 'critical',
    status: 'OPEN',
    resource: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d',
    adapter: 'aws',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'CC6.7',
    title: 'Default Security Group Has Unrestricted Outbound Rules',
    description: 'The default security group in VPC vpc-12345 allows all outbound traffic without restriction.',
    severity: 'medium',
    status: 'OPEN',
    resource: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-default',
    adapter: 'aws',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'A1.1',
    title: 'Azure VM Availability Set Not Configured',
    description: 'Production VMs in resource group "prod-rg" are not deployed in an availability set, risking single points of failure.',
    severity: 'medium',
    status: 'OPEN',
    resource: '/subscriptions/abc123/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-01',
    adapter: 'azure',
    remediationAvailable: true,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'C1.1',
    title: 'GitHub Repository Missing SECURITY.md',
    description: 'The repository "acme-corp/platform" does not contain a SECURITY.md file for responsible disclosure.',
    severity: 'low',
    status: 'OPEN',
    resource: 'acme-corp/platform',
    adapter: 'github',
    remediationAvailable: false,
    auditRunId: '',
  },
  {
    id: `finding-${uuidv4()}`,
    controlId: 'P1.1',
    title: 'Privacy Policy Last Updated Over 12 Months Ago',
    description: 'The privacy policy on the company website was last updated on 2025-03-15, exceeding the recommended annual review cycle.',
    severity: 'medium',
    status: 'OPEN',
    resource: 'https://acme-corp.com/privacy',
    adapter: 'custom',
    remediationAvailable: false,
    auditRunId: '',
  },
];

const DEMO_EVIDENCE = [
  {
    id: `evidence-${uuidv4()}`,
    controlId: 'CC6.1',
    adapter: 'aws',
    resource: 'arn:aws:iam::123456789012:account-password-policy',
    rawData: {
      minimumPasswordLength: 8,
      requireSymbols: true,
      requireNumbers: true,
      requireUppercaseCharacters: true,
      requireLowercaseCharacters: true,
      allowUsersToChangePassword: true,
      maxPasswordAge: 90,
      passwordReusePrevention: 12,
      hardExpiry: false,
    },
    severity: 'high',
  },
  {
    id: `evidence-${uuidv4()}`,
    controlId: 'CC6.6',
    adapter: 'aws',
    resource: 'arn:aws:s3:::compliance-reports',
    rawData: {
      publicAccessBlockConfiguration: null,
      bucketPolicy: null,
      versioning: { enabled: true },
      encryption: null,
      tags: [{ key: 'Environment', value: 'Production' }],
    },
    severity: 'high',
  },
  {
    id: `evidence-${uuidv4()}`,
    controlId: 'CC6.7',
    adapter: 'aws',
    resource: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d',
    rawData: {
      groupName: 'web-server-sg',
      ipPermissions: [
        {
          ipProtocol: 'tcp',
          fromPort: 22,
          toPort: 22,
          ipRanges: [{ cidrIp: '0.0.0.0/0', description: 'SSH access' }],
        },
        {
          ipProtocol: 'tcp',
          fromPort: 443,
          toPort: 443,
          ipRanges: [{ cidrIp: '0.0.0.0/0', description: 'HTTPS' }],
        },
      ],
    },
    severity: 'critical',
  },
  {
    id: `evidence-${uuidv4()}`,
    controlId: 'A1.1',
    adapter: 'azure',
    resource: '/subscriptions/abc123/resourceGroups/prod-rg',
    rawData: {
      vms: [
        { name: 'web-01', availabilitySet: null, zone: null },
        { name: 'web-02', availabilitySet: null, zone: null },
        { name: 'db-01', availabilitySet: 'db-availability-set', zone: '1' },
      ],
    },
    severity: 'medium',
  },
];

// ============================================
// Seeding Functions
// ============================================

async function seedControls() {
  console.log('🌱 Seeding controls...');
  for (const control of DEMO_CONTROLS) {
    await prisma.control.upsert({
      where: { id: control.id },
      update: control,
      create: control,
    });
  }
  console.log(`   ✅ ${DEMO_CONTROLS.length} controls seeded`);
}

async function seedAuditRuns() {
  console.log('🌱 Seeding audit runs...');
  for (const run of DEMO_AUDIT_RUNS) {
    await prisma.auditRun.upsert({
      where: { id: run.id },
      update: run,
      create: run,
    });
  }
  console.log(`   ✅ ${DEMO_AUDIT_RUNS.length} audit runs seeded`);
}

async function seedFindings() {
  console.log('🌱 Seeding findings...');
  // Assign findings to the first completed audit run
  const targetRun = DEMO_AUDIT_RUNS[0];

  for (const finding of DEMO_FINDINGS) {
    finding.auditRunId = targetRun.id;
    finding.createdAt = new Date(targetRun.startedAt.getTime() + Math.random() * 600000);

    await prisma.finding.upsert({
      where: { id: finding.id },
      update: finding,
      create: finding,
    });
  }
  console.log(`   ✅ ${DEMO_FINDINGS.length} findings seeded`);
}

async function seedEvidence() {
  console.log('🌱 Seeding evidence...');
  for (const ev of DEMO_EVIDENCE) {
    ev.collectedAt = new Date('2026-07-15T09:10:00Z');

    await prisma.evidence.upsert({
      where: { id: ev.id },
      update: ev,
      create: ev,
    });
  }
  console.log(`   ✅ ${DEMO_EVIDENCE.length} evidence records seeded`);
}

async function seedRemediationActions() {
  console.log('🌱 Seeding remediation actions...');

  const remediatedFinding = DEMO_FINDINGS.find(f => f.status === 'REMEDIATED');
  if (remediatedFinding) {
    await prisma.remediationAction.create({
      data: {
        id: `remediation-${uuidv4()}`,
        findingId: remediatedFinding.id,
        adapter: 'aws',
        actionTaken: 's3_public_access_blocked',
        success: true,
        message: 'Successfully applied public access block to S3 bucket compliance-reports',
        executedAt: new Date('2026-07-15T09:25:00Z'),
        rolledBack: false,
      },
    });
    console.log('   ✅ 1 remediation action seeded');
  }
}

// ============================================
// Main
// ============================================

async function main() {
  console.log('\n🚀 Autonomous Compliance Agent — Demo Data Seeder\n');

  try {
    await seedControls();
    await seedAuditRuns();
    await seedFindings();
    await seedEvidence();
    await seedRemediationActions();

    console.log('\n✅ Demo data seeding complete!');
    console.log('\n📊 Summary:');
    console.log(`   • Controls: ${await prisma.control.count()}`);
    console.log(`   • Audit Runs: ${await prisma.auditRun.count()}`);
    console.log(`   • Findings: ${await prisma.finding.count()}`);
    console.log(`   • Evidence: ${await prisma.evidence.count()}`);
    console.log(`   • Remediation Actions: ${await prisma.remediationAction.count()}`);

  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();

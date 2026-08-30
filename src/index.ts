import { PolicyEvaluator } from './policies/evaluator.js';
import { PolicyRemediator } from './policies/remediator.js';
import { AuditAgent } from './agents/audit.agent.js';
import { AWSAdapter } from './adapters/aws.adapter.js';
import { GitHubAdapter } from './adapters/github.adapter.js';
import { SlackAdapter } from './adapters/slack.adapter.js';
import { registerAWSRemediations } from './adapters/aws.remediator.js';
import { registerGitHubRemediations } from './adapters/github.remediator.js';
import { AzureAdapter } from './adapters/azure.adapter.js';
import { registerAzureRemediations } from './adapters/azure.remediator.js';
import { SOC2Control, Evidence } from './types/policy.js';
import { syncControls, saveAuditReport, prisma } from './core/db.js';
import { seedTemplates, getTemplateStats } from './templates/loader.js';

const DEFAULT_CONTROLS: SOC2Control[] = [
  {
    id: 'CC6.1',
    category: 'SECURITY',
    title: 'Logical Access Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures.',
    tscReference: 'CC6.1',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.6',
    category: 'SECURITY',
    title: 'Encryption in Transit & at Rest',
    description: 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
    tscReference: 'CC6.6',
    severity: 'CRITICAL',
    isAutomated: true,
  },
  {
    id: 'CC6.7',
    category: 'SECURITY',
    title: 'Malware Protection',
    description: 'The entity prevents or detects the installation of unauthorized software.',
    tscReference: 'CC6.7',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.8',
    category: 'SECURITY',
    title: 'Code Change Protection & Reviews',
    description: 'The entity prevents unauthorized code modifications via branch enforcement and peer reviews.',
    tscReference: 'CC6.8',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC7.2',
    category: 'SECURITY',
    title: 'System Monitoring & Anomaly Detection',
    description: 'The entity monitors infrastructure to detect anomalies and unauthorized actions.',
    tscReference: 'CC7.2',
    severity: 'CRITICAL',
    isAutomated: true,
  },
];

async function main() {
  const args = process.argv.slice(2);

  // Template management commands
  if (args.includes('--templates')) {
    console.log('[+] Loading control templates...');
    const stats = getTemplateStats();
    console.log(`[+] Available templates: ${stats.total} controls`);
    console.log(`    Categories:`, stats.byCategory);
    console.log(`    Automated: ${stats.automated} | Manual: ${stats.manual}`);

    const category = process.env.TEMPLATE_CATEGORY as any;
    const automatedOnly = args.includes('--automated-only');
    const manualOnly = args.includes('--manual-only');

    const result = await seedTemplates({
      category: category || 'ALL',
      automatedOnly,
      manualOnly,
    });

    console.log(`[+] Seeded ${result.seeded} controls into database.`);
    console.log('[+] Seeded controls:');
    for (const c of result.controls) {
      console.log(`    • ${c.id} — ${c.title} (${c.category})`);
    }
    await prisma.$disconnect();
    return;
  }

  const autoRemediate = args.includes('--remediate') || args.includes('-r');

  console.log('[+] Initializing Autonomous Compliance Engine...');
  if (autoRemediate) {
    console.log('[+] Auto-remediation ENABLED — non-compliant controls will be fixed automatically.');
  }

  const evaluator = new PolicyEvaluator();

  // Register Rules
  evaluator.registerRule('CC6.1', (evidenceList: Evidence[]) => {
    const passed = evidenceList.some(
      (e) => (e.rawPayload as { status?: string })?.status === 'PASSED'
    );
    return {
      status: passed ? 'COMPLIANT' : 'NON_COMPLIANT',
      findings: passed
        ? ['Logical access security verified via AWS Security Hub.']
        : ['MFA or Password policy non-compliant.'],
    };
  });

  evaluator.registerRule('CC6.8', (evidenceList: Evidence[]) => {
    const passed = evidenceList.some(
      (e) => (e.rawPayload as { protected?: boolean })?.protected === true
    );
    return {
      status: passed ? 'COMPLIANT' : 'NON_COMPLIANT',
      findings: passed
        ? ['Main branch protection and peer approvals enforced.']
        : ['Main branch allows unreviewed commits.'],
    };
  });

  evaluator.registerRule('CC6.6', (evidenceList: Evidence[]) => {
    const encrypted = evidenceList.some(
      (e) => (e.rawPayload as { httpsOnly?: boolean })?.httpsOnly === true
    );
    return {
      status: encrypted ? 'COMPLIANT' : 'NON_COMPLIANT',
      findings: encrypted
        ? ['Storage encryption in transit and at rest verified.']
        : ['Storage account does not enforce HTTPS or encryption.'],
    };
  });

  evaluator.registerRule('CC6.7', (evidenceList: Evidence[]) => {
    const hardened = evidenceList.some(
      (e) => (e.rawPayload as { defaultDenyInbound?: boolean })?.defaultDenyInbound === true
    );
    return {
      status: hardened ? 'COMPLIANT' : 'NON_COMPLIANT',
      findings: hardened
        ? ['NSG default deny inbound rule enforced.']
        : ['NSG allows unrestricted inbound traffic.'],
    };
  });

  evaluator.registerRule('CC7.2', (evidenceList: Evidence[]) => {
    const isLogging = evidenceList.some(
      (e) => (e.rawPayload as { isLogging?: boolean })?.isLogging === true
    );
    return {
      status: isLogging ? 'COMPLIANT' : 'NON_COMPLIANT',
      findings: isLogging
        ? ['AWS CloudTrail audit trail active.']
        : ['CloudTrail audit logging disabled.'],
    };
  });

  // Build remediator if auto-remediation is enabled
  const remediator = autoRemediate ? new PolicyRemediator() : undefined;
  if (remediator) {
    registerAWSRemediations(remediator);
    registerGitHubRemediations(remediator);
    registerAzureRemediations(remediator);
  }

  // Orchestrate Adapters
  const agent = new AuditAgent(evaluator, remediator);
  agent.registerControls(DEFAULT_CONTROLS);

  const awsAdapter = new AWSAdapter({
    adapterId: 'aws-prod-us-east-1',
    enabled: true,
    region: process.env.AWS_REGION || 'us-east-1',
  });

  const githubAdapter = new GitHubAdapter({
    adapterId: 'github-main-repo',
    enabled: true,
    owner: process.env.GITHUB_OWNER || 'enterprise-org',
    repo: process.env.GITHUB_REPO || 'core-platform',
  });

  await awsAdapter.initialize();
  await githubAdapter.initialize();

  const azureAdapter = new AzureAdapter({
    adapterId: 'azure-prod-subscription',
    enabled: true,
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID || '00000000-0000-0000-0000-000000000000',
  });

  agent.registerAdapter(awsAdapter);
  agent.registerAdapter(githubAdapter);
  agent.registerAdapter(azureAdapter);

  console.log('[+] Syncing SOC 2 control schema...');
  await syncControls(DEFAULT_CONTROLS);

  console.log('[+] Executing compliance evaluation loop...');
  const report = await agent.executeAudit(autoRemediate);

  console.log(`[+] Audit complete. Passed: ${report.summary.compliantCount}/${report.summary.totalControls}`);

  if (report.remediations) {
    const fixed = Array.from(report.remediations.values()).filter((o) => o.success).length;
    const failed = Array.from(report.remediations.values()).filter((o) => !o.success).length;
    console.log(`[+] Remediation: ${fixed} controls fixed, ${failed} failed.`);
    for (const [controlId, outcome] of report.remediations) {
      const icon = outcome.success ? '✅' : '❌';
      console.log(`    ${icon} ${controlId}: ${outcome.message}`);
    }
  }

  console.log('[+] Storing run metrics to PostgreSQL...');
  const runId = await saveAuditReport(report);
  console.log(`[+] Run saved successfully. ID: ${runId}`);

  // Optional: Send Slack notification
  const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (slackWebhookUrl) {
    try {
      const slackAdapter = new SlackAdapter({
        adapterId: 'slack-alerts',
        enabled: true,
        webhookUrl: slackWebhookUrl,
        channel: process.env.SLACK_CHANNEL,
        username: 'Compliance Agent',
      });
      await slackAdapter.sendAuditSummary(report);
      console.log('[+] Slack notification sent.');
    } catch (err) {
      console.error('[-] Failed to send Slack notification:', (err as Error).message);
    }
  }
}

main()
  .catch(console.error)
  .finally(async () => {
    await prisma.$disconnect();
  });
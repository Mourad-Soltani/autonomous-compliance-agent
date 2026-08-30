import { PolicyEvaluator } from './policies/evaluator.js';
import { AuditAgent } from './agents/audit.agent.js';
import { AWSAdapter } from './adapters/aws.adapter.js';
import { GitHubAdapter } from './adapters/github.adapter.js';
import { SlackAdapter } from './adapters/slack.adapter.js';
import { SOC2Control, Evidence } from './types/policy.js';
import { syncControls, saveAuditReport, prisma } from './core/db.js';

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
  console.log('[+] Initializing Autonomous Compliance Engine...');

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

  // Orchestrate Adapters
  const agent = new AuditAgent(evaluator);
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

  agent.registerAdapter(awsAdapter);
  agent.registerAdapter(githubAdapter);

  console.log('[+] Syncing SOC 2 control schema...');
  await syncControls(DEFAULT_CONTROLS);

  console.log('[+] Executing compliance evaluation loop...');
  const report = await agent.executeAudit();

  console.log(`[+] Audit complete. Passed: ${report.summary.compliantCount}/${report.summary.totalControls}`);

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
import { createServer, IncomingMessage, ServerResponse } from 'http';
import { URL } from 'url';
import { PolicyEvaluator } from './policies/evaluator.js';
import { AuditAgent } from './agents/audit.agent.js';
import { AWSAdapter } from './adapters/aws.adapter.js';
import { GitHubAdapter } from './adapters/github.adapter.js';
import { SlackAdapter } from './adapters/slack.adapter.js';
import { SOC2Control, Evidence } from './types/policy.js';
import { syncControls, saveAuditReport, prisma } from './core/db.js';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

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

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function buildAgent(): AuditAgent {
  const evaluator = new PolicyEvaluator();

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

  agent.registerAdapter(awsAdapter);
  agent.registerAdapter(githubAdapter);

  return agent;
}

async function triggerAudit(slackWebhookUrl?: string): Promise<unknown> {
  const agent = buildAgent();

  console.log('[+] Syncing SOC 2 control schema...');
  await syncControls(DEFAULT_CONTROLS);

  console.log('[+] Executing compliance evaluation loop...');
  const report = await agent.executeAudit();

  console.log(`[+] Audit complete. Passed: ${report.summary.compliantCount}/${report.summary.totalControls}`);

  console.log('[+] Storing run metrics to PostgreSQL...');
  const runId = await saveAuditReport(report);
  console.log(`[+] Run saved successfully. ID: ${runId}`);

  if (slackWebhookUrl) {
    try {
      const slack = new SlackAdapter({
        adapterId: 'slack-alerts',
        enabled: true,
        webhookUrl: slackWebhookUrl,
        channel: process.env.SLACK_CHANNEL,
        username: 'Compliance Agent',
      });
      await slack.sendAuditSummary(report);
      console.log('[+] Slack notification sent.');
    } catch (err) {
      console.error('[-] Failed to send Slack notification:', (err as Error).message);
    }
  }

  return { runId, ...report };
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // GET /health — health check
    if (url.pathname === '/health' && req.method === 'GET') {
      json(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
      return;
    }

    // POST /audit — trigger a new audit run
    if (url.pathname === '/audit' && req.method === 'POST') {
      const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;
      const result = await triggerAudit(slackWebhookUrl);
      json(res, 200, result);
      return;
    }

    // GET /audit/runs — list recent audit runs
    if (url.pathname === '/audit/runs' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '10', 10);
      const runs = await prisma.auditRun.findMany({
        take: limit,
        orderBy: { timestamp: 'desc' },
        include: {
          results: {
            include: {
              control: true,
              evidenceList: true,
            },
          },
        },
      });
      json(res, 200, { count: runs.length, runs });
      return;
    }

    // GET /audit/runs/:id — get a specific audit run
    if (url.pathname.startsWith('/audit/runs/') && req.method === 'GET') {
      const runId = url.pathname.split('/')[3];
      const run = await prisma.auditRun.findUnique({
        where: { id: runId },
        include: {
          results: {
            include: {
              control: true,
              evidenceList: true,
            },
          },
        },
      });
      if (!run) {
        json(res, 404, { error: 'Audit run not found' });
        return;
      }
      json(res, 200, run);
      return;
    }

    // GET /controls — list all controls
    if (url.pathname === '/controls' && req.method === 'GET') {
      const controls = await prisma.control.findMany({
        orderBy: { createdAt: 'desc' },
      });
      json(res, 200, { count: controls.length, controls });
      return;
    }

    // GET /controls/:id — get a specific control
    if (url.pathname.startsWith('/controls/') && req.method === 'GET') {
      const controlId = url.pathname.split('/')[2];
      const control = await prisma.control.findUnique({
        where: { id: controlId },
        include: {
          evaluations: { orderBy: { evaluatedAt: 'desc' }, take: 5 },
          evidence: { orderBy: { timestamp: 'desc' }, take: 5 },
        },
      });
      if (!control) {
        json(res, 404, { error: 'Control not found' });
        return;
      }
      json(res, 200, control);
      return;
    }

    // GET /evidence — list all evidence
    if (url.pathname === '/evidence' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '50', 10);
      const evidence = await prisma.evidence.findMany({
        take: limit,
        orderBy: { timestamp: 'desc' },
        include: { control: true },
      });
      json(res, 200, { count: evidence.length, evidence });
      return;
    }

    // 404 fallback
    json(res, 404, { error: 'Not found', path: url.pathname, method: req.method });
  } catch (err) {
    console.error('[-] Server error:', err);
    json(res, 500, { error: 'Internal server error', message: (err as Error).message });
  }
});

server.listen(PORT, async () => {
  console.log(`[+] Compliance Agent API running on http://localhost:${PORT}`);
  console.log(`[+] Endpoints:`);
  console.log(`    GET  /health          → Health check`);
  console.log(`    POST /audit           → Trigger compliance audit`);
  console.log(`    GET  /audit/runs      → List audit runs`);
  console.log(`    GET  /audit/runs/:id  → Get specific audit run`);
  console.log(`    GET  /controls        → List SOC 2 controls`);
  console.log(`    GET  /controls/:id    → Get specific control`);
  console.log(`    GET  /evidence        → List collected evidence`);
});

process.on('SIGINT', async () => {
  console.log('\n[+] Shutting down...');
  await prisma.$disconnect();
  server.close(() => {
    process.exit(0);
  });
});

process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  server.close(() => {
    process.exit(0);
  });
});
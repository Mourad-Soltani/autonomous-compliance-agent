import { createServer, IncomingMessage, ServerResponse } from 'http';
import { URL } from 'url';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { PolicyEvaluator } from './policies/evaluator.js';
import { PolicyRemediator } from './policies/remediator.js';
import { AuditAgent } from './agents/audit.agent.js';
import { AWSAdapter } from './adapters/aws.adapter.js';
import { GitHubAdapter } from './adapters/github.adapter.js';
import { SlackAdapter } from './adapters/slack.adapter.js';
import { registerAWSRemediations } from './adapters/aws.remediator.js';
import { registerGitHubRemediations } from './adapters/github.remediator.js';
import { SOC2Control, Evidence } from './types/policy.js';
import { syncControls, saveAuditReport, prisma } from './core/db.js';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const __dirname = new URL('.', import.meta.url).pathname;

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

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

function serveStaticFile(res: ServerResponse, filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  try {
    const content = readFileSync(filePath);
    const ext = extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(content);
    return true;
  } catch {
    return false;
  }
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function buildEvaluator(): PolicyEvaluator {
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

  return evaluator;
}

function buildRemediator(): PolicyRemediator {
  const remediator = new PolicyRemediator();
  registerAWSRemediations(remediator);
  registerGitHubRemediations(remediator);
  return remediator;
}

function buildAgent(autoRemediate = false): AuditAgent {
  const evaluator = buildEvaluator();
  const remediator = autoRemediate ? buildRemediator() : undefined;
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

  agent.registerAdapter(awsAdapter);
  agent.registerAdapter(githubAdapter);

  return agent;
}

async function triggerAudit(autoRemediate = false): Promise<unknown> {
  const agent = buildAgent(autoRemediate);

  console.log('[+] Syncing SOC 2 control schema...');
  await syncControls(DEFAULT_CONTROLS);

  console.log(`[+] Executing compliance evaluation loop${autoRemediate ? ' with auto-remediation' : ''}...`);
  const report = await agent.executeAudit(autoRemediate);

  console.log(`[+] Audit complete. Passed: ${report.summary.compliantCount}/${report.summary.totalControls}`);

  if (report.remediations) {
    const fixed = Array.from(report.remediations.values()).filter((o) => o.success).length;
    const failed = Array.from(report.remediations.values()).filter((o) => !o.success).length;
    console.log(`[+] Remediation: ${fixed} fixed, ${failed} failed.`);
  }

  console.log('[+] Storing run metrics to PostgreSQL...');
  const runId = await saveAuditReport(report);
  console.log(`[+] Run saved successfully. ID: ${runId}`);

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

  // Static files — Dashboard
  if (url.pathname === '/' || url.pathname === '/dashboard' || url.pathname === '/dashboard/') {
    const served = serveStaticFile(res, join(__dirname, '../dashboard/index.html'));
    if (served) return;
  }
  if (url.pathname.startsWith('/dashboard/')) {
    const filePath = join(__dirname, '..', url.pathname);
    const served = serveStaticFile(res, filePath);
    if (served) return;
  }

  try {
    // GET /health
    if (url.pathname === '/health' && req.method === 'GET') {
      json(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
      return;
    }

    // POST /audit
    if (url.pathname === '/audit' && req.method === 'POST') {
      const result = await triggerAudit(false);
      json(res, 200, result);
      return;
    }

    // POST /remediate
    if (url.pathname === '/remediate' && req.method === 'POST') {
      const result = await triggerAudit(true);
      json(res, 200, result);
      return;
    }

    // GET /audit/runs
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

    // GET /audit/runs/:id
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

    // GET /controls
    if (url.pathname === '/controls' && req.method === 'GET') {
      const controls = await prisma.control.findMany({
        orderBy: { createdAt: 'desc' },
      });
      json(res, 200, { count: controls.length, controls });
      return;
    }

    // GET /controls/:id
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

    // GET /evidence
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


    // GET /templates — list all available control templates
    if (url.pathname === '/templates' && req.method === 'GET') {
      const { listTemplates, getTemplateStats } = await import('./templates/loader.js');
      const templates = listTemplates();
      const stats = getTemplateStats();
      json(res, 200, { stats, templates });
      return;
    }

    // POST /templates/seed — seed database with templates
    if (url.pathname === '/templates/seed' && req.method === 'POST') {
      const { seedTemplates } = await import('./templates/loader.js');
      const category = url.searchParams.get('category') as any;
      const automatedOnly = url.searchParams.get('automatedOnly') === 'true';
      const manualOnly = url.searchParams.get('manualOnly') === 'true';

      const result = await seedTemplates({
        category: category || 'ALL',
        automatedOnly,
        manualOnly,
      });
      json(res, 200, {
        message: `Seeded ${result.seeded} controls`,
        seeded: result.seeded,
        controls: result.controls.map(c => ({ id: c.id, title: c.title, category: c.category })),
      });
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
  console.log(`[+] Dashboard available at http://localhost:${PORT}/dashboard`);
  console.log(`[+] Endpoints:`);
  console.log(`    GET  /                    → Web Dashboard`);
  console.log(`    GET  /health              → Health check`);
  console.log(`    POST /audit               → Trigger compliance audit`);
  console.log(`    POST /remediate           → Trigger audit + auto-fix`);
  console.log(`    GET  /audit/runs          → List audit runs`);
  console.log(`    GET  /audit/runs/:id      → Get specific audit run`);
  console.log(`    GET  /controls            → List SOC 2 controls`);
  console.log(`    GET  /controls/:id        → Get specific control`);
  console.log(`    GET  /evidence            → List collected evidence`);
  console.log(`    GET  /templates           → List control templates`);
  console.log(`    POST /templates/seed      → Seed database with templates`);
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
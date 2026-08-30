#!/usr/bin/env node
/**
 * Zero-dependency bundler for the Autonomous Compliance Agent.
 * Concatenates all source files into a single deployable script.
 */

const fs = require('fs');
const path = require('path');

const FILES_TO_BUNDLE = [
  // --- Domain Models & Types ---
  'src/types/index.ts',
  'src/types/soc2.ts',
  'src/models/control.ts',
  'src/models/evidence.ts',
  'src/models/finding.ts',
  'src/models/remediation.ts',

  // --- Core Engine ---
  'src/core/rule-engine.ts',
  'src/core/policy-evaluator.ts',
  'src/core/remediation-engine.ts',
  'src/core/export.ts',
  'src/core/agent-runtime.ts',

  // --- Database Layer ---
  'src/db/prisma.ts',
  'src/db/services/audit-run.service.ts',
  'src/db/services/control.service.ts',
  'src/db/services/evidence.service.ts',
  'src/db/services/finding.service.ts',

  // --- Adapters ---
  'src/adapters/base.adapter.ts',
  'src/adapters/aws.adapter.ts',
  'src/adapters/aws.remediator.ts',
  'src/adapters/github.adapter.ts',
  'src/adapters/github.remediator.ts',
  'src/adapters/azure.adapter.ts',
  'src/adapters/azure.remediator.ts',

  // --- Templates ---
  'src/templates/controls.ts',
  'src/templates/loader.ts',

  // --- Notifications ---
  'src/notifications/slack.adapter.ts',
  'src/notifications/webhook.adapter.ts',

  // --- API & Server ---
  'src/api/server.ts',
  'src/api/routes/audit.routes.ts',
  'src/api/routes/control.routes.ts',
  'src/api/routes/template.routes.ts',
  'src/api/routes/export.routes.ts',
  'src/api/routes/adapter.routes.ts',
  'src/api/middleware/error-handler.ts',

  // --- Dashboard ---
  'src/dashboard/app.tsx',
  'src/dashboard/pages/Dashboard.tsx',
  'src/dashboard/pages/AuditRuns.tsx',
  'src/dashboard/pages/Controls.tsx',
  'src/dashboard/pages/AuditorPortal.tsx',
  'src/dashboard/components/Sidebar.tsx',
  'src/dashboard/components/StatusBadge.tsx',
  'src/dashboard/components/ExportButton.tsx',

  // --- CLI & Entry ---
  'src/cli/commands.ts',
  'src/index.ts',
];

const OUT_DIR = path.resolve(__dirname, '../dist');
const OUT_FILE = path.join(OUT_DIR, 'bundle.ts');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function bundle() {
  ensureDir(OUT_DIR);
  const root = path.resolve(__dirname, '..');
  let output = `// ============================================\n`;
  output += `// Autonomous Compliance Agent — Bundled Build\n`;
  output += `// Generated: ${new Date().toISOString()}\n`;
  output += `// ============================================\n\n`;

  for (const file of FILES_TO_BUNDLE) {
    const fullPath = path.join(root, file);
    if (!fs.existsSync(fullPath)) {
      console.warn(`⚠️  Missing: ${file}`);
      continue;
    }
    const content = fs.readFileSync(fullPath, 'utf-8');
    output += `// --- FILE: ${file} ---\n`;
    output += content;
    output += `\n\n`;
  }

  fs.writeFileSync(OUT_FILE, output, 'utf-8');
  const sizeKB = (fs.statSync(OUT_FILE).size / 1024).toFixed(1);
  console.log(`✅ Bundle written to ${OUT_FILE} (${sizeKB} KB)`);
  console.log(`📦 Files included: ${FILES_TO_BUNDLE.length}`);
}

bundle();

const fs = require('fs');
const path = require('path');

const FILES_TO_BUNDLE = [
  'package.json',
  'tsconfig.json',
  '.env.example',
  'README.md',
  'prisma/schema.prisma',
  'dashboard/index.html',
  'dashboard/styles.css',
  'dashboard/app.js',
  'src/types/policy.ts',
  'src/policies/evaluator.ts',
  'src/policies/remediator.ts',
  'src/adapters/base.adapter.ts',
  'src/adapters/aws.adapter.ts',
  'src/adapters/aws.remediator.ts',
  'src/adapters/github.adapter.ts',
  'src/adapters/github.remediator.ts',
  'src/adapters/slack.adapter.ts',
  'src/agents/audit.agent.ts',
  'src/core/db.ts',
  'src/index.ts',
  'src/server.ts',
];

const OUTPUT_FILE = 'bundle.md';

function generateBundle() {
  console.log('[+] Combining repository files...');
  let content = `# Complete Codebase Export\n\n`;

  for (const relativePath of FILES_TO_BUNDLE) {
    const fullPath = path.resolve(process.cwd(), relativePath);
    if (fs.existsSync(fullPath)) {
      const fileData = fs.readFileSync(fullPath, 'utf8');
      content += `---\n\n## File: \`${relativePath}\`\n\n\`\`\`\n${fileData}\n\`\`\`\n\n`;
    } else {
      console.log(`[!] File not found: ${relativePath}`);
    }
  }

  fs.writeFileSync(OUTPUT_FILE, content, 'utf8');
  console.log(`[+] Combined files saved to \`${OUTPUT_FILE}\`.`);
}

generateBundle();
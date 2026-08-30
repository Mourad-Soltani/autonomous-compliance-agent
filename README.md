# Autonomous Compliance Agent

> Autonomous AI agent for continuous SOC 2 compliance evaluation, evidence collection, and **automatic remediation**.

## Overview

This TypeScript-based platform continuously audits your cloud infrastructure and code repositories against SOC 2 Trust Services Criteria, evaluates collected evidence against dynamic policy rules, **automatically fixes non-compliant controls**, and persists audit reports to PostgreSQL.

**Key differentiator:** Unlike Vanta, Drata, or Secureframe, this agent does not just *detect* misconfigurations — it **remediates them automatically** via live AWS and GitHub API calls.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AWS Adapter   │     │ GitHub Adapter  │     │  Slack Adapter  │
│  (CC6.1, CC7.2) │     │    (CC6.8)      │     │  (Alerts)       │
│   LIVE or MOCK  │     │   LIVE or MOCK  │     │                 │
└────────┬────────┘     └────────┬────────┘     └─────────────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
            ┌─────────────────┐
            │   Audit Agent   │  ← Orchestrator
            └────────┬────────┘
                     ▼
            ┌─────────────────┐
            │ Policy Evaluator│  ← Dynamic rule engine
            └────────┬────────┘
                     ▼
            ┌─────────────────┐     ┌─────────────────┐
            │ Policy Remediator│ ←── │ Auto-fix engine │
            │  (LIVE or MOCK)  │     │                 │
            └────────┬────────┘     └─────────────────┘
                     ▼
            ┌─────────────────┐
            │    PostgreSQL   │  ← Prisma ORM
            │  (Audit Runs,   │
            │   Evidence,     │
            │   Controls)     │
            └─────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Set Up Database

```bash
npx prisma generate
npx prisma db push
```

### 4. Run CLI Audit

```bash
# Detection only (mock mode if no credentials)
npm run dev

# Detection + automatic remediation
npm run dev -- --remediate
```

### 5. Start REST API Server

```bash
npm run server
```

The API will be available at `http://localhost:3000`.

## Live Mode vs Mock Mode

The agent operates in **two modes** depending on credential availability:

| Mode | Trigger | Behavior |
|------|---------|----------|
| **LIVE** | AWS/GitHub credentials provided in `.env` | Connects to real APIs, collects actual evidence, performs real remediation |
| **MOCK** | Credentials missing | Returns simulated data for demo/testing purposes |

### AWS Live Mode

Requires:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`

IAM permissions needed:
- `iam:GetAccountPasswordPolicy`
- `iam:GetAccountSummary`
- `iam:UpdateAccountPasswordPolicy`
- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`
- `cloudtrail:CreateTrail`
- `cloudtrail:StartLogging`
- `cloudtrail:PutEventSelectors`
- `s3:CreateBucket` (for CloudTrail S3 bucket, if not pre-created)

### GitHub Live Mode

Requires:
- `GITHUB_TOKEN` (PAT with `repo` and `admin:repo_hook` scopes)
- `GITHUB_OWNER`
- `GITHUB_REPO`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/audit` | Trigger compliance audit (detection only) |
| `POST` | `/remediate` | Trigger audit + **auto-fix non-compliant controls** |
| `GET` | `/audit/runs` | List recent audit runs |
| `GET` | `/audit/runs/:id` | Get a specific audit run |
| `GET` | `/controls` | List all SOC 2 controls |
| `GET` | `/controls/:id` | Get a specific control |
| `GET` | `/evidence` | List collected evidence |

## Autonomous Remediation

### How It Works

1. **Evaluate** — Run the audit to detect non-compliant controls
2. **Remediate** — The `PolicyRemediator` looks up registered fix functions per control ID
3. **Execute** — AWS/GitHub APIs are called to enforce the desired state
4. **Report** — Remediation outcomes are logged and stored alongside audit results

### Supported Remediations

| Control | Issue | Auto-Fix Action |
|---------|-------|-----------------|
| **CC6.1** | IAM MFA disabled / weak password policy | Enforces 14-char password with symbols & 90-day rotation. Logs warning for root MFA (requires console). |
| **CC7.2** | CloudTrail logging disabled | Creates multi-region trail with log file validation; starts logging. |
| **CC6.8** | Branch protection disabled | Enforces PR reviews (2 approvers), code owner review, CI status checks. |

### CLI Usage

```bash
# Detection only
npx tsx src/index.ts

# Detection + auto-fix
npx tsx src/index.ts --remediate
```

### API Usage

```bash
# Detection only
curl -X POST http://localhost:3000/audit

# Detection + auto-remediation
curl -X POST http://localhost:3000/remediate
```

### Adding Custom Remediations

```typescript
import { PolicyRemediator } from './policies/remediator.js';

const remediator = new PolicyRemediator();

remediator.registerRemediation('CC6.1', async (control, evaluation) => {
  // Your fix logic here
  await enableMFA();
  return {
    success: true,
    message: 'MFA enabled.',
    actionTaken: 'Enabled MFA for root user.',
  };
});
```

## Project Structure

```
├── prisma/
│   └── schema.prisma           # PostgreSQL schema
├── scripts/
│   └── bundle.js               # Zero-dependency code bundler
├── src/
│   ├── adapters/
│   │   ├── base.adapter.ts         # Abstract adapter interface
│   │   ├── aws.adapter.ts          # AWS SDK evidence collection
│   │   ├── aws.remediator.ts       # AWS SDK auto-fix logic
│   │   ├── github.adapter.ts       # GitHub API evidence collection
│   │   ├── github.remediator.ts    # GitHub API auto-fix logic
│   │   └── slack.adapter.ts        # Slack notifications
│   ├── agents/
│   │   └── audit.agent.ts          # Audit orchestrator
│   ├── core/
│   │   └── db.ts                   # Prisma database service
│   ├── policies/
│   │   ├── evaluator.ts            # Dynamic rule engine
│   │   └── remediator.ts           # Auto-fix engine
│   ├── types/
│   │   └── policy.ts               # Zod schemas & TypeScript types
│   ├── index.ts                    # CLI entry point
│   └── server.ts                   # REST API server
├── .env.example
├── package.json
├── tsconfig.json
└── README.md
```

## Database Schema

### Models

- **Control** — SOC 2 compliance requirements (e.g., CC6.1, CC7.2)
- **AuditRun** — Summary metrics of a completed audit cycle
- **Evidence** — Raw JSON audit logs from third-party services
- **EvaluationResult** — Findings and remediation steps per control

## Adapters

### AWS Adapter (LIVE / MOCK)
- **LIVE mode:** Uses `@aws-sdk/client-iam` and `@aws-sdk/client-cloudtrail` to query real infrastructure
- **MOCK mode:** Returns simulated compliant data for testing

Collects evidence from:
- **AWS IAM** — Password policy strength, MFA status (CC6.1)
- **AWS CloudTrail** — Trail existence, logging status, multi-region config (CC7.2)

### AWS Remediator (LIVE / MOCK)
- **LIVE mode:** Calls AWS APIs to enforce compliance
- **MOCK mode:** Logs simulated actions

Fixes:
- **Password Policy** — Enforces 14+ chars, symbols, 90-day rotation
- **CloudTrail** — Creates/starts multi-region trail with log validation

### GitHub Adapter (LIVE / MOCK)
- **LIVE mode:** Uses GitHub REST API via native `fetch`
- **MOCK mode:** Returns simulated branch protection data

Collects evidence from:
- **Branch Protection API** — Required PR reviews, status checks, admin enforcement (CC6.8)

### GitHub Remediator (LIVE / MOCK)
- **LIVE mode:** Calls GitHub API to enforce branch protection
- **MOCK mode:** Logs simulated actions

Fixes:
- **Branch Protection** — Enforces 2 required reviews, code owner approval, CI checks

### Slack Adapter
Sends notifications:
- **Audit Summary** — Pass rate, control breakdown, critical findings
- **Critical Alerts** — Real-time failure notifications with remediation steps

## Policy Engine

Rules are registered dynamically by control ID:

```typescript
evaluator.registerRule('CC6.1', (evidence) => {
  const passed = evidence.some((e) => e.rawPayload.status === 'PASSED');
  return {
    status: passed ? 'COMPLIANT' : 'NON_COMPLIANT',
    findings: passed ? ['MFA enabled.'] : ['MFA disabled.'],
  };
});
```

## Scripts

| Script | Command | Description |
|--------|---------|-------------|
| Build | `npm run build` | Compile TypeScript |
| Dev | `npm run dev` | Run CLI with tsx |
| Server | `npm run server` | Start REST API |
| Start | `npm start` | Run compiled CLI output |
| Bundle | `npm run bundle` | Export all source to `bundle.md` |
| Prisma Generate | `npm run prisma:generate` | Generate Prisma client |
| Prisma Push | `npm run prisma:push` | Push schema to database |

## Roadmap

- [x] Initial repo scaffolding & TS build settings
- [x] Zod domain models & SOC 2 types
- [x] Dynamic rule engine & policy evaluator
- [x] Autonomous remediation engine
- [x] Abstract adapter interface
- [x] AWS SDK adapter + remediator (LIVE + MOCK)
- [x] GitHub API adapter + remediator (LIVE + MOCK)
- [x] Autonomous agent runtime orchestrator
- [x] PostgreSQL Prisma persistence schema
- [x] Database service layer
- [x] Runnable main execution pipeline
- [x] Zero-dependency bundling script
- [x] Slack / Webhook notification adapter
- [x] REST API Endpoints for UI / External Triggering
- [ ] Web dashboard (React/Vue)
- [ ] Policy template library (50+ pre-built controls)
- [ ] Evidence export / auditor portal
- [ ] Additional adapters (Azure, GCP, Okta, Jira)

## License

MIT

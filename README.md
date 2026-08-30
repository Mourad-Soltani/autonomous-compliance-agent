# Autonomous Compliance Agent

> Autonomous AI agent for continuous SOC 2 compliance evaluation and evidence collection.

## Overview

This TypeScript-based platform continuously audits your cloud infrastructure and code repositories against SOC 2 Trust Services Criteria, evaluates collected evidence against dynamic policy rules, and persists audit reports to PostgreSQL.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AWS Adapter   │     │ GitHub Adapter  │     │  Slack Adapter  │
│  (CC6.1, CC7.2) │     │    (CC6.8)      │     │  (Alerts)       │
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
npm run dev
```

### 5. Start REST API Server

```bash
npx tsx src/server.ts
```

The API will be available at `http://localhost:3000`.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/audit` | Trigger a new compliance audit |
| `GET` | `/audit/runs` | List recent audit runs |
| `GET` | `/audit/runs/:id` | Get a specific audit run |
| `GET` | `/controls` | List all SOC 2 controls |
| `GET` | `/controls/:id` | Get a specific control |
| `GET` | `/evidence` | List collected evidence |

## Project Structure

```
├── prisma/
│   └── schema.prisma       # PostgreSQL schema
├── scripts/
│   └── bundle.js           # Zero-dependency code bundler
├── src/
│   ├── adapters/
│   │   ├── base.adapter.ts     # Abstract adapter interface
│   │   ├── aws.adapter.ts      # AWS Security Hub / CloudTrail
│   │   ├── github.adapter.ts   # GitHub branch protection
│   │   └── slack.adapter.ts    # Slack notifications
│   ├── agents/
│   │   └── audit.agent.ts      # Audit orchestrator
│   ├── core/
│   │   └── db.ts               # Prisma database service
│   ├── policies/
│   │   └── evaluator.ts        # Dynamic rule engine
│   ├── types/
│   │   └── policy.ts           # Zod schemas & TypeScript types
│   ├── index.ts                # CLI entry point
│   └── server.ts               # REST API server
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

### AWS Adapter
Collects evidence from:
- **AWS Security Hub** — IAM MFA, password policies (CC6.1)
- **AWS CloudTrail** — Audit trail logging status (CC7.2)

### GitHub Adapter
Collects evidence from:
- **Branch Protection** — Required PR reviews, status checks (CC6.8)

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
| Start | `npm start` | Run compiled output |
| Bundle | `npm run bundle` | Export all source to `bundle.md` |
| Prisma Generate | `npm run prisma:generate` | Generate Prisma client |
| Prisma Push | `npm run prisma:push` | Push schema to database |

## Roadmap

- [x] Initial repo scaffolding & TS build settings
- [x] Zod domain models & SOC 2 types
- [x] Dynamic rule engine & policy evaluator
- [x] Abstract adapter interface
- [x] AWS CloudTrail / Security Hub adapter
- [x] GitHub branch protection adapter
- [x] Autonomous agent runtime orchestrator
- [x] PostgreSQL Prisma persistence schema
- [x] Database service layer
- [x] Runnable main execution pipeline
- [x] Zero-dependency bundling script
- [x] Slack / Webhook notification adapter
- [x] REST API Endpoints for UI / External Triggering
- [ ] Autonomous remediation (fix misconfigurations automatically)
- [ ] Web dashboard (React/Vue)
- [ ] Policy template library (50+ pre-built controls)
- [ ] Evidence export / auditor portal
- [ ] Additional adapters (Azure, GCP, Okta, Jira)

## License

MIT

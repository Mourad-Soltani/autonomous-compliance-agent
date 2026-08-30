# 🤖 Autonomous Compliance Agent

> Multi-cloud SOC 2 compliance automation platform with autonomous remediation, policy templates, evidence export, CIS benchmarks, and an auditor-ready web portal.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)
[![Prisma](https://img.shields.io/badge/Prisma-ORM-2D3748)](https://www.prisma.io/)
[![SOC 2](https://img.shields.io/badge/SOC%202-Trust%20Service%20Categories-green)](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
[![CIS](https://img.shields.io/badge/CIS-Benchmarks-orange)](https://www.cisecurity.org/cis-benchmarks)

---

## 🚀 Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Policy Template Library** | ✅ LIVE | 25 pre-built SOC 2 controls across all 5 Trust Service Categories |
| **CIS Benchmarks** | ✅ LIVE | 45 CIS controls mapped to SOC 2 (AWS, Azure, GCP) |
| **Custom Control Builder** | ✅ LIVE | No-code UI for creating custom compliance controls |
| **Multi-Cloud Adapters** | ✅ LIVE | AWS, Azure, GCP, GitHub |
| **Autonomous Remediation** | ✅ LIVE | Auto-fix violations with rollback support |
| **Evidence Export** | ✅ LIVE | CSV, JSON, Markdown, HTML auditor reports |
| **Auditor Portal** | ✅ LIVE | Print-ready HTML dashboard for external auditors |
| **Web Dashboard** | ✅ LIVE | Dark-themed React dashboard for real-time monitoring |
| **REST API** | ✅ LIVE | Full CRUD + trigger endpoints |
| **Notifications** | ✅ LIVE | Slack + generic webhook alerts |
| **Zero-Dependency Bundle** | ✅ LIVE | Single-file deploy script |

---

## 📁 Project Structure

```
├── src/
│   ├── adapters/           # Cloud SDK adapters + remediators
│   │   ├── aws.adapter.ts
│   │   ├── aws.remediator.ts
│   │   ├── github.adapter.ts
│   │   ├── github.remediator.ts
│   │   ├── azure.adapter.ts
│   │   ├── azure.remediator.ts
│   │   ├── gcp.adapter.ts
│   │   └── gcp.remediator.ts
│   ├── api/                # REST API routes & middleware
│   │   ├── routes/
│   │   │   ├── audit.routes.ts
│   │   │   ├── control.routes.ts
│   │   │   ├── template.routes.ts
│   │   │   ├── export.routes.ts
│   │   │   ├── adapter.routes.ts
│   │   │   └── custom-control.routes.ts
│   │   └── middleware/
│   ├── core/               # Rule engine, evaluator, export
│   │   ├── rule-engine.ts
│   │   ├── policy-evaluator.ts
│   │   ├── remediation-engine.ts
│   │   └── export.ts
│   ├── dashboard/          # React web UI
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── AuditRuns.tsx
│   │   │   ├── Controls.tsx
│   │   │   ├── AuditorPortal.tsx
│   │   │   └── CustomControlBuilder.tsx
│   │   └── components/
│   ├── db/                 # Prisma schema + service layer
│   ├── models/             # Zod domain models
│   ├── notifications/      # Slack & webhook adapters
│   ├── templates/          # SOC 2 + CIS control templates
│   │   ├── controls.ts
│   │   ├── cis-benchmarks.ts
│   │   └── loader.ts
│   ├── types/              # Shared TypeScript types
│   ├── cli/                # CLI commands
│   └── index.ts            # Entry point
├── scripts/
│   └── bundle.js           # Zero-dependency bundler
├── prisma/
│   └── schema.prisma
├── .env.example
└── README.md
```

---

## 🛠️ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/Mourad-Soltani/autonomous-compliance-agent.git
cd autonomous-compliance-agent
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your cloud credentials
```

### 3. Database Setup

```bash
npx prisma migrate dev --name init
npx prisma generate
```

### 4. Seed Policy Templates

```bash
npx tsx src/index.ts --templates
# Or seed only automated controls:
npx tsx src/index.ts --templates --automated-only
```

### 5. Start Server

```bash
npm run dev        # Development
npm start          # Production
```

---

## ☁️ Cloud Adapters

### AWS
- **CC6.1** — IAM password policy, MFA enforcement
- **CC6.6** — S3 bucket encryption & public access blocks
- **CC6.7** — Security group hardening
- **CIS-AWS-1.4–5.1** — 18 CIS benchmark checks

### Azure
- **CC6.1** — Key Vault access policies, purge protection, RBAC
- **CC6.6** — Storage encryption (HTTPS-only, customer-managed keys, soft-delete)
- **CC6.7** — NSG hardening (default deny inbound, SSH/RDP restriction)
- **CIS-AZURE-1.1–7.1** — 15 CIS benchmark checks

### GCP
- **CC6.1** — IAM overly permissive bindings, audit logging
- **CC6.6** — GCS uniform access, public access prevention, CMEK, versioning
- **CC6.7** — Firewall rules (SSH/RDP from internet, default-allow rules)
- **CC7.2** — Cloud KMS key management
- **CIS-GCP-1.1–7.1** — 12 CIS benchmark checks

### GitHub
- **CC6.1** — Branch protection rules, required reviews
- **CC7.2** — Secret scanning & dependency alerts

---

## 📊 API Endpoints

### Audit Runs
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/audit/run` | Trigger new compliance scan |
| `GET`  | `/audit/runs` | List all audit runs |
| `GET`  | `/audit/runs/:id` | Get audit run details |
| `GET`  | `/audit/runs/:id/export?format=csv` | Export CSV report |
| `GET`  | `/audit/runs/:id/export?format=json` | Export JSON report |
| `GET`  | `/audit/runs/:id/export?format=markdown` | Export Markdown report |
| `GET`  | `/audit/runs/:id/export?format=html` | Export HTML report |
| `GET`  | `/audit/runs/:id/auditor` | Auditor portal (print-ready HTML) |

### Controls & Templates
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/controls` | List all controls |
| `GET`  | `/templates` | List policy templates with stats |
| `POST` | `/templates/seed` | Seed database from templates |

### Custom Controls
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/controls/custom` | List custom controls |
| `POST` | `/controls/custom` | Create custom control |
| `GET`  | `/controls/custom/:id` | Get custom control |
| `PUT`  | `/controls/custom/:id` | Update custom control |
| `DELETE` | `/controls/custom/:id` | Delete custom control |
| `POST` | `/controls/custom/:id/test` | Test control check |
| `POST` | `/controls/custom/:id/activate` | Activate control |
| `POST` | `/controls/custom/:id/deactivate` | Deactivate control |

### Adapters
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/adapters/:name/scan` | Trigger adapter scan |
| `POST` | `/adapters/:name/remediate` | Trigger remediation |

---

## 🖥️ CLI Commands

```bash
# Run full compliance scan
npx tsx src/index.ts --scan

# Run scan for specific adapter
npx tsx src/index.ts --scan --adapter aws

# Trigger remediation
npx tsx src/index.ts --remediate --finding-id <id>

# Seed templates
npx tsx src/index.ts --templates
npx tsx src/index.ts --templates --category SECURITY

# Export evidence
npx tsx src/index.ts --export --run-id <id> --format html

# Bundle for deployment
node scripts/bundle.js
```

---

## 📦 Zero-Dependency Bundle

Deploy anywhere with a single file:

```bash
node scripts/bundle.js
# Outputs: dist/bundle.ts
```

---

## 🗺️ Roadmap

- [x] Initial repo scaffolding & TS build settings
- [x] Zod domain models & SOC 2 types
- [x] Dynamic rule engine & policy evaluator
- [x] Autonomous remediation engine
- [x] Abstract adapter interface
- [x] AWS SDK adapter + remediator (LIVE + MOCK)
- [x] GitHub API adapter + remediator (LIVE + MOCK)
- [x] Azure SDK adapter + remediator (LIVE + MOCK)
- [x] GCP SDK adapter + remediator (LIVE + MOCK)
- [x] Autonomous agent runtime orchestrator
- [x] PostgreSQL Prisma persistence schema
- [x] Database service layer
- [x] Runnable main execution pipeline
- [x] Zero-dependency bundling script
- [x] Slack / Webhook notification adapter
- [x] REST API Endpoints for UI / External Triggering
- [x] Web Dashboard (Dark Theme)
- [x] Policy template library (25 controls)
- [x] Evidence export / auditor portal
- [x] CIS Benchmarks integration (45 controls)
- [x] Custom control builder UI
- [ ] Kubernetes / Container adapter (future)
- [ ] Compliance-as-Code Terraform provider (future)

---

## 💰 Commercial Potential

| Metric | Value |
|--------|-------|
| One-time codebase sale | $40,000 – $80,000 |
| SaaS launch price | $999 – $2,499 / month |
| Status | Enterprise multi-cloud compliance platform with CIS benchmarks, custom controls, and full audit lifecycle |

---

## 📄 License

MIT — See [LICENSE](LICENSE) for details.

---

Built with 🔒 by Mourad Soltani

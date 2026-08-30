# Architecture Overview

> System design, data flow, and component interactions for the Autonomous Compliance Agent.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Web UI     │  │   CLI       │  │  CI/CD      │  │  External Systems   │ │
│  │  (React)    │  │  (Node.js)  │  │  (GitHub    │  │  (Slack, Webhook)   │ │
│  │             │  │             │  │   Actions)  │  │                     │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                │                    │            │
└─────────┼────────────────┼────────────────┼────────────────────┼────────────┘
          │                │                │                    │
          └────────────────┴────────────────┴────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API LAYER                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    Express.js REST API Server                            │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │ │
│  │  │ /audit/*     │ │ /controls/*  │ │ /templates/* │ │ /adapters/*  │   │ │
│  │  │ Audit Routes │ │ Control      │ │ Template     │ │ Adapter      │   │ │
│  │  │              │ │ Routes       │ │ Routes       │ │ Routes       │   │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                    │ │
│  │  │ /export/*    │ │ /health/*    │ │ Middleware   │                    │ │
│  │  │ Export       │ │ Health       │ │ (Auth,       │                    │ │
│  │  │ Routes       │ │ Routes       │ │  Rate Limit) │                    │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘                    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CORE ENGINE LAYER                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Rule Engine  │  │ Policy       │  │ Remediation  │  │ Export       │    │
│  │              │  │ Evaluator    │  │ Engine       │  │ Engine       │    │
│  │ • Parses     │  │              │  │              │  │              │    │
│  │   control    │  │ • Matches    │  │ • Auto-fix   │  │ • CSV        │    │
│  │   definitions│  │   evidence   │  │   findings   │  │ • JSON       │    │
│  │ • Executes   │  │   against    │  │ • Rollback   │  │ • Markdown   │    │
│  │   checks     │  │   policies   │  │   support    │  │ • HTML       │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │                 │            │
└─────────┼─────────────────┼─────────────────┼─────────────────┼────────────┘
          │                 │                 │                 │
          └─────────────────┴─────────────────┴─────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ADAPTER LAYER                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ AWS Adapter  │  │ Azure Adapter│  │ GCP Adapter  │  │ GitHub       │    │
│  │ + Remediator │  │ + Remediator │  │ + Remediator │  │ Adapter      │    │
│  │              │  │              │  │              │  │ + Remediator │    │
│  │ • IAM        │  │ • Key Vault  │  │ • Cloud IAM  │  │ • Branch     │    │
│  │ • S3         │  │ • Storage    │  │ • GCS        │  │   Protection │    │
│  │ • EC2/SG     │  │ • NSG        │  │ • VPC        │  │ • Secrets    │    │
│  │ • CloudTrail │  │ • SQL TDE    │  │ • Cloud SQL  │  │   Scanning   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    Base Adapter Interface                                │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │ │
│  │  │ scan()     │  │ remediate()│  │ validate() │  │ rollback() │       │ │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘       │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA LAYER                                           │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐  │
│  │   PostgreSQL        │  │      Redis          │  │   File System       │  │
│  │   (Prisma ORM)      │  │      (Cache/Queue)  │  │   (Exports/Logs)    │  │
│  │                     │  │                     │  │                     │  │
│  │  • Audit Runs       │  │  • Session cache    │  │  • CSV reports      │  │
│  │  • Controls         │  │  • Rate limiting    │  │  • JSON exports     │  │
│  │  • Findings         │  │  • Job queues       │  │  • HTML auditor     │  │
│  │  • Evidence         │  │  • Real-time stats  │  │    portals          │  │
│  │  • Remediation      │  │                     │  │  • Application      │  │
│  │    Actions          │  │                     │  │    logs             │  │
│  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow: Compliance Scan

```
1. Trigger          2. Orchestrate        3. Scan              4. Evaluate
   │                    │                    │                    │
   ▼                    ▼                    ▼                    ▼
┌──────┐         ┌──────────┐        ┌──────────┐        ┌──────────┐
│ User │────────▶│ Agent    │───────▶│ Adapter  │───────▶│ Policy   │
│      │  POST   │ Runtime  │ invoke │ (AWS/    │ collect│ Evaluator│
│      │ /audit/ │          │        │ Azure/   │        │          │
│      │ run     │          │        │ GCP/GH)  │        │          │
└──────┘         └──────────┘        └──────────┘        └────┬─────┘
                                                              │
                                   ┌──────────────────────────┘
                                   │
                                   ▼
                            ┌──────────┐
                            │ Finding  │──────▶┌──────────────┐
                            │ Created  │       │ Notification │
                            └────┬─────┘       │ (Slack/Web)  │
                                 │             └──────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
            ┌──────────┐              ┌──────────┐
            │ Evidence │              │ Remedia- │
            │ Stored   │              │ tion     │
            └──────────┘              │ Engine   │
                                      └────┬─────┘
                                           │
                                           ▼
                                    ┌──────────┐
                                    │ Auto-fix │
                                    │ Applied  │
                                    └──────────┘
```

---

## Database Schema

### Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   AuditRun      │       │    Control      │       │    Finding      │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id (PK)         │       │ id (PK)         │       │ id (PK)         │
│ name            │       │ title           │       │ controlId (FK)  │
│ status          │       │ description     │       │ auditRunId (FK) │
│ startedAt       │       │ category        │       │ title           │
│ completedAt     │       │ soc2Mapping     │       │ description     │
│ totalControls   │       │ severity        │       │ severity        │
│ passedControls  │       │ automated       │       │ status          │
│ failedControls  │       │ adapter         │       │ resource        │
│ errorControls   │       │ status          │       │ adapter         │
│ findingsCount   │       │ createdAt       │       │ remediationAvail│
│ adapters[]      │       │ updatedAt       │       │ createdAt       │
└─────────────────┘       └─────────────────┘       └─────────────────┘
         │                         │                         │
         │                         │                         │
         │              ┌──────────┴──────────┐              │
         │              │                     │              │
         │              ▼                     ▼              │
         │       ┌─────────────────┐  ┌─────────────────┐   │
         │       │    Evidence     │  │ RemediationAction│   │
         │       ├─────────────────┤  ├─────────────────┤   │
         └──────▶│ auditRunId (FK) │  │ id (PK)         │◀──┘
                 │ controlId (FK)  │  │ findingId (FK)  │
                 │ adapter         │  │ adapter         │
                 │ resource        │  │ actionTaken     │
                 │ rawData (JSON)  │  │ success         │
                 │ severity        │  │ message         │
                 │ collectedAt     │  │ executedAt      │
                 └─────────────────┘  │ rolledBack      │
                                      └─────────────────┘
```

### Key Design Decisions

1. **JSONB for Evidence**: Evidence `rawData` is stored as JSONB in PostgreSQL for flexible schema evolution across different cloud providers.

2. **Soft Deletes**: All entities use soft deletes (optional `deletedAt` field) to maintain audit trail integrity.

3. **Indexing Strategy**:
   - `AuditRun`: Indexed on `status`, `startedAt`, `adapters`
   - `Finding`: Indexed on `controlId`, `status`, `severity`, `adapter`, `auditRunId`
   - `Evidence`: Indexed on `controlId`, `adapter`, `collectedAt`

4. **Partitioning**: For high-volume deployments, `Evidence` and `Finding` tables should be partitioned by `collectedAt` month.

---

## Adapter Architecture

### Base Adapter Interface

All cloud adapters implement a common interface:

```typescript
interface BaseAdapter {
  readonly name: string;
  readonly config: AdapterConfig;

  scan(): Promise<AdapterScanResult>;
  validateConfig(): Promise<boolean>;
  getHealth(): Promise<AdapterHealth>;
}

interface BaseRemediator {
  readonly name: string;

  remediate(finding: Finding): Promise<RemediationResult>;
  rollback(action: RemediationAction): Promise<RollbackResult>;
  validateAction(action: RemediationAction): Promise<boolean>;
}
```

### Adapter Lifecycle

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Initialize │───▶│   Validate  │───▶│    Scan     │───▶│   Report    │
│             │    │   Config    │    │             │    │             │
│ • Load SDK  │    │ • Check     │    │ • Collect   │    │ • Findings  │
│ • Auth      │    │   creds     │    │   evidence  │    │ • Evidence  │
│ • Set region│    │ • Verify    │    │ • Evaluate  │    │ • Metrics   │
│             │    │   perms     │    │   policies  │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                               │
                                                               ▼
                                                        ┌─────────────┐
                                                        │  Remediate  │
                                                        │  (optional) │
                                                        │             │
                                                        │ • Auto-fix  │
                                                        │ • Rollback  │
                                                        │   support   │
                                                        └─────────────┘
```

---

## Security Architecture

### Defense in Depth

| Layer | Measures |
|-------|----------|
| **Network** | Nginx reverse proxy, rate limiting, TLS 1.2+, private subnets |
| **Application** | Input validation (Zod), parameterized queries, CORS policies |
| **Authentication** | API key auth (v1.1: OAuth2 / SAML SSO) |
| **Authorization** | RBAC with role-based access to controls and findings |
| **Data** | Encryption at rest (PostgreSQL TDE), encryption in transit (TLS) |
| **Secrets** | Environment variables, AWS Secrets Manager / Azure Key Vault integration |
| **Audit** | All actions logged with user ID, timestamp, and IP address |

### Secret Management

```
┌─────────────────┐
│   Application   │
│   (Container)   │
└────────┬────────┘
         │ reads
         ▼
┌─────────────────┐     ┌─────────────────┐
│  Environment    │     │  Cloud Secret   │
│  Variables      │────▶│  Manager        │
│  (.env / k8s)   │     │  (AWS/Azure/GCP)│
└─────────────────┘     └─────────────────┘
```

---

## Scalability Considerations

### Horizontal Scaling

```
                    ┌─────────────┐
                    │   Nginx LB  │
                    │  (Round-robin)
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  ACA App    │ │  ACA App    │ │  ACA App    │
    │  Instance 1 │ │  Instance 2 │ │  Instance N │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                    ┌──────┴──────┐
                    │   Shared    │
                    │  PostgreSQL │
                    │   + Redis   │
                    └─────────────┘
```

### Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| API response time (p95) | < 200ms | ~ 150ms |
| Scan duration (100 controls) | < 5 min | ~ 3 min |
| Concurrent scans | 10 | 5 |
| Dashboard load time | < 2s | ~ 1.2s |
| Export generation (10K findings) | < 30s | ~ 15s |

### Caching Strategy

| Cache Layer | TTL | Purpose |
|-------------|-----|---------|
| Redis — Control definitions | 1 hour | Reduce DB reads |
| Redis — Adapter health | 30s | Quick status checks |
| Redis — Rate limits | 1 min | API throttling |
| Redis — Session data | 24h | User sessions |
| Nginx — Static assets | 1 day | Dashboard assets |
| Nginx — Export files | 7 days | Evidence downloads |

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18 + TypeScript | Dashboard UI |
| **Backend** | Node.js 20 + Express | API server |
| **ORM** | Prisma | Database access |
| **Validation** | Zod | Schema validation |
| **Database** | PostgreSQL 16 | Primary data store |
| **Cache** | Redis 7 | Caching & queues |
| **Reverse Proxy** | Nginx | SSL, rate limiting |
| **Container** | Docker + Compose | Deployment |
| **CI/CD** | GitHub Actions | Build & deploy |
| **Monitoring** | Health endpoints + logs | Observability |
| **Cloud SDKs** | AWS SDK v3, Azure SDK, GCP SDK | Adapter integrations |

---

## Deployment Patterns

### Single Node (Development / Small Team)

```
┌─────────────────────────────────────┐
│            VPS / VM                 │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌──────┐ │
│  │App  │ │DB   │ │Redis│ │Nginx │ │
│  │:3000│ │:5432│ │:6379│ │:80/443│ │
│  └─────┘ └─────┘ └─────┘ └──────┘ │
└─────────────────────────────────────┘
```

### Multi-Node (Production)

```
┌─────────────┐     ┌─────────────────────────────┐
│   Nginx LB  │────▶│      ACA App Cluster        │
│  (SSL term) │     │  ┌─────┐ ┌─────┐ ┌─────┐   │
└─────────────┘     │  │App 1│ │App 2│ │App N│   │
                    │  └─────┘ └─────┘ └─────┘   │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────┴───────────────┐
                    │      Data Tier              │
                    │  ┌─────────┐  ┌─────────┐   │
                    │  │PostgreSQL│  │  Redis  │   │
                    │  │ Primary │  │ Cluster │   │
                    │  │+ Replica│  │         │   │
                    │  └─────────┘  └─────────┘   │
                    └─────────────────────────────┘
```

---

## Future Architecture Evolution

### v1.1 — Authentication & Multi-Tenancy
- JWT-based auth with refresh tokens
- Organization isolation in PostgreSQL (row-level security)
- SAML SSO integration

### v1.2 — Distributed Scanning
- Redis-backed job queue (BullMQ)
- Worker processes for long-running scans
- Real-time WebSocket updates to dashboard

### v1.3 — Kubernetes Native
- Helm charts for deployment
- Horizontal Pod Autoscaler
- Prometheus + Grafana monitoring
- Istio service mesh

### v2.0 — Compliance-as-Code
- Terraform provider for control definitions
- GitOps workflow for policy changes
- Drift detection and continuous compliance

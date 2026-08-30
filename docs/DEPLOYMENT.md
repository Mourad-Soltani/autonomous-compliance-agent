# Deployment Guide

> Complete instructions for deploying the Autonomous Compliance Agent in production, staging, and development environments.

---

## Table of Contents

1. [Quick Start (Docker Compose)](#quick-start-docker-compose)
2. [Production Deployment](#production-deployment)
3. [Environment Variables](#environment-variables)
4. [Database Setup](#database-setup)
5. [SSL/TLS Configuration](#ssltls-configuration)
6. [Monitoring & Health Checks](#monitoring--health-checks)
7. [Backup & Recovery](#backup--recovery)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start (Docker Compose)

The fastest way to get running:

```bash
# 1. Clone the repository
git clone https://github.com/Mourad-Soltani/autonomous-compliance-agent.git
cd autonomous-compliance-agent

# 2. Create environment file
cp .env.example .env
# Edit .env with your credentials

# 3. Start the stack
docker-compose up -d

# 4. Run database migrations
docker-compose exec app npx prisma migrate deploy

# 5. Seed demo data (optional)
docker-compose exec app npx tsx scripts/seed-demo.ts

# 6. Access the dashboard
open http://localhost:3000
```

### Services Started

| Service | Port | Purpose |
|---------|------|---------|
| ACA App | 3000 | Main application API + dashboard |
| PostgreSQL | 5432 | Primary database |
| Redis | 6379 | Cache & job queue |
| Nginx | 80/443 | Reverse proxy + SSL |
| Prisma Studio | 5555 | Database admin UI (dev profile) |

---

## Production Deployment

### Prerequisites

- Docker Engine 24.0+ and Docker Compose 2.20+
- 4 CPU cores, 8GB RAM minimum
- 50GB disk space
- Valid SSL certificates
- PostgreSQL 16+ (managed or containerized)

### Step-by-Step

#### 1. Provision Infrastructure

**Option A: VPS (DigitalOcean, Hetzner, AWS EC2)**
```bash
# Ubuntu 22.04 LTS recommended
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
```

**Option B: Kubernetes**
```bash
# See k8s/ directory for manifests (coming soon)
kubectl apply -f k8s/
```

#### 2. Configure Environment

Create a production `.env`:

```bash
# Server
NODE_ENV=production
PORT=3000

# Database (use managed Postgres for production)
DATABASE_URL=postgresql://aca:${DB_PASSWORD}@db.example.com:5432/compliance_prod?schema=public

# Redis
REDIS_URL=redis://redis.example.com:6379

# Cloud Credentials (use IAM roles where possible)
AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=...  # Only if not using IAM roles
# AWS_SECRET_ACCESS_KEY=...

AZURE_SUBSCRIPTION_ID=...
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz

# Export directory
EXPORT_DIR=/var/lib/aca/exports
```

#### 3. Deploy with Docker Compose

```bash
# Pull latest images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml pull

# Start services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify health
curl -f https://your-domain.com/health
```

#### 4. Run Migrations

```bash
docker-compose exec app npx prisma migrate deploy
```

#### 5. Seed Initial Data

```bash
# Seed policy templates
docker-compose exec app npx tsx src/index.ts --templates

# Seed demo data (for evaluation only)
docker-compose exec app npx tsx scripts/seed-demo.ts
```

---

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `PORT` | HTTP server port | `3000` |

### Cloud Adapters (at least one required for scans)

| Variable | Cloud | Required For |
|----------|-------|-------------|
| `AWS_REGION` | AWS | All AWS scans |
| `AWS_ACCESS_KEY_ID` | AWS | AWS scans (if not using IAM roles) |
| `AWS_SECRET_ACCESS_KEY` | AWS | AWS scans (if not using IAM roles) |
| `AZURE_SUBSCRIPTION_ID` | Azure | All Azure scans |
| `AZURE_TENANT_ID` | Azure | Azure auth |
| `AZURE_CLIENT_ID` | Azure | Azure auth |
| `AZURE_CLIENT_SECRET` | Azure | Azure auth |
| `GITHUB_TOKEN` | GitHub | GitHub scans |
| `GITHUB_OWNER` | GitHub | GitHub scans |
| `GITHUB_REPO` | GitHub | GitHub scans |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis cache connection | — |
| `SLACK_WEBHOOK_URL` | Slack notifications | — |
| `WEBHOOK_URL` | Generic webhook URL | — |
| `EXPORT_DIR` | Evidence export directory | `./exports` |
| `LOG_LEVEL` | Logging verbosity | `info` |
| `MAX_SCAN_CONCURRENCY` | Parallel scan limit | `5` |

---

## Database Setup

### Initial Migration

```bash
# Generate Prisma client
npx prisma generate

# Run migrations
npx prisma migrate deploy

# (Optional) Open Studio for inspection
npx prisma studio
```

### Backup Strategy

```bash
# Automated daily backup via cron
0 2 * * * pg_dump -h db.example.com -U aca compliance_prod > /backups/aca-$(date +\%Y\%m\%d).sql

# Restore from backup
psql -h db.example.com -U aca compliance_prod < backup-file.sql
```

### Performance Tuning

Recommended PostgreSQL settings for production:

```conf
# postgresql.conf
max_connections = 200
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 5242kB
min_wal_size = 1GB
max_wal_size = 4GB
```

---

## SSL/TLS Configuration

### Using Let\'s Encrypt (Recommended)

```bash
# Install certbot
sudo apt install certbot

# Generate certificates
sudo certbot certonly --standalone -d your-domain.com

# Copy to nginx SSL directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem

# Auto-renewal cron
0 3 * * * certbot renew --quiet && docker-compose restart nginx
```

### Using Custom Certificates

Place your `cert.pem` and `key.pem` in `nginx/ssl/` and restart:

```bash
docker-compose restart nginx
```

---

## Monitoring & Health Checks

### Built-in Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness probe — returns 200 if app is running |
| `GET /health/ready` | Readiness probe — checks DB connectivity |
| `GET /health/metrics` | Prometheus-compatible metrics |

### Docker Health Checks

All services include health checks:
- **App**: HTTP check on `/health` every 30s
- **DB**: `pg_isready` every 10s
- **Redis**: `redis-cli ping` every 10s

### Log Aggregation

```bash
# View all logs
docker-compose logs -f

# View app logs only
docker-compose logs -f app

# Export logs
docker-compose logs app > app-logs-$(date +%Y%m%d).txt
```

---

## Backup & Recovery

### Full Stack Backup

```bash
#!/bin/bash
# backup.sh — Run daily via cron

DATE=$(date +%Y%m%d)
BACKUP_DIR=/backups/aca/$DATE
mkdir -p $BACKUP_DIR

# Database
docker-compose exec -T db pg_dump -U compliance compliance_db > $BACKUP_DIR/database.sql

# Evidence exports
docker cp aca-app:/app/exports $BACKUP_DIR/exports

# Environment config
cp .env $BACKUP_DIR/.env

# Compress
tar czf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

# Keep only last 30 days
find /backups/aca -name "*.tar.gz" -mtime +30 -delete
```

### Disaster Recovery

```bash
# 1. Restore database
psql -h db.example.com -U compliance compliance_db < database.sql

# 2. Restore exports
docker cp exports aca-app:/app/exports

# 3. Restart stack
docker-compose up -d
```

---

## Troubleshooting

### Container Won\'t Start

```bash
# Check logs
docker-compose logs app

# Common issues:
# - Missing .env file → cp .env.example .env
# - Port conflict → change PORT in .env
# - DB not ready → wait for db health check: docker-compose ps
```

### Database Connection Errors

```bash
# Test connection from app container
docker-compose exec app node -e "
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient();
  prisma.$connect().then(() => console.log('OK')).catch(e => console.error(e));
"
```

### High Memory Usage

```bash
# Check container stats
docker stats

# Restart app container
docker-compose restart app

# Adjust Node.js memory limit
# Add to docker-compose.yml: NODE_OPTIONS=--max-old-space-size=4096
```

### Scan Timeouts

```bash
# Increase scan timeout in .env
MAX_SCAN_DURATION=3600000  # 1 hour in ms

# Or run scans with longer timeout via CLI
npx tsx src/index.ts --scan --timeout 3600
```

---

## Support

For issues not covered here:

1. Check [GitHub Issues](https://github.com/Mourad-Soltani/autonomous-compliance-agent/issues)
2. Review application logs: `docker-compose logs app`
3. Open a new issue with logs and reproduction steps

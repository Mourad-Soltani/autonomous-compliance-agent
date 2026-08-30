# API Reference

> Complete REST API documentation for the Autonomous Compliance Agent.

**Base URL**: `https://api.aca.example.com/v1`  
**Content-Type**: `application/json`  
**Authentication**: Bearer token (coming in v1.1)

---

## Endpoints Overview

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| **Health** | `/health` | GET | Service health check |
| **Audit** | `/audit/run` | POST | Trigger compliance scan |
| **Audit** | `/audit/runs` | GET | List all audit runs |
| **Audit** | `/audit/runs/:id` | GET | Get audit run details |
| **Audit** | `/audit/runs/:id/export` | GET | Export evidence (csv/json/md/html) |
| **Audit** | `/audit/runs/:id/auditor` | GET | Auditor portal HTML view |
| **Controls** | `/controls` | GET | List all controls |
| **Controls** | `/controls/custom` | GET | List custom controls |
| **Controls** | `/controls/custom` | POST | Create custom control |
| **Controls** | `/controls/custom/:id` | GET | Get custom control |
| **Controls** | `/controls/custom/:id` | PUT | Update custom control |
| **Controls** | `/controls/custom/:id` | DELETE | Delete custom control |
| **Controls** | `/controls/custom/:id/test` | POST | Test custom control |
| **Templates** | `/templates` | GET | List policy templates |
| **Templates** | `/templates/seed` | POST | Seed database from templates |
| **Adapters** | `/adapters/:name/scan` | POST | Trigger adapter scan |
| **Adapters** | `/adapters/:name/remediate` | POST | Trigger remediation |

---

## Health

### GET /health

Check if the service is running.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-08-30T17:30:00.000Z",
  "version": "1.0.0",
  "uptime": 86400
}
```

**Status Codes**:
- `200` — Service is healthy
- `503` — Service is unhealthy (DB disconnected)

---

## Audit Runs

### POST /audit/run

Trigger a new compliance scan across all configured adapters.

**Request Body**:
```json
{
  "name": "Monthly Compliance Scan",
  "adapters": ["aws", "azure", "gcp"],
  "controls": ["CC6.1", "CC6.6", "CC6.7"],
  "autoRemediate": false,
  "notify": true
}
```

**Parameters**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable scan name |
| `adapters` | string[] | No | Adapters to scan (default: all) |
| `controls` | string[] | No | Specific controls to check (default: all) |
| `autoRemediate` | boolean | No | Auto-fix findings (default: false) |
| `notify` | boolean | No | Send Slack/webhook notification (default: true) |

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Monthly Compliance Scan",
  "status": "RUNNING",
  "startedAt": "2026-08-30T17:30:00.000Z",
  "adapters": ["aws", "azure", "gcp"],
  "totalControls": 25,
  "message": "Scan initiated successfully"
}
```

**Status Codes**:
- `202` — Scan accepted and running
- `400` — Invalid request body
- `429` — Rate limit exceeded (max 5 concurrent scans)

---

### GET /audit/runs

List all audit runs with pagination.

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `limit` | integer | 20 | Items per page (max 100) |
| `status` | string | — | Filter by status: `RUNNING`, `COMPLETED`, `FAILED` |
| `adapter` | string | — | Filter by adapter name |

**Response**:
```json
{
  "runs": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Monthly Compliance Scan",
      "status": "COMPLETED",
      "startedAt": "2026-08-30T17:30:00.000Z",
      "completedAt": "2026-08-30T17:45:23.000Z",
      "totalControls": 25,
      "passedControls": 19,
      "failedControls": 4,
      "errorControls": 2,
      "findingsCount": 12,
      "adapters": ["aws", "azure", "gcp"]
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 47,
    "totalPages": 3
  }
}
```

---

### GET /audit/runs/:id

Get detailed information about a specific audit run.

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Monthly Compliance Scan",
  "status": "COMPLETED",
  "startedAt": "2026-08-30T17:30:00.000Z",
  "completedAt": "2026-08-30T17:45:23.000Z",
  "duration": 923,
  "totalControls": 25,
  "passedControls": 19,
  "failedControls": 4,
  "errorControls": 2,
  "findingsCount": 12,
  "adapters": ["aws", "azure", "gcp"],
  "findingsBySeverity": {
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1
  },
  "findingsByAdapter": {
    "aws": 7,
    "azure": 3,
    "gcp": 2
  }
}
```

---

### GET /audit/runs/:id/export

Export audit run evidence in multiple formats.

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `format` | string | Yes | `csv`, `json`, `markdown`, or `html` |
| `severity` | string | No | Filter by severity |
| `status` | string | No | Filter by finding status |

**Response**: File download with appropriate `Content-Type` and `Content-Disposition` headers.

**Example**:
```bash
curl -O -J "https://api.aca.example.com/v1/audit/runs/550e8400-e29b-41d4-a716-446655440000/export?format=csv"
```

---

### GET /audit/runs/:id/auditor

Get a print-ready HTML view for external auditors.

**Response**: `text/html` — Complete auditor portal with:
- Executive summary
- Control-by-control findings
- Evidence references
- Remediation status
- Severity breakdown charts

---

## Controls

### GET /controls

List all built-in and custom controls.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Filter by category: `SECURITY`, `AVAILABILITY`, etc. |
| `adapter` | string | Filter by adapter |
| `automated` | boolean | Filter by automation status |

**Response**:
```json
{
  "controls": [
    {
      "id": "CC6.1",
      "title": "Logical and Physical Access Controls",
      "category": "SECURITY",
      "soc2Mapping": "CC6.1",
      "severity": "critical",
      "automated": true,
      "adapter": "aws",
      "status": "ACTIVE"
    }
  ],
  "count": 25,
  "byCategory": {
    "SECURITY": 14,
    "AVAILABILITY": 3,
    "CONFIDENTIALITY": 2,
    "PRIVACY": 6
  }
}
```

---

## Custom Controls

### POST /controls/custom

Create a new custom compliance control.

**Request Body**:
```json
{
  "id": "CUSTOM-SEC-001",
  "title": "Ensure custom WAF rules are active",
  "description": "Verify that all production CloudFront distributions have an active WAF ACL attached.",
  "category": "SECURITY",
  "soc2Mapping": "CC6.7",
  "severity": "high",
  "adapter": "aws",
  "checkType": "api",
  "checkConfig": "async function check() { /* ... */ }",
  "remediationEnabled": true,
  "remediationConfig": "async function remediate(finding) { /* ... */ }",
  "automated": true
}
```

**Response**:
```json
{
  "message": "Custom control created successfully",
  "control": {
    "id": "CUSTOM-SEC-001",
    "title": "Ensure custom WAF rules are active",
    "createdAt": "2026-08-30T17:30:00.000Z",
    "active": true
  }
}
```

---

### POST /controls/custom/:id/test

Test a custom control\'s check function without creating findings.

**Response**:
```json
{
  "controlId": "CUSTOM-SEC-001",
  "testedAt": "2026-08-30T17:30:00.000Z",
  "results": [
    {
      "id": "dist-abc123",
      "compliant": false,
      "details": "CloudFront distribution d-abc123 has no WAF ACL"
    }
  ],
  "passed": false
}
```

---

## Templates

### GET /templates

List all available policy templates with statistics.

**Response**:
```json
{
  "templates": [
    {
      "id": "CC6.1",
      "title": "Logical and Physical Access Controls",
      "category": "SECURITY",
      "automated": true,
      "adapter": "aws"
    }
  ],
  "stats": {
    "total": 25,
    "automated": 18,
    "manual": 7,
    "byCategory": {
      "SECURITY": 14,
      "AVAILABILITY": 3,
      "CONFIDENTIALITY": 2,
      "PRIVACY": 6
    }
  }
}
```

---

### POST /templates/seed

Seed the database with policy templates.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Only seed controls in this category |
| `automatedOnly` | boolean | Only seed automated controls |

**Response**:
```json
{
  "message": "Seeded 25 controls",
  "created": 25,
  "updated": 0,
  "category": null,
  "automatedOnly": false
}
```

---

## Adapters

### POST /adapters/:name/scan

Trigger a scan for a specific adapter.

**URL Parameters**:
| Parameter | Description |
|-----------|-------------|
| `name` | Adapter name: `aws`, `azure`, `gcp`, `github` |

**Request Body**:
```json
{
  "controls": ["CC6.1", "CC6.6"],
  "autoRemediate": false
}
```

**Response**:
```json
{
  "adapter": "aws",
  "status": "COMPLETED",
  "findings": 7,
  "evidence": 12,
  "duration": 14500
}
```

---

### POST /adapters/:name/remediate

Trigger remediation for a specific adapter\'s open findings.

**Request Body**:
```json
{
  "findingIds": ["finding-abc123", "finding-def456"],
  "dryRun": true
}
```

**Response**:
```json
{
  "adapter": "aws",
  "dryRun": true,
  "actions": [
    {
      "findingId": "finding-abc123",
      "action": "s3_public_access_blocked",
      "wouldSucceed": true
    }
  ]
}
```

---

## Error Responses

All errors follow this structure:

```json
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR",
  "details": [
    {
      "field": "checkConfig",
      "message": "Check configuration is required"
    }
  ],
  "timestamp": "2026-08-30T17:30:00.000Z",
  "requestId": "req-550e8400"
}
```

**Common Status Codes**:
| Code | Meaning |
|------|---------|
| `400` | Bad Request — Validation error |
| `401` | Unauthorized — Authentication required |
| `404` | Not Found — Resource does not exist |
| `409` | Conflict — Resource already exists |
| `429` | Too Many Requests — Rate limit exceeded |
| `500` | Internal Server Error |
| `503` | Service Unavailable — Dependency down |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `POST /audit/run` | 5 requests / minute |
| `POST /adapters/:name/scan` | 10 requests / minute |
| `POST /adapters/:name/remediate` | 3 requests / minute |
| All other endpoints | 100 requests / minute |

Rate limit headers included in all responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1693420800
```

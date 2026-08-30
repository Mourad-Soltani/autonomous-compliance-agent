# Terraform Provider for Autonomous Compliance Agent

> Manage ACA compliance controls, audit runs, and findings via Terraform.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.21 (for building)

## Installation

### From Source

```bash
git clone https://github.com/Mourad-Soltani/terraform-provider-aca.git
cd terraform-provider-aca
make install
```

### From Terraform Registry (coming soon)

```hcl
terraform {
  required_providers {
    aca = {
      source  = "Mourad-Soltani/aca"
      version = "~> 1.0.0"
    }
  }
}
```

## Provider Configuration

```hcl
provider "aca" {
  host    = "https://aca.example.com"
  api_key = var.aca_api_key  # or ACA_API_KEY env var
  timeout = 60               # seconds, default: 30
}
```

## Resources

### `aca_control`

Manages a custom compliance control.

```hcl
resource "aca_control" "example" {
  id          = "CUSTOM-SEC-001"
  title       = "Ensure WAF is Active"
  description = "Verify CloudFront distributions have WAF ACLs."
  category    = "SECURITY"
  soc2_mapping = "CC6.7"
  severity    = "high"
  adapter     = "aws"
  check_type  = "api"
  check_config = file("${path.module}/check.js")
  remediation_enabled = true
  remediation_config  = file("${path.module}/remediate.js")
  automated = true
}
```

### `aca_audit_run`

Triggers a compliance scan. This resource waits for scan completion.

```hcl
resource "aca_audit_run" "scan" {
  name           = "Weekly Scan"
  adapters       = ["aws", "azure"]
  controls       = ["CC6.1", "CC6.6"]
  auto_remediate = false
  notify         = true
}
```

## Data Sources

### `aca_template`

Fetches a built-in policy template.

```hcl
data "aca_template" "cc6_1" {
  id = "CC6.1"
}
```

### `aca_finding`

Fetches a specific finding by ID.

```hcl
data "aca_finding" "example" {
  id = "finding-abc123"
}
```

## Use Cases

### Compliance-as-Code

Define your entire compliance posture in Terraform:

```hcl
module "soc2_controls" {
  source = "./modules/soc2"

  controls = {
    "CC6.1" = { adapter = "aws", severity = "critical" },
    "CC6.6" = { adapter = "aws", severity = "high" },
    "CC6.7" = { adapter = "aws", severity = "high" },
  }
}

resource "aca_audit_run" "validate" {
  name     = "Post-Deploy Validation"
  adapters = ["aws"]
  depends_on = [module.soc2_controls]
}
```

### GitOps Workflow

1. Engineer opens PR adding a new `aca_control` resource
2. Terraform plan shows the control definition
3. On merge, control is created in ACA
4. Next scheduled scan includes the new control
5. Findings appear in dashboard

## Development

```bash
# Build
make build

# Test
make test

# Format
make fmt

# Generate docs
make docs
```

## License

MIT

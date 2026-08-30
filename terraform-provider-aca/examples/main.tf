terraform {
  required_providers {
    aca = {
      source  = "Mourad-Soltani/aca"
      version = "~> 1.0.0"
    }
  }
}

provider "aca" {
  host    = "https://aca.example.com"
  api_key = var.aca_api_key
  timeout = 60
}

# --- Data Sources ---

data "aca_template" "cc6_1" {
  id = "CC6.1"
}

output "cc6_1_title" {
  value = data.aca_template.cc6_1.title
}

# --- Custom Controls ---

resource "aca_control" "waf_check" {
  id          = "CUSTOM-WAF-001"
  title       = "Ensure CloudFront WAF is Active"
  description = "Verify all CloudFront distributions have an active WAF ACL."
  category    = "SECURITY"
  soc2_mapping = "CC6.7"
  severity    = "high"
  adapter     = "aws"
  check_type  = "api"
  check_config = <<-EOF
    async function check() {
      const { CloudFrontClient, ListDistributionsCommand } = require('@aws-sdk/client-cloudfront');
      const client = new CloudFrontClient({ region: process.env.AWS_REGION });
      const result = await client.send(new ListDistributionsCommand({}));
      return result.DistributionList.Items.map(dist => ({
        id: dist.Id,
        compliant: !!dist.WebACLId,
        details: dist.DomainName,
      }));
    }
  EOF
  remediation_enabled = true
  remediation_config = <<-EOF
    async function remediate(finding) {
      // Attach default WAF ACL
      return { success: true, message: 'WAF ACL attached', actionTaken: 'waf_attached' };
    }
  EOF
  automated = true
}

resource "aca_control" "azure_storage_encryption" {
  id          = "CUSTOM-AZ-001"
  title       = "Azure Storage Customer-Managed Keys"
  description = "All storage accounts must use customer-managed encryption keys."
  category    = "SECURITY"
  soc2_mapping = "CC6.6"
  severity    = "high"
  adapter     = "azure"
  check_type  = "api"
  check_config = <<-EOF
    async function check() {
      // Azure SDK check implementation
      return [];
    }
  EOF
  automated = true
}

# --- Audit Runs ---

resource "aca_audit_run" "monthly_scan" {
  name           = "Monthly Full Compliance Scan"
  adapters       = ["aws", "azure", "gcp"]
  controls       = ["CC6.1", "CC6.6", "CC6.7", "A1.1"]
  auto_remediate = false
  notify         = true
}

output "audit_status" {
  value = aca_audit_run.monthly_scan.status
}

output "findings_count" {
  value = aca_audit_run.monthly_scan.findings_count
}

# --- Finding Lookup ---

data "aca_finding" "critical_finding" {
  id = "finding-abc123"
}

output "finding_severity" {
  value = data.aca_finding.critical_finding.severity
}

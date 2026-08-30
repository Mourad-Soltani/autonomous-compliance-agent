import { BaseRemediator, RemediationResult } from './base.adapter';
import { Finding, FindingStatus } from '../models/finding';

interface Storage {
  buckets: {
    setIamPolicy(params: { resource: string; requestBody: { policy: { bindings: { role: string; members: string[] }[] } } }): Promise<unknown>;
    patch(params: { bucket: string; requestBody: { iamConfiguration?: { uniformBucketLevelAccess?: { enabled: boolean }; publicAccessPrevention?: string }; encryption?: { defaultKmsKeyName: string }; versioning?: { enabled: boolean } } }): Promise<unknown>;
  };
}

interface Compute {
  firewalls: {
    patch(params: { project: string; firewall: string; requestBody: { sourceRanges?: string[]; disabled?: boolean } }): Promise<unknown>;
    delete(params: { project: string; firewall: string }): Promise<unknown>;
  };
}

interface IAM {
  projects: {
    setIamPolicy(params: { resource: string; requestBody: { policy: { bindings: { role: string; members: string[] }[]; auditConfigs: { service: string; auditLogConfigs: { logType: string }[] }[] } } }): Promise<unknown>;
  };
}

interface KMS {
  projects: {
    locations: {
      keyRings: {
        cryptoKeys: {
          create(params: { parent: string; cryptoKeyId: string; requestBody: { purpose: string; versionTemplate: { algorithm: string; protectionLevel: string } } }): Promise<unknown>;
        };
      };
    };
  };
}

export class GCPRemediator extends BaseRemediator {
  private storage: Storage;
  private compute: Compute;
  private iam: IAM;
  private kms: KMS;
  private projectId: string;

  constructor(projectId: string) {
    super();
    this.projectId = projectId;
    this.storage = {} as Storage;
    this.compute = {} as Compute;
    this.iam = {} as IAM;
    this.kms = {} as KMS;
  }

  get name(): string { return 'gcp-remediator'; }

  async remediate(finding: Finding): Promise<RemediationResult> {
    try {
      switch (finding.controlId) {
        case 'CC6.1':
          return await this.remediateIAM(finding);
        case 'CC6.6':
          return await this.remediateStorage(finding);
        case 'CC6.7':
          return await this.remediateNetwork(finding);
        case 'CC7.2':
          return await this.remediateKMS(finding);
        default:
          return { success: false, message: `No remediation available for control ${finding.controlId}`, finding };
      }
    } catch (error) {
      return { success: false, message: `Remediation failed: ${error instanceof Error ? error.message : String(error)}`, finding };
    }
  }

  // ==================== CC6.1: IAM Remediation ====================
  private async remediateIAM(finding: Finding): Promise<RemediationResult> {
    if (finding.id.includes('gcp-iam-001')) {
      // Remove overly permissive bindings
      const policy = await this.iam.projects.setIamPolicy({
        resource: `projects/${this.projectId}`,
        requestBody: {
          policy: {
            bindings: [
              { role: 'roles/viewer', members: ['group:compliance-readers@example.com'] },
            ],
            auditConfigs: [
              {
                service: 'allServices',
                auditLogConfigs: [
                  { logType: 'ADMIN_READ' },
                  { logType: 'DATA_READ' },
                  { logType: 'DATA_WRITE' },
                ],
              },
            ],
          },
        },
      });
      return { success: true, message: 'Removed overly permissive IAM bindings and enabled audit logging', finding, actionTaken: 'iam_policy_restricted' };
    }

    if (finding.id.includes('gcp-iam-002')) {
      await this.iam.projects.setIamPolicy({
        resource: `projects/${this.projectId}`,
        requestBody: {
          policy: {
            bindings: [],
            auditConfigs: [
              {
                service: 'allServices',
                auditLogConfigs: [
                  { logType: 'ADMIN_READ' },
                  { logType: 'DATA_READ' },
                  { logType: 'DATA_WRITE' },
                ],
              },
            ],
          },
        },
      });
      return { success: true, message: 'Enabled data access audit logging for all services', finding, actionTaken: 'audit_logging_enabled' };
    }

    return { success: false, message: 'Unknown IAM finding type', finding };
  }

  // ==================== CC6.6: Storage Remediation ====================
  private async remediateStorage(finding: Finding): Promise<RemediationResult> {
    const bucketName = finding.resource.replace('gs://', '');

    if (finding.id.includes('gcp-storage-001')) {
      await this.storage.buckets.patch({
        bucket: bucketName,
        requestBody: {
          iamConfiguration: {
            uniformBucketLevelAccess: { enabled: true },
          },
        },
      });
      return { success: true, message: `Enabled uniform bucket-level access for ${bucketName}`, finding, actionTaken: 'uniform_access_enabled' };
    }

    if (finding.id.includes('gcp-storage-002')) {
      await this.storage.buckets.patch({
        bucket: bucketName,
        requestBody: {
          iamConfiguration: {
            publicAccessPrevention: 'enforced',
          },
        },
      });
      return { success: true, message: `Enforced public access prevention for ${bucketName}`, finding, actionTaken: 'public_access_blocked' };
    }

    if (finding.id.includes('gcp-storage-003')) {
      const kmsKeyName = `projects/${this.projectId}/locations/global/keyRings/compliance-ring/cryptoKeys/${bucketName}-key`;
      await this.storage.buckets.patch({
        bucket: bucketName,
        requestBody: {
          encryption: {
            defaultKmsKeyName: kmsKeyName,
          },
        },
      });
      return { success: true, message: `Applied CMEK to ${bucketName}`, finding, actionTaken: 'cmek_applied' };
    }

    if (finding.id.includes('gcp-storage-004')) {
      await this.storage.buckets.patch({
        bucket: bucketName,
        requestBody: {
          versioning: { enabled: true },
        },
      });
      return { success: true, message: `Enabled object versioning for ${bucketName}`, finding, actionTaken: 'versioning_enabled' };
    }

    return { success: false, message: 'Unknown storage finding type', finding };
  }

  // ==================== CC6.7: Network Remediation ====================
  private async remediateNetwork(finding: Finding): Promise<RemediationResult> {
    const firewallName = finding.resource.split('/').pop() || '';

    if (finding.id.includes('gcp-fw-001') || finding.id.includes('gcp-fw-002')) {
      // Restrict source ranges to internal/VPN ranges
      await this.compute.firewalls.patch({
        project: this.projectId,
        firewall: firewallName,
        requestBody: {
          sourceRanges: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        },
      });
      return { success: true, message: `Restricted ${firewallName} to private IP ranges`, finding, actionTaken: 'firewall_restricted' };
    }

    if (finding.id.includes('gcp-fw-003')) {
      // Delete default-allow rules (they should be replaced with explicit rules)
      await this.compute.firewalls.delete({
        project: this.projectId,
        firewall: firewallName,
      });
      return { success: true, message: `Deleted default-allow rule ${firewallName}`, finding, actionTaken: 'default_rule_deleted' };
    }

    return { success: false, message: 'Unknown network finding type', finding };
  }

  // ==================== CC7.2: KMS Remediation ====================
  private async remediateKMS(finding: Finding): Promise<RemediationResult> {
    if (finding.id.includes('gcp-kms-001')) {
      const keyName = finding.resource.split('/').pop() || '';
      // Note: Cannot change protection level on existing key. Create new HSM key and rotate.
      return {
        success: true,
        message: `HSM protection cannot be retroactively applied. New HSM key must be created and rotation performed for ${keyName}.`,
        finding,
        actionTaken: 'hsm_migration_required',
        requiresManualAction: true,
      };
    }

    if (finding.id.includes('gcp-kms-003')) {
      // Create a default compliance key ring and key
      const parent = `projects/${this.projectId}/locations/global/keyRings/compliance-ring`;
      await this.kms.projects.locations.keyRings.cryptoKeys.create({
        parent,
        cryptoKeyId: 'compliance-default-key',
        requestBody: {
          purpose: 'ENCRYPT_DECRYPT',
          versionTemplate: {
            algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
            protectionLevel: 'HSM',
          },
        },
      });
      return { success: true, message: 'Created default Cloud KMS key with HSM protection', finding, actionTaken: 'kms_key_created' };
    }

    return { success: false, message: 'Unknown KMS finding type', finding };
  }
}

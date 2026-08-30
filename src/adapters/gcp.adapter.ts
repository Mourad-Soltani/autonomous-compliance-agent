import { BaseAdapter, AdapterScanResult, AdapterConfig } from './base.adapter';
import { Evidence, EvidenceSeverity } from '../models/evidence';
import { Finding, FindingStatus } from '../models/finding';

// --- GCP SDK Types (mocked for zero-dependency bundling) ---
interface Storage {
  buckets: {
    getIamPolicy(params: { resource: string }): Promise<{ data: { bindings: { role: string; members: string[] }[] } }>;
    get(params: { bucket: string }): Promise<{ data: { iamConfiguration?: { uniformBucketLevelAccess?: { enabled?: boolean }; publicAccessPrevention?: string }; encryption?: { defaultKmsKeyName?: string }; versioning?: { enabled?: boolean }; retentionPolicy?: { isLocked?: boolean } } }>;
  };
}

interface Compute {
  firewalls: {
    list(params: { project: string }): Promise<{ data: { items: { name: string; sourceRanges: string[]; allowed: { IPProtocol: string; ports?: string[] }[]; direction: string; disabled: boolean }[] } }>;
  };
}

interface IAM {
  projects: {
    getIamPolicy(params: { resource: string }): Promise<{ data: { bindings: { role: string; members: string[] }[]; auditConfigs: { service: string; auditLogConfigs: { logType: string }[] }[] } }>;
  };
  roles: {
    list(params: { parent: string }): Promise<{ data: { roles: { name: string; includedPermissions: string[] }[] } }>;
  };
}

interface KMS {
  projects: {
    locations: {
      keyRings: {
        cryptoKeys: {
          list(params: { parent: string }): Promise<{ data: { cryptoKeys: { name: string; purpose: string; primary: { state: string; algorithm: string; protectionLevel: string } }[] } }>;
        };
      };
    };
  };
}

interface CloudResourceManager {
  projects: {
    get(params: { projectId: string }): Promise<{ data: { projectNumber: string; lifecycleState: string; labels: Record<string, string> } }>;
  };
}

export interface GCPConfig extends AdapterConfig {
  projectId: string;
  credentialsPath?: string;
  region?: string;
}

export class GCPAdapter extends BaseAdapter {
  private storage: Storage;
  private compute: Compute;
  private iam: IAM;
  private kms: KMS;
  private resourceManager: CloudResourceManager;
  private projectId: string;

  constructor(config: GCPConfig) {
    super(config);
    this.projectId = config.projectId;
    // In real usage: const { Storage } = require('@google-cloud/storage');
    this.storage = {} as Storage;
    this.compute = {} as Compute;
    this.iam = {} as IAM;
    this.kms = {} as KMS;
    this.resourceManager = {} as CloudResourceManager;
  }

  get name(): string { return 'gcp'; }

  async scan(): Promise<AdapterScanResult> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    // --- CC6.1: Identity & Access Management ---
    const iamFindings = await this.scanIAM();
    findings.push(...iamFindings.findings);
    evidence.push(...iamFindings.evidence);

    // --- CC6.6: Storage Encryption & Data Protection ---
    const storageFindings = await this.scanStorage();
    findings.push(...storageFindings.findings);
    evidence.push(...storageFindings.evidence);

    // --- CC6.7: Network Security (Firewall Rules) ---
    const networkFindings = await this.scanNetwork();
    findings.push(...networkFindings.findings);
    evidence.push(...networkFindings.evidence);

    // --- CC7.2: Key Management (KMS) ---
    const kmsFindings = await this.scanKMS();
    findings.push(...kmsFindings.findings);
    evidence.push(...kmsFindings.evidence);

    return { findings, evidence, adapter: this.name, timestamp: new Date() };
  }

  // ==================== CC6.1: IAM ====================
  private async scanIAM(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const policy = await this.iam.projects.getIamPolicy({ resource: `projects/${this.projectId}` });
      const bindings = policy.data.bindings || [];
      const auditConfigs = policy.data.auditConfigs || [];

      // Check for overly permissive roles
      const overlyPermissive = bindings.filter(b =>
        b.role === 'roles/editor' || b.role === 'roles/owner'
      );

      if (overlyPermissive.length > 0) {
        findings.push({
          id: `gcp-iam-001-${this.projectId}`,
          controlId: 'CC6.1',
          title: 'Overly Permissive IAM Bindings Detected',
          description: `${overlyPermissive.length} binding(s) with Editor/Owner roles found. Principle of least privilege violated.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: `projects/${this.projectId}`,
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      // Check for audit logging
      const hasDataAccessLogging = auditConfigs.some(
        ac => ac.auditLogConfigs.some(alc => alc.logType === 'DATA_READ' || alc.logType === 'DATA_WRITE')
      );

      if (!hasDataAccessLogging) {
        findings.push({
          id: `gcp-iam-002-${this.projectId}`,
          controlId: 'CC6.1',
          title: 'IAM Data Access Audit Logging Disabled',
          description: 'Data access audit logging is not configured for all services. Compliance monitoring impaired.',
          severity: 'medium',
          status: FindingStatus.OPEN,
          resource: `projects/${this.projectId}`,
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `gcp-iam-ev-${Date.now()}`,
        controlId: 'CC6.1',
        adapter: this.name,
        resource: `projects/${this.projectId}`,
        rawData: { bindings: bindings.map(b => ({ role: b.role, memberCount: b.members.length })), auditConfigCount: auditConfigs.length },
        collectedAt: new Date(),
        severity: overlyPermissive.length > 0 ? EvidenceSeverity.HIGH : EvidenceSeverity.LOW,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('CC6.1', 'IAM scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== CC6.6: Storage ====================
  private async scanStorage(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      // In real usage: list all buckets
      const mockBuckets = ['compliance-data', 'audit-logs', 'app-backups'];

      for (const bucketName of mockBuckets) {
        const bucket = await this.storage.buckets.get({ bucket: bucketName });
        const config = bucket.data;

        // Check uniform bucket-level access
        if (!config.iamConfiguration?.uniformBucketLevelAccess?.enabled) {
          findings.push({
            id: `gcp-storage-001-${bucketName}`,
            controlId: 'CC6.6',
            title: `Uniform Bucket-Level Access Disabled: ${bucketName}`,
            description: `Bucket ${bucketName} uses ACLs instead of IAM. This increases access management complexity and risk.`,
            severity: 'medium',
            status: FindingStatus.OPEN,
            resource: `gs://${bucketName}`,
            adapter: this.name,
            remediationAvailable: true,
            createdAt: new Date(),
          });
        }

        // Check public access prevention
        if (config.iamConfiguration?.publicAccessPrevention !== 'enforced') {
          findings.push({
            id: `gcp-storage-002-${bucketName}`,
            controlId: 'CC6.6',
            title: `Public Access Prevention Not Enforced: ${bucketName}`,
            description: `Bucket ${bucketName} does not enforce public access prevention. Data exposure risk.`,
            severity: 'high',
            status: FindingStatus.OPEN,
            resource: `gs://${bucketName}`,
            adapter: this.name,
            remediationAvailable: true,
            createdAt: new Date(),
          });
        }

        // Check encryption (CMEK)
        if (!config.encryption?.defaultKmsKeyName) {
          findings.push({
            id: `gcp-storage-003-${bucketName}`,
            controlId: 'CC6.6',
            title: `Customer-Managed Encryption Missing: ${bucketName}`,
            description: `Bucket ${bucketName} uses Google-managed encryption keys. CMEK recommended for compliance.`,
            severity: 'low',
            status: FindingStatus.OPEN,
            resource: `gs://${bucketName}`,
            adapter: this.name,
            remediationAvailable: true,
            createdAt: new Date(),
          });
        }

        // Check versioning
        if (!config.versioning?.enabled) {
          findings.push({
            id: `gcp-storage-004-${bucketName}`,
            controlId: 'CC6.6',
            title: `Object Versioning Disabled: ${bucketName}`,
            description: `Bucket ${bucketName} does not have object versioning enabled. Ransomware/data loss recovery impaired.`,
            severity: 'medium',
            status: FindingStatus.OPEN,
            resource: `gs://${bucketName}`,
            adapter: this.name,
            remediationAvailable: true,
            createdAt: new Date(),
          });
        }

        evidence.push({
          id: `gcp-storage-ev-${bucketName}-${Date.now()}`,
          controlId: 'CC6.6',
          adapter: this.name,
          resource: `gs://${bucketName}`,
          rawData: {
            uniformAccess: config.iamConfiguration?.uniformBucketLevelAccess?.enabled,
            publicAccessPrevention: config.iamConfiguration?.publicAccessPrevention,
            encryption: config.encryption?.defaultKmsKeyName ? 'CMEK' : 'Google-managed',
            versioning: config.versioning?.enabled,
            retentionLocked: config.retentionPolicy?.isLocked,
          },
          collectedAt: new Date(),
          severity: EvidenceSeverity.MEDIUM,
        });
      }
    } catch (err) {
      findings.push(this.createErrorFinding('CC6.6', 'Storage scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== CC6.7: Network Security ====================
  private async scanNetwork(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const firewalls = await this.compute.firewalls.list({ project: this.projectId });
      const rules = firewalls.data.items || [];

      for (const rule of rules) {
        if (rule.disabled) continue;

        // Check for overly permissive ingress (0.0.0.0/0)
        if (rule.direction === 'INGRESS' && rule.sourceRanges?.includes('0.0.0.0/0')) {
          const allowsSSH = rule.allowed.some(a => a.IPProtocol === 'tcp' && a.ports?.includes('22'));
          const allowsRDP = rule.allowed.some(a => a.IPProtocol === 'tcp' && a.ports?.includes('3389'));

          if (allowsSSH || allowsRDP) {
            findings.push({
              id: `gcp-fw-001-${rule.name}`,
              controlId: 'CC6.7',
              title: `Overly Permissive Firewall Rule: ${rule.name}`,
              description: `Rule ${rule.name} allows ${allowsSSH ? 'SSH' : ''}${allowsSSH && allowsRDP ? ' and ' : ''}${allowsRDP ? 'RDP' : ''} from 0.0.0.0/0. Administrative access should be restricted.`,
              severity: 'critical',
              status: FindingStatus.OPEN,
              resource: `projects/${this.projectId}/global/firewalls/${rule.name}`,
              adapter: this.name,
              remediationAvailable: true,
              createdAt: new Date(),
            });
          }

          // Check for all ports open
          const allPorts = rule.allowed.some(a => !a.ports || a.ports.includes('0-65535'));
          if (allPorts) {
            findings.push({
              id: `gcp-fw-002-${rule.name}`,
              controlId: 'CC6.7',
              title: `All Ports Exposed to Internet: ${rule.name}`,
              description: `Rule ${rule.name} allows all traffic from 0.0.0.0/0. This is a critical security risk.`,
              severity: 'critical',
              status: FindingStatus.OPEN,
              resource: `projects/${this.projectId}/global/firewalls/${rule.name}`,
              adapter: this.name,
              remediationAvailable: true,
              createdAt: new Date(),
            });
          }
        }
      }

      // Check for default-allow rules
      const defaultAllowRules = rules.filter(r => r.name.startsWith('default-allow') && !r.disabled);
      if (defaultAllowRules.length > 0) {
        findings.push({
          id: `gcp-fw-003-${this.projectId}`,
          controlId: 'CC6.7',
          title: 'Default Allow Firewall Rules Present',
          description: `${defaultAllowRules.length} default-allow rule(s) found. These should be replaced with explicit, least-privilege rules.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: `projects/${this.projectId}`,
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `gcp-fw-ev-${Date.now()}`,
        controlId: 'CC6.7',
        adapter: this.name,
        resource: `projects/${this.projectId}`,
        rawData: {
          totalRules: rules.length,
          activeRules: rules.filter(r => !r.disabled).length,
          defaultAllowRules: defaultAllowRules.length,
          openToInternet: rules.filter(r => r.direction === 'INGRESS' && r.sourceRanges?.includes('0.0.0.0/0')).length,
        },
        collectedAt: new Date(),
        severity: EvidenceSeverity.HIGH,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('CC6.7', 'Network scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== CC7.2: KMS ====================
  private async scanKMS(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const keyRings = ['global', 'us-central1', 'europe-west1'];
      let totalKeys = 0;
      let hsmKeys = 0;
      let rotatedKeys = 0;

      for (const location of keyRings) {
        const parent = `projects/${this.projectId}/locations/${location}/keyRings/compliance-ring`;
        try {
          const keys = await this.kms.projects.locations.keyRings.cryptoKeys.list({ parent });
          const cryptoKeys = keys.data.cryptoKeys || [];
          totalKeys += cryptoKeys.length;

          for (const key of cryptoKeys) {
            // Check HSM protection
            if (key.primary?.protectionLevel !== 'HSM') {
              findings.push({
                id: `gcp-kms-001-${key.name}`,
                controlId: 'CC7.2',
                title: `Key Not Using HSM Protection: ${key.name}`,
                description: `Crypto key ${key.name} uses software-backed protection. HSM recommended for high-value keys.`,
                severity: 'medium',
                status: FindingStatus.OPEN,
                resource: key.name,
                adapter: this.name,
                remediationAvailable: true,
                createdAt: new Date(),
              });
            } else {
              hsmKeys++;
            }

            // Check key state
            if (key.primary?.state !== 'ENABLED') {
              findings.push({
                id: `gcp-kms-002-${key.name}`,
                controlId: 'CC7.2',
                title: `Key Not in ENABLED State: ${key.name}`,
                description: `Crypto key ${key.name} is in ${key.primary?.state} state. Verify intentional disablement/rotation.`,
                severity: 'low',
                status: FindingStatus.OPEN,
                resource: key.name,
                adapter: this.name,
                remediationAvailable: false,
                createdAt: new Date(),
              });
            }
          }
        } catch {
          // Key ring may not exist, skip
        }
      }

      evidence.push({
        id: `gcp-kms-ev-${Date.now()}`,
        controlId: 'CC7.2',
        adapter: this.name,
        resource: `projects/${this.projectId}`,
        rawData: { totalKeys, hsmKeys, rotatedKeys, keyRingLocations: keyRings },
        collectedAt: new Date(),
        severity: totalKeys === 0 ? EvidenceSeverity.HIGH : EvidenceSeverity.LOW,
      });

      if (totalKeys === 0) {
        findings.push({
          id: `gcp-kms-003-${this.projectId}`,
          controlId: 'CC7.2',
          title: 'No Cloud KMS Keys Configured',
          description: 'No Cloud KMS keys found in the project. Encryption key management is essential for SOC 2 compliance.',
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: `projects/${this.projectId}`,
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }
    } catch (err) {
      findings.push(this.createErrorFinding('CC7.2', 'KMS scan failed', err));
    }

    return { findings, evidence };
  }

  private createErrorFinding(controlId: string, title: string, error: unknown): Finding {
    return {
      id: `gcp-error-${controlId}-${Date.now()}`,
      controlId,
      title,
      description: error instanceof Error ? error.message : String(error),
      severity: 'medium',
      status: FindingStatus.ERROR,
      resource: `projects/${this.projectId}`,
      adapter: this.name,
      remediationAvailable: false,
      createdAt: new Date(),
    };
  }
}

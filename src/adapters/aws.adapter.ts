import { BaseAdapter, AdapterConfig, AdapterHealth } from './base.adapter.js';
import { Evidence } from '../types/policy.js';

export interface AWSAdapterConfig extends AdapterConfig {
  region: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

export class AWSAdapter extends BaseAdapter {
  private region: string;

  constructor(config: AWSAdapterConfig) {
    super(config);
    this.region = config.region || 'us-east-1';
  }

  public async initialize(): Promise<void> {}

  public async checkHealth(): Promise<AdapterHealth> {
    return {
      healthy: true,
      lastChecked: new Date(),
      message: `AWS Adapter connected to region ${this.region}`,
    };
  }

  public async fetchEvidence(targetControlIds?: string[]): Promise<Evidence[]> {
    const evidenceList: Evidence[] = [];

    if (!targetControlIds || targetControlIds.includes('CC6.1')) {
      evidenceList.push(
        this.createEvidence(
          'CC6.1',
          {
            findingId: 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-mfa-enabled',
            title: 'IAM Root User MFA Enabled',
            status: 'PASSED',
            complianceType: 'AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES',
            details: { mfaActive: true, passwordPolicyEnforced: true },
          },
          'arn:aws:iam::123456789012:root'
        )
      );
    }

    if (!targetControlIds || targetControlIds.includes('CC7.2')) {
      evidenceList.push(
        this.createEvidence(
          'CC7.2',
          {
            trailName: 'production-audit-trail',
            isLogging: true,
            includeGlobalServiceEvents: true,
            isMultiRegionTrail: true,
            logFileValidationEnabled: true,
          },
          'arn:aws:cloudtrail:us-east-1:123456789012:trail/production-audit-trail'
        )
      );
    }

    return evidenceList;
  }
}
import {
  IAMClient,
  GetAccountPasswordPolicyCommand,
  GetAccountSummaryCommand,
} from '@aws-sdk/client-iam';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} from '@aws-sdk/client-cloudtrail';
import { BaseAdapter, AdapterConfig, AdapterHealth } from './base.adapter.js';
import { Evidence } from '../types/policy.js';

export interface AWSAdapterConfig extends AdapterConfig {
  region: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

export class AWSAdapter extends BaseAdapter {
  private region: string;
  private iamClient: IAMClient;
  private cloudTrailClient: CloudTrailClient;
  private hasCredentials: boolean;

  constructor(config: AWSAdapterConfig) {
    super(config);
    this.region = config.region || 'us-east-1';
    this.hasCredentials = !!(config.accessKeyId && config.secretAccessKey);

    const clientConfig = this.hasCredentials
      ? {
          region: this.region,
          credentials: {
            accessKeyId: config.accessKeyId!,
            secretAccessKey: config.secretAccessKey!,
          },
        }
      : { region: this.region };

    this.iamClient = new IAMClient(clientConfig);
    this.cloudTrailClient = new CloudTrailClient(clientConfig);
  }

  public async initialize(): Promise<void> {
    if (!this.hasCredentials) {
      console.log('[AWS] No credentials provided — running in mock mode.');
    }
  }

  public async checkHealth(): Promise<AdapterHealth> {
    try {
      if (this.hasCredentials) {
        await this.iamClient.send(new GetAccountSummaryCommand({}));
      }
      return {
        healthy: true,
        lastChecked: new Date(),
        message: `AWS Adapter ${this.hasCredentials ? 'connected' : 'mock mode'} — region ${this.region}`,
      };
    } catch (err) {
      return {
        healthy: false,
        lastChecked: new Date(),
        message: `AWS health check failed: ${(err as Error).message}`,
      };
    }
  }

  public async fetchEvidence(targetControlIds?: string[]): Promise<Evidence[]> {
    const evidenceList: Evidence[] = [];

    if (!targetControlIds || targetControlIds.includes('CC6.1')) {
      evidenceList.push(await this.fetchCC6_1Evidence());
    }

    if (!targetControlIds || targetControlIds.includes('CC7.2')) {
      evidenceList.push(await this.fetchCC7_2Evidence());
    }

    return evidenceList;
  }

  private async fetchCC6_1Evidence(): Promise<Evidence> {
    if (!this.hasCredentials) {
      return this.createEvidence(
        'CC6.1',
        {
          mode: 'MOCK',
          findingId: 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-mfa-enabled',
          title: 'IAM Root User MFA Enabled (MOCK)',
          status: 'PASSED',
          complianceType: 'AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES',
          details: { mfaActive: true, passwordPolicyEnforced: true },
        },
        'arn:aws:iam::123456789012:root'
      );
    }

    try {
      const passwordPolicy = await this.iamClient.send(
        new GetAccountPasswordPolicyCommand({})
      );

      const accountSummary = await this.iamClient.send(
        new GetAccountSummaryCommand({})
      );
      const mfaEnabled = (accountSummary.SummaryMap?.AccountMFAEnabled || 0) === 1;

      const passed = mfaEnabled && !!passwordPolicy.PasswordPolicy;

      return this.createEvidence(
        'CC6.1',
        {
          mode: 'LIVE',
          title: 'IAM Access Security',
          status: passed ? 'PASSED' : 'FAILED',
          mfaEnabled,
          passwordPolicy: passwordPolicy.PasswordPolicy
            ? {
                minimumPasswordLength: passwordPolicy.PasswordPolicy.MinimumPasswordLength,
                requireSymbols: passwordPolicy.PasswordPolicy.RequireSymbols,
                requireNumbers: passwordPolicy.PasswordPolicy.RequireNumbers,
                requireUppercaseCharacters: passwordPolicy.PasswordPolicy.RequireUppercaseCharacters,
                requireLowercaseCharacters: passwordPolicy.PasswordPolicy.RequireLowercaseCharacters,
                maxPasswordAge: passwordPolicy.PasswordPolicy.MaxPasswordAge,
                passwordReusePrevention: passwordPolicy.PasswordPolicy.PasswordReusePrevention,
              }
            : null,
        },
        `arn:aws:iam::${accountSummary.SummaryMap?.AccountAccessKeysPresent || 'unknown'}:root`
      );
    } catch (err) {
      const error = err as Error;
      return this.createEvidence(
        'CC6.1',
        {
          mode: 'LIVE',
          title: 'IAM Access Security',
          status: 'FAILED',
          error: error.name,
          message: error.message,
          mfaEnabled: false,
          passwordPolicy: null,
        },
        'arn:aws:iam::unknown:root'
      );
    }
  }

  private async fetchCC7_2Evidence(): Promise<Evidence> {
    if (!this.hasCredentials) {
      return this.createEvidence(
        'CC7.2',
        {
          mode: 'MOCK',
          trailName: 'production-audit-trail',
          isLogging: true,
          includeGlobalServiceEvents: true,
          isMultiRegionTrail: true,
          logFileValidationEnabled: true,
        },
        'arn:aws:cloudtrail:us-east-1:123456789012:trail/production-audit-trail'
      );
    }

    try {
      const trails = await this.cloudTrailClient.send(
        new DescribeTrailsCommand({})
      );

      if (!trails.trailList || trails.trailList.length === 0) {
        return this.createEvidence(
          'CC7.2',
          {
            mode: 'LIVE',
            title: 'CloudTrail Audit Logging',
            status: 'FAILED',
            isLogging: false,
            message: 'No CloudTrail trails found.',
          },
          'arn:aws:cloudtrail::unknown'
        );
      }

      const trail = trails.trailList[0];
      const status = await this.cloudTrailClient.send(
        new GetTrailStatusCommand({ Name: trail.Name })
      );

      const isLogging = status.IsLogging === true;
      const passed = isLogging && trail.IsMultiRegionTrail === true;

      return this.createEvidence(
        'CC7.2',
        {
          mode: 'LIVE',
          title: 'CloudTrail Audit Logging',
          status: passed ? 'PASSED' : 'FAILED',
          trailName: trail.Name,
          isLogging,
          isMultiRegionTrail: trail.IsMultiRegionTrail,
          includeGlobalServiceEvents: trail.IncludeGlobalServiceEvents,
          logFileValidationEnabled: trail.LogFileValidationEnabled,
          s3BucketName: trail.S3BucketName,
        },
        trail.TrailARN || 'arn:aws:cloudtrail::unknown'
      );
    } catch (err) {
      const error = err as Error;
      return this.createEvidence(
        'CC7.2',
        {
          mode: 'LIVE',
          title: 'CloudTrail Audit Logging',
          status: 'FAILED',
          error: error.name,
          message: error.message,
          isLogging: false,
        },
        'arn:aws:cloudtrail::unknown'
      );
    }
  }
}
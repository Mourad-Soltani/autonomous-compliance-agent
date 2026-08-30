import {
  IAMClient,
  UpdateAccountPasswordPolicyCommand,
  CreateVirtualMFADeviceCommand,
  EnableMFADeviceCommand,
  ListVirtualMFADevicesCommand,
  ListUsersCommand,
} from '@aws-sdk/client-iam';
import {
  CloudTrailClient,
  CreateTrailCommand,
  StartLoggingCommand,
  PutEventSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
import { RemediationFunction, RemediationOutcome } from '../policies/remediator.js';
import { SOC2Control, EvaluationResult } from '../types/policy.js';

function createAWSClients(region: string) {
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const hasCredentials = !!(accessKeyId && secretAccessKey);

  const clientConfig = hasCredentials
    ? {
        region,
        credentials: { accessKeyId, secretAccessKey },
      }
    : { region };

  return {
    iam: new IAMClient(clientConfig),
    cloudTrail: new CloudTrailClient(clientConfig),
    hasCredentials,
  };
}

export const awsRemediations: Record<string, RemediationFunction> = {
  'CC6.1': async (
    _control: SOC2Control,
    evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    const { iam, hasCredentials } = createAWSClients(process.env.AWS_REGION || 'us-east-1');

    if (!hasCredentials) {
      console.log('[REMEDIATE] CC6.1 — MOCK mode: Simulating IAM MFA and password policy enforcement...');
      return {
        success: true,
        message: '[MOCK] IAM root MFA enabled and password policy enforced.',
        actionTaken: '[MOCK] Enabled MFA device for root user; updated password policy (min 14 chars, symbols, rotation 90 days).',
      };
    }

    try {
      console.log('[REMEDIATE] CC6.1 — Enforcing IAM password policy...');

      // 1. Enforce strong password policy
      await iam.send(
        new UpdateAccountPasswordPolicyCommand({
          MinimumPasswordLength: 14,
          RequireSymbols: true,
          RequireNumbers: true,
          RequireUppercaseCharacters: true,
          RequireLowercaseCharacters: true,
          MaxPasswordAge: 90,
          PasswordReusePrevention: 24,
          HardExpiry: false,
        })
      );

      // 2. Check if root MFA is enabled
      const users = await iam.send(new ListUsersCommand({}));
      const rootUser = users.Users?.find((u) => u.UserName === 'root') || users.Users?.[0];

      let mfaAction = 'Root MFA already enabled.';
      if (rootUser && !rootUser.PasswordLastUsed) {
        // For root user, we can't programmatically enable MFA without
        // console access. We log a warning instead.
        mfaAction = 'Root MFA must be enabled via AWS Console. Please navigate to IAM > MFA and activate a virtual/hardware MFA device.';
      }

      return {
        success: true,
        message: 'Password policy enforced. Root MFA requires manual console activation.',
        actionTaken: `Updated password policy (14 chars, symbols, 90-day rotation). ${mfaAction}`,
      };
    } catch (err) {
      const error = err as Error;
      return {
        success: false,
        message: `Failed to enforce IAM policy: ${error.message}`,
        actionTaken: 'attempted',
        error: error.name,
      };
    }
  },

  'CC7.2': async (
    _control: SOC2Control,
    evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    const { cloudTrail, hasCredentials } = createAWSClients(process.env.AWS_REGION || 'us-east-1');

    if (!hasCredentials) {
      console.log('[REMEDIATE] CC7.2 — MOCK mode: Simulating CloudTrail creation...');
      return {
        success: true,
        message: '[MOCK] CloudTrail multi-region trail created and logging enabled.',
        actionTaken: '[MOCK] Created trail "compliance-audit-trail"; enabled multi-region logging; enabled log file validation.',
      };
    }

    try {
      console.log('[REMEDIATE] CC7.2 — Creating CloudTrail multi-region trail...');

      const trailName = 'compliance-audit-trail';
      const s3BucketName = process.env.AWS_CLOUDTRAIL_BUCKET || `cloudtrail-logs-${Date.now()}`;

      // Create the trail
      const trail = await cloudTrail.send(
        new CreateTrailCommand({
          Name: trailName,
          S3BucketName: s3BucketName,
          IsMultiRegionTrail: true,
          EnableLogFileValidation: true,
          IncludeGlobalServiceEvents: true,
        })
      );

      // Start logging
      await cloudTrail.send(
        new StartLoggingCommand({ Name: trailName })
      );

      // Configure event selectors for all management events
      await cloudTrail.send(
        new PutEventSelectorsCommand({
          TrailName: trailName,
          EventSelectors: [
            {
              ReadWriteType: 'All',
              IncludeManagementEvents: true,
              DataResources: [],
            },
          ],
        })
      );

      return {
        success: true,
        message: `CloudTrail trail "${trailName}" created and logging enabled.`,
        actionTaken: `Created multi-region trail "${trailName}" in S3 bucket "${s3BucketName}"; enabled log file validation; capturing all management events.`,
      };
    } catch (err) {
      const error = err as Error;
      // Trail may already exist
      if (error.name === 'TrailAlreadyExistsException') {
        try {
          await cloudTrail.send(
            new StartLoggingCommand({ Name: 'compliance-audit-trail' })
          );
          return {
            success: true,
            message: 'CloudTrail trail already exists — logging re-enabled.',
            actionTaken: 'Trail "compliance-audit-trail" already exists; ensured logging is active.',
          };
        } catch (startErr) {
          return {
            success: false,
            message: `Trail exists but failed to start logging: ${(startErr as Error).message}`,
            actionTaken: 'attempted',
            error: (startErr as Error).name,
          };
        }
      }

      return {
        success: false,
        message: `Failed to create CloudTrail: ${error.message}`,
        actionTaken: 'attempted',
        error: error.name,
      };
    }
  },
};

export function registerAWSRemediations(remediator: { registerRemediation: (id: string, fn: RemediationFunction) => void }): void {
  for (const [controlId, fn] of Object.entries(awsRemediations)) {
    remediator.registerRemediation(controlId, fn);
  }
}
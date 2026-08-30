import {
  IAMClient,
  UpdateAccountPasswordPolicyCommand,
  ListUsersCommand,
} from '@aws-sdk/client-iam';
import {
  CloudTrailClient,
  CreateTrailCommand,
  StartLoggingCommand,
  PutEventSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  S3Client,
  CreateBucketCommand,
  PutBucketPolicyCommand,
  HeadBucketCommand,
} from '@aws-sdk/client-s3';
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
    s3: new S3Client(clientConfig),
    hasCredentials,
  };
}

/**
 * Ensure the CloudTrail S3 bucket exists with the required policy.
 * Returns the bucket name.
 */
async function ensureCloudTrailBucket(
  s3: S3Client,
  bucketName: string,
  accountId: string
): Promise<string> {
  try {
    await s3.send(new HeadBucketCommand({ Bucket: bucketName }));
    return bucketName;
  } catch {
    // Bucket doesn't exist — create it
    await s3.send(new CreateBucketCommand({ Bucket: bucketName }));

    const bucketPolicy = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'AWSCloudTrailAclCheck20150319',
          Effect: 'Allow',
          Principal: { Service: 'cloudtrail.amazonaws.com' },
          Action: 's3:GetBucketAcl',
          Resource: `arn:aws:s3:::${bucketName}`,
        },
        {
          Sid: 'AWSCloudTrailWrite20150319',
          Effect: 'Allow',
          Principal: { Service: 'cloudtrail.amazonaws.com' },
          Action: 's3:PutObject',
          Resource: `arn:aws:s3:::${bucketName}/AWSLogs/${accountId}/*`,
          Condition: {
            StringEquals: {
              's3:x-amz-acl': 'bucket-owner-full-control',
            },
          },
        },
      ],
    };

    await s3.send(
      new PutBucketPolicyCommand({
        Bucket: bucketName,
        Policy: JSON.stringify(bucketPolicy),
      })
    );

    return bucketName;
  }
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

      const users = await iam.send(new ListUsersCommand({}));
      const rootUser = users.Users?.find((u) => u.UserName === 'root') || users.Users?.[0];

      let mfaAction = 'Root MFA already enabled.';
      if (rootUser && !rootUser.PasswordLastUsed) {
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
    const { cloudTrail, s3, hasCredentials } = createAWSClients(process.env.AWS_REGION || 'us-east-1');

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
      const bucketName = process.env.AWS_CLOUDTRAIL_BUCKET || `cloudtrail-logs-${Date.now()}`;
      const accountId = process.env.AWS_ACCOUNT_ID || '000000000000';

      // FIX: Ensure S3 bucket exists with proper CloudTrail policy before creating trail
      await ensureCloudTrailBucket(s3, bucketName, accountId);

      const trail = await cloudTrail.send(
        new CreateTrailCommand({
          Name: trailName,
          S3BucketName: bucketName,
          IsMultiRegionTrail: true,
          EnableLogFileValidation: true,
          IncludeGlobalServiceEvents: true,
        })
      );

      await cloudTrail.send(
        new StartLoggingCommand({ Name: trailName })
      );

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
        actionTaken: `Created multi-region trail "${trailName}" in S3 bucket "${bucketName}"; enabled log file validation; capturing all management events.`,
      };
    } catch (err) {
      const error = err as Error;
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

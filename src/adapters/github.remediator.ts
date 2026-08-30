import { RemediationFunction, RemediationOutcome } from '../policies/remediator.js';
import { SOC2Control, EvaluationResult } from '../types/policy.js';

const apiBase = 'https://api.github.com';

function getGitHubConfig() {
  const owner = process.env.GITHUB_OWNER || 'enterprise-org';
  const repo = process.env.GITHUB_REPO || 'core-platform';
  const authToken = process.env.GITHUB_TOKEN;
  const hasToken = !!authToken;
  return { owner, repo, authToken, hasToken };
}

async function githubFetch(path: string, method: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.luke-cage-preview+json',
    'User-Agent': 'compliance-agent/1.0',
    'Content-Type': 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${apiBase}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  return response;
}

export const githubRemediations: Record<string, RemediationFunction> = {
  'CC6.8': async (
    _control: SOC2Control,
    evaluation: EvaluationResult
  ): Promise<RemediationOutcome> => {
    const { owner, repo, authToken, hasToken } = getGitHubConfig();

    if (!hasToken) {
      console.log('[REMEDIATE] CC6.8 — MOCK mode: Simulating branch protection enforcement...');
      return {
        success: true,
        message: '[MOCK] Branch protection enforced on main with required PR reviews.',
        actionTaken: '[MOCK] Enabled branch protection: 2 required reviews, code owner review, dismiss stale reviews, CI status checks enforced.',
      };
    }

    try {
      console.log('[REMEDIATE] CC6.8 — Enforcing branch protection on main...');

      // 1. Set branch protection rules
      const protectionResponse = await githubFetch(
        `/repos/${owner}/${repo}/branches/main/protection`,
        'PUT',
        {
          required_status_checks: {
            strict: true,
            contexts: ['ci/build', 'security/codeql-scan'],
          },
          enforce_admins: true,
          required_pull_request_reviews: {
            dismissal_restrictions: {},
            dismiss_stale_reviews: true,
            require_code_owner_reviews: true,
            required_approving_review_count: 2,
          },
          restrictions: null,
        },
        authToken
      );

      if (!protectionResponse.ok && protectionResponse.status !== 422) {
        const errorText = await protectionResponse.text();
        return {
          success: false,
          message: `GitHub API error: ${protectionResponse.status} — ${errorText}`,
          actionTaken: 'attempted',
          error: `HTTP ${protectionResponse.status}`,
        };
      }

      // 2. Verify the protection was applied
      const verifyResponse = await githubFetch(
        `/repos/${owner}/${repo}/branches/main/protection`,
        'GET',
        undefined,
        authToken
      );

      if (!verifyResponse.ok) {
        return {
          success: false,
          message: 'Branch protection API call succeeded but verification failed.',
          actionTaken: 'attempted',
          error: `Verification HTTP ${verifyResponse.status}`,
        };
      }

      const protection = await verifyResponse.json();
      const reviews = protection.required_pull_request_reviews;
      const checks = protection.required_status_checks;

      return {
        success: true,
        message: 'Branch protection enforced on main.',
        actionTaken: `Enabled: ${reviews?.required_approving_review_count || 0} required reviews, code owner review=${reviews?.require_code_owner_reviews || false}, dismiss stale=${reviews?.dismiss_stale_reviews || false}, CI checks=[${checks?.contexts?.join(', ') || 'none'}].`,
      };
    } catch (err) {
      const error = err as Error;
      return {
        success: false,
        message: `Failed to enforce branch protection: ${error.message}`,
        actionTaken: 'attempted',
        error: error.name,
      };
    }
  },
};

export function registerGitHubRemediations(remediator: { registerRemediation: (id: string, fn: RemediationFunction) => void }): void {
  for (const [controlId, fn] of Object.entries(githubRemediations)) {
    remediator.registerRemediation(controlId, fn);
  }
}
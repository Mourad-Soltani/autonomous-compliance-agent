import { BaseAdapter, AdapterConfig, AdapterHealth } from './base.adapter.js';
import { Evidence } from '../types/policy.js';

export interface GitHubAdapterConfig extends AdapterConfig {
  owner: string;
  repo: string;
  token?: string;
}

export class GitHubAdapter extends BaseAdapter {
  private owner: string;
  private repo: string;
  private token?: string;
  private apiBase = 'https://api.github.com';

  constructor(config: GitHubAdapterConfig) {
    super(config);
    this.owner = config.owner;
    this.repo = config.repo;
    this.token = config.token || process.env.GITHUB_TOKEN;
  }

  public async initialize(): Promise<void> {
    if (!this.token) {
      console.log('[GitHub] No token provided — running in mock mode.');
    }
  }

  public async checkHealth(): Promise<AdapterHealth> {
    if (!this.token) {
      return {
        healthy: true,
        lastChecked: new Date(),
        message: `GitHub Adapter mock mode — ${this.owner}/${this.repo}`,
      };
    }

    try {
      const response = await fetch(`${this.apiBase}/repos/${this.owner}/${this.repo}`, {
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'compliance-agent/1.0',
        },
      });

      if (!response.ok) {
        return {
          healthy: false,
          lastChecked: new Date(),
          message: `GitHub API returned ${response.status}: ${response.statusText}`,
        };
      }

      return {
        healthy: true,
        lastChecked: new Date(),
        message: `GitHub Adapter connected — ${this.owner}/${this.repo}`,
      };
    } catch (err) {
      return {
        healthy: false,
        lastChecked: new Date(),
        message: `GitHub API unreachable: ${(err as Error).message}`,
      };
    }
  }

  public async fetchEvidence(targetControlIds?: string[]): Promise<Evidence[]> {
    const evidenceList: Evidence[] = [];

    if (!targetControlIds || targetControlIds.includes('CC6.8')) {
      evidenceList.push(await this.fetchCC6_8Evidence());
    }

    return evidenceList;
  }

  private async fetchCC6_8Evidence(): Promise<Evidence> {
    if (!this.token) {
      return this.createEvidence(
        'CC6.8',
        {
          mode: 'MOCK',
          branch: 'main',
          protected: true,
          requiredPullRequestReviews: {
            dismissStaleReviews: true,
            requireCodeOwnerReviews: true,
            requiredApprovingReviewCount: 2,
          },
          enforceAdmins: true,
          requiredStatusChecks: {
            strict: true,
            contexts: ['ci/build', 'security/codeql-scan'],
          },
        },
        `https://github.com/${this.owner}/${this.repo}/branches/main/protection`
      );
    }

    try {
      const response = await fetch(
        `${this.apiBase}/repos/${this.owner}/${this.repo}/branches/main/protection`,
        {
          headers: {
            Authorization: `Bearer ${this.token}`,
            Accept: 'application/vnd.github.luke-cage-preview+json',
            'User-Agent': 'compliance-agent/1.0',
          },
        }
      );

      if (response.status === 404) {
        // No branch protection configured
        return this.createEvidence(
          'CC6.8',
          {
            mode: 'LIVE',
            branch: 'main',
            protected: false,
            requiredPullRequestReviews: null,
            enforceAdmins: false,
            requiredStatusChecks: null,
            message: 'Branch protection not configured for main.',
          },
          `https://github.com/${this.owner}/${this.repo}/branches/main/protection`
        );
      }

      if (!response.ok) {
        throw new Error(`GitHub API ${response.status}: ${response.statusText}`);
      }

      const protection = await response.json();

      const passed =
        protection.enabled === true &&
        protection.required_pull_request_reviews?.required_approving_review_count >= 1;

      return this.createEvidence(
        'CC6.8',
        {
          mode: 'LIVE',
          branch: 'main',
          protected: protection.enabled === true,
          requiredPullRequestReviews: protection.required_pull_request_reviews
            ? {
                dismissStaleReviews: protection.required_pull_request_reviews.dismiss_stale_reviews,
                requireCodeOwnerReviews: protection.required_pull_request_reviews.require_code_owner_reviews,
                requiredApprovingReviewCount: protection.required_pull_request_reviews.required_approving_review_count,
              }
            : null,
          enforceAdmins: protection.enforce_admins?.enabled || false,
          requiredStatusChecks: protection.required_status_checks
            ? {
                strict: protection.required_status_checks.strict,
                contexts: protection.required_status_checks.contexts || [],
              }
            : null,
          status: passed ? 'PASSED' : 'FAILED',
        },
        `https://github.com/${this.owner}/${this.repo}/branches/main/protection`
      );
    } catch (err) {
      const error = err as Error;
      return this.createEvidence(
        'CC6.8',
        {
          mode: 'LIVE',
          branch: 'main',
          protected: false,
          error: error.name,
          message: error.message,
          status: 'FAILED',
        },
        `https://github.com/${this.owner}/${this.repo}/branches/main/protection`
      );
    }
  }
}
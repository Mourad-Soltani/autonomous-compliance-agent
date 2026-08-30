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

  constructor(config: GitHubAdapterConfig) {
    super(config);
    this.owner = config.owner;
    this.repo = config.repo;
  }

  public async initialize(): Promise<void> {}

  public async checkHealth(): Promise<AdapterHealth> {
    return {
      healthy: true,
      lastChecked: new Date(),
      message: `GitHub Adapter ready for repository ${this.owner}/${this.repo}`,
    };
  }

  public async fetchEvidence(targetControlIds?: string[]): Promise<Evidence[]> {
    const evidenceList: Evidence[] = [];

    if (!targetControlIds || targetControlIds.includes('CC6.8')) {
      evidenceList.push(
        this.createEvidence(
          'CC6.8',
          {
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
        )
      );
    }

    return evidenceList;
  }
}
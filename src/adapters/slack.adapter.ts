import { BaseAdapter, AdapterConfig, AdapterHealth } from './base.adapter.js';
import { Evidence } from '../types/policy.js';

export interface SlackAdapterConfig extends AdapterConfig {
  webhookUrl: string;
  channel?: string;
  username?: string;
}

export class SlackAdapter extends BaseAdapter {
  private webhookUrl: string;
  private channel?: string;
  private username: string;

  constructor(config: SlackAdapterConfig) {
    super(config);
    this.webhookUrl = config.webhookUrl;
    this.channel = config.channel;
    this.username = config.username || 'Compliance Agent';
  }

  public async initialize(): Promise<void> {
    const health = await this.checkHealth();
    if (!health.healthy) {
      throw new Error(`Slack adapter health check failed: ${health.message}`);
    }
  }

  public async checkHealth(): Promise<AdapterHealth> {
    try {
      const response = await fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'Compliance Agent health check' }),
      });
      // Slack webhooks return 200 even for invalid payloads, but 404/410 for invalid URLs
      if (response.status >= 400) {
        return {
          healthy: false,
          lastChecked: new Date(),
          message: `Slack webhook returned ${response.status}`,
        };
      }
      return {
        healthy: true,
        lastChecked: new Date(),
        message: 'Slack webhook reachable',
      };
    } catch (err) {
      return {
        healthy: false,
        lastChecked: new Date(),
        message: `Slack webhook unreachable: ${(err as Error).message}`,
      };
    }
  }

  public async fetchEvidence(): Promise<Evidence[]> {
    // Slack adapter does not collect evidence — it only sends notifications
    return [];
  }

  public async sendAuditSummary(report: {
    timestamp: Date;
    summary: {
      totalControls: number;
      compliantCount: number;
      nonCompliantCount: number;
      notEvaluatedCount: number;
    };
    results: Array<{
      controlId: string;
      status: string;
      findings: string[];
      remediationSteps?: string[];
    }>;
  }): Promise<void> {
    const { summary, results } = report;
    const passRate = Math.round((summary.compliantCount / summary.totalControls) * 100);

    const color = passRate === 100 ? '#36a64f' : passRate >= 70 ? '#daa520' : '#ff0000';

    const nonCompliant = results.filter((r) => r.status === 'NON_COMPLIANT');
    const criticalFindings = nonCompliant
      .map((r) => `• *${r.controlId}*: ${r.findings.join('; ')}`)
      .join('\n');

    const payload = {
      username: this.username,
      channel: this.channel,
      attachments: [
        {
          color,
          title: `SOC 2 Compliance Audit — ${passRate}% Pass Rate`,
          title_link: 'https://github.com/Mourad-Soltani/autonomous-compliance-agent',
          fields: [
            { title: 'Total Controls', value: summary.totalControls, short: true },
            { title: 'Compliant', value: summary.compliantCount, short: true },
            { title: 'Non-Compliant', value: summary.nonCompliantCount, short: true },
            { title: 'Not Evaluated', value: summary.notEvaluatedCount, short: true },
          ],
          footer: 'Autonomous Compliance Agent',
          ts: Math.floor(report.timestamp.getTime() / 1000),
        },
        ...(nonCompliant.length > 0
          ? [
              {
                color: '#ff0000',
                title: 'Critical Remediation Required',
                text: criticalFindings || 'No critical findings.',
              },
            ]
          : []),
      ],
    };

    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }

  public async sendCriticalAlert(controlId: string, findings: string[], remediationSteps: string[]): Promise<void> {
    const payload = {
      username: this.username,
      channel: this.channel,
      attachments: [
        {
          color: '#ff0000',
          title: `🚨 Critical Compliance Failure: ${controlId}`,
          text: findings.join('\n'),
          fields: [
            {
              title: 'Remediation Steps',
              value: remediationSteps.join('\n'),
              short: false,
            },
          ],
          footer: 'Autonomous Compliance Agent',
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }
}
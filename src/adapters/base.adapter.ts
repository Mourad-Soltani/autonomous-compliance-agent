import { Evidence } from '../types/policy.js';

export interface AdapterConfig {
  adapterId: string;
  enabled: boolean;
  credentials?: Record<string, string>;
  options?: Record<string, unknown>;
}

export interface AdapterHealth {
  healthy: boolean;
  lastChecked: Date;
  message?: string;
}

export abstract class BaseAdapter {
  protected config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  public get id(): string {
    return this.config.adapterId;
  }

  public abstract initialize(): Promise<void>;
  public abstract checkHealth(): Promise<AdapterHealth>;
  public abstract fetchEvidence(targetControlIds?: string[]): Promise<Evidence[]>;

  protected createEvidence(
    controlId: string,
    rawPayload: Record<string, unknown>,
    resourceArn?: string
  ): Evidence {
    return {
      id: crypto.randomUUID(),
      controlId,
      sourceAdapter: this.config.adapterId,
      timestamp: new Date(),
      rawPayload,
      resourceArn,
    };
  }
}
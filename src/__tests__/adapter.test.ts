import { describe, it, expect } from 'vitest';
import { BaseAdapter, AdapterConfig } from '../adapters/base.adapter.js';

class TestAdapter extends BaseAdapter {
  async initialize(): Promise<void> {}
  async checkHealth() {
    return { healthy: true, lastChecked: new Date() };
  }
  async fetchEvidence() {
    return [this.createEvidence('TEST', { ok: true }, 'arn:test')];
  }
}

describe('BaseAdapter', () => {
  it('creates evidence with correct structure', async () => {
    const adapter = new TestAdapter({ adapterId: 'test-1', enabled: true });
    const evidence = await adapter.fetchEvidence();

    expect(evidence).toHaveLength(1);
    expect(evidence[0].controlId).toBe('TEST');
    expect(evidence[0].sourceAdapter).toBe('test-1');
    expect(evidence[0].resourceArn).toBe('arn:test');
    expect(evidence[0].id).toBeDefined();
  });

  it('exposes adapter id', () => {
    const adapter = new TestAdapter({ adapterId: 'my-adapter', enabled: true });
    expect(adapter.id).toBe('my-adapter');
  });
});

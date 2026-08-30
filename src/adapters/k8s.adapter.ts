import { BaseAdapter, AdapterConfig, AdapterHealth } from './base.adapter.js';
import { Evidence } from '../types/policy.js';

export interface K8sAdapterConfig extends AdapterConfig {
  kubeconfigPath?: string;
  context?: string;
  namespaces?: string[];
}

/**
 * Kubernetes Adapter — stub implementation.
 * 
 * NOTE: Full K8s SDK integration requires @kubernetes/client-node.
 * This adapter currently operates in mock mode and logs a warning
 * when initialized without the K8s SDK.
 * 
 * To enable live mode:
 *   npm install @kubernetes/client-node
 *   Provide a valid kubeconfig or in-cluster service account.
 */
export class K8sAdapter extends BaseAdapter {
  private kubeconfigPath?: string;
  private context?: string;
  private namespaces: string[];
  private hasSDK: boolean;

  constructor(config: K8sAdapterConfig) {
    super(config);
    this.kubeconfigPath = config.kubeconfigPath;
    this.context = config.context;
    this.namespaces = config.namespaces || [];
    this.hasSDK = false;

    try {
      // Attempt to detect if @kubernetes/client-node is available
      require.resolve('@kubernetes/client-node');
      this.hasSDK = true;
    } catch {
      this.hasSDK = false;
    }
  }

  public async initialize(): Promise<void> {
    if (!this.hasSDK) {
      console.log('[K8s] @kubernetes/client-node not installed — running in mock mode.');
      console.log('[K8s] Install with: npm install @kubernetes/client-node');
    } else if (!this.kubeconfigPath && !process.env.KUBECONFIG) {
      console.log('[K8s] No kubeconfig provided — assuming in-cluster config.');
    }
  }

  public async checkHealth(): Promise<AdapterHealth> {
    if (!this.hasSDK) {
      return {
        healthy: true,
        lastChecked: new Date(),
        message: 'K8s Adapter mock mode — @kubernetes/client-node not installed',
      };
    }

    try {
      // In a full implementation, this would ping the K8s API server
      return {
        healthy: true,
        lastChecked: new Date(),
        message: 'K8s Adapter connected',
      };
    } catch (err) {
      return {
        healthy: false,
        lastChecked: new Date(),
        message: `K8s health check failed: ${(err as Error).message}`,
      };
    }
  }

  public async fetchEvidence(targetControlIds?: string[]): Promise<Evidence[]> {
    const evidenceList: Evidence[] = [];

    // Return mock evidence for known controls
    if (!targetControlIds || targetControlIds.includes('CC6.1')) {
      evidenceList.push(this.createEvidence('CC6.1', {
        mode: 'MOCK',
        message: 'K8s RBAC scan not available without @kubernetes/client-node',
        clusterAdminBindings: 0,
        wildcardClusterRoles: 0,
      }));
    }

    if (!targetControlIds || targetControlIds.includes('CC6.6')) {
      evidenceList.push(this.createEvidence('CC6.6', {
        mode: 'MOCK',
        message: 'K8s secrets scan not available without @kubernetes/client-node',
        defaultTokenSecrets: 0,
        secretsInDefaultNs: 0,
      }));
    }

    if (!targetControlIds || targetControlIds.includes('CC6.7')) {
      evidenceList.push(this.createEvidence('CC6.7', {
        mode: 'MOCK',
        message: 'K8s NetworkPolicy scan not available without @kubernetes/client-node',
        unprotectedNamespaces: 0,
        allowAllIngressPolicies: 0,
      }));
    }

    if (!targetControlIds || targetControlIds.includes('CC7.2')) {
      evidenceList.push(this.createEvidence('CC7.2', {
        mode: 'MOCK',
        message: 'K8s Pod Security scan not available without @kubernetes/client-node',
        privilegedContainers: 0,
        rootContainers: 0,
        hostNetworkPods: 0,
      }));
    }

    if (!targetControlIds || targetControlIds.includes('A1.1')) {
      evidenceList.push(this.createEvidence('A1.1', {
        mode: 'MOCK',
        message: 'K8s node health scan not available without @kubernetes/client-node',
        outdatedNodes: 0,
      }));
    }

    return evidenceList;
  }
}

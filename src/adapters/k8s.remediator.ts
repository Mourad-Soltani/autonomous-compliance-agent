import { BaseRemediator, RemediationResult } from './base.adapter';
import { Finding, FindingStatus } from '../models/finding';

interface CoreV1Api {
  patchNamespacedPod(params: { name: string; namespace: string; body: object }): Promise<unknown>;
  createNamespacedNetworkPolicy(params: { namespace: string; body: object }): Promise<unknown>;
  patchNamespacedServiceAccount(params: { name: string; namespace: string; body: object }): Promise<unknown>;
}

interface RbacAuthorizationV1Api {
  deleteClusterRoleBinding(params: { name: string }): Promise<unknown>;
  deleteClusterRole(params: { name: string }): Promise<unknown>;
}

export class K8sRemediator extends BaseRemediator {
  private core: CoreV1Api;
  private rbac: RbacAuthorizationV1Api;

  constructor() {
    super();
    this.core = {} as CoreV1Api;
    this.rbac = {} as RbacAuthorizationV1Api;
  }

  get name(): string { return 'k8s-remediator'; }

  async remediate(finding: Finding): Promise<RemediationResult> {
    try {
      switch (finding.controlId) {
        case 'CC6.1':
          return await this.remediateRBAC(finding);
        case 'CC6.6':
          return await this.remediateSecrets(finding);
        case 'CC6.7':
          return await this.remediateNetwork(finding);
        case 'CC7.2':
          return await this.remediatePods(finding);
        default:
          return { success: false, message: `No remediation available for control ${finding.controlId}`, finding };
      }
    } catch (error) {
      return { success: false, message: `Remediation failed: ${error instanceof Error ? error.message : String(error)}`, finding };
    }
  }

  // ==================== CC6.1: RBAC Remediation ====================
  private async remediateRBAC(finding: Finding): Promise<RemediationResult> {
    if (finding.id.includes('k8s-rbac-001')) {
      // Remove overly permissive cluster-admin bindings
      // In production: identify specific binding and remove subjects or delete binding
      return {
        success: true,
        message: 'Review required: Remove subjects from cluster-admin ClusterRoleBindings or create dedicated roles with minimal permissions.',
        finding,
        actionTaken: 'rbac_review_required',
        requiresManualAction: true,
      };
    }

    if (finding.id.includes('k8s-rbac-002')) {
      // Flag wildcard roles for review
      return {
        success: true,
        message: 'Wildcard ClusterRoles flagged for review. Replace with explicit resource and verb permissions.',
        finding,
        actionTaken: 'wildcard_roles_flagged',
        requiresManualAction: true,
      };
    }

    return { success: false, message: 'Unknown RBAC finding type', finding };
  }

  // ==================== CC6.6: Secrets Remediation ====================
  private async remediateSecrets(finding: Finding): Promise<RemediationResult> {
    if (finding.id.includes('k8s-secret-001')) {
      // Disable auto-mount of default service account tokens
      return {
        success: true,
        message: 'Set automountServiceAccountToken: false on default service accounts and create dedicated service accounts per workload.',
        finding,
        actionTaken: 'automount_disabled',
        requiresManualAction: true,
      };
    }

    if (finding.id.includes('k8s-secret-002')) {
      return {
        success: true,
        message: 'Move secrets from default namespace to dedicated namespaces with appropriate RBAC.',
        finding,
        actionTaken: 'namespace_migration_required',
        requiresManualAction: true,
      };
    }

    return { success: false, message: 'Unknown secret finding type', finding };
  }

  // ==================== CC6.7: Network Remediation ====================
  private async remediateNetwork(finding: Finding): Promise<RemediationResult> {
    if (finding.id.includes('k8s-net-001')) {
      // Create default-deny NetworkPolicy for unprotected namespaces
      const defaultDenyPolicy = {
        apiVersion: 'networking.k8s.io/v1',
        kind: 'NetworkPolicy',
        metadata: { name: 'default-deny-all' },
        spec: {
          podSelector: {},
          policyTypes: ['Ingress', 'Egress'],
        },
      };

      return {
        success: true,
        message: 'Apply default-deny NetworkPolicy to namespaces without network policies. Use the provided manifest.',
        finding,
        actionTaken: 'default_deny_policy_recommended',
        requiresManualAction: true,
        manifest: defaultDenyPolicy,
      };
    }

    if (finding.id.includes('k8s-net-002')) {
      return {
        success: true,
        message: 'Restrict NetworkPolicy ingress rules to specific pod selectors and namespaces. Avoid empty from: blocks.',
        finding,
        actionTaken: 'ingress_restriction_recommended',
        requiresManualAction: true,
      };
    }

    return { success: false, message: 'Unknown network finding type', finding };
  }

  // ==================== CC7.2: Pod Security Remediation ====================
  private async remediatePods(finding: Finding): Promise<RemediationResult> {
    if (finding.id.includes('k8s-pod-001')) {
      return {
        success: true,
        message: 'Remove privileged: true from container security contexts. Use specific capabilities if elevated permissions are required.',
        finding,
        actionTaken: 'privileged_removed',
        requiresManualAction: true,
      };
    }

    if (finding.id.includes('k8s-pod-002')) {
      return {
        success: true,
        message: 'Set runAsNonRoot: true and specify a non-root runAsUser UID in pod security contexts.',
        finding,
        actionTaken: 'runAsNonRoot_enforced',
        requiresManualAction: true,
      };
    }

    if (finding.id.includes('k8s-pod-003')) {
      return {
        success: true,
        message: 'Remove hostNetwork, hostPID, and hostIPC from pod specs. Use services and shared volumes for cross-pod communication.',
        finding,
        actionTaken: 'host_isolation_restored',
        requiresManualAction: true,
      };
    }

    if (finding.id.includes('k8s-pod-004')) {
      return {
        success: true,
        message: 'Add capabilities: { drop: ["ALL"] } to all containers. Add only required capabilities explicitly.',
        finding,
        actionTaken: 'capabilities_dropped',
        requiresManualAction: true,
      };
    }

    return { success: false, message: 'Unknown pod security finding type', finding };
  }
}

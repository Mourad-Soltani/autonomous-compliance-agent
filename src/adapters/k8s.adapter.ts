import { BaseAdapter, AdapterScanResult, AdapterConfig } from './base.adapter';
import { Evidence, EvidenceSeverity } from '../models/evidence';
import { Finding, FindingStatus } from '../models/finding';

// --- K8s SDK Types (mocked for zero-dependency bundling) ---
interface CoreV1Api {
  listPodForAllNamespaces(): Promise<{ body: { items: { metadata?: { name: string; namespace: string; labels?: Record<string, string> }; spec?: { containers: { name: string; image: string; securityContext?: { privileged?: boolean; runAsRoot?: boolean; allowPrivilegeEscalation?: boolean; readOnlyRootFilesystem?: boolean; runAsNonRoot?: boolean; capabilities?: { add?: string[]; drop?: string[] } } }[]; serviceAccountName?: string; hostNetwork?: boolean; hostPID?: boolean; hostIPC?: boolean } }[] } }>;
  listSecretForAllNamespaces(): Promise<{ body: { items: { metadata?: { name: string; namespace: string }; type?: string; data?: Record<string, string> }[] } }>;
  listServiceAccountForAllNamespaces(): Promise<{ body: { items: { metadata?: { name: string; namespace: string }; secrets?: { name: string }[]; imagePullSecrets?: { name: string }[] }[] } }>;
  listNode(): Promise<{ body: { items: { metadata?: { name: string; labels?: Record<string, string> }; status?: { nodeInfo?: { kubeletVersion: string; osImage: string; containerRuntimeVersion: string } } }[] } }>;
}

interface RbacAuthorizationV1Api {
  listClusterRoleBinding(): Promise<{ body: { items: { metadata?: { name: string }; roleRef?: { kind: string; name: string }; subjects?: { kind: string; name: string; namespace?: string }[] }[] } }>;
  listRoleBindingForAllNamespaces(): Promise<{ body: { items: { metadata?: { name: string; namespace: string }; roleRef?: { kind: string; name: string }; subjects?: { kind: string; name: string }[] }[] } }>;
  listClusterRole(): Promise<{ body: { items: { metadata?: { name: string }; rules?: { verbs: string[]; resources: string[]; apiGroups: string[] }[] }[] } }>;
}

interface NetworkingV1Api {
  listNetworkPolicyForAllNamespaces(): Promise<{ body: { items: { metadata?: { name: string; namespace: string }; spec?: { podSelector: {}; policyTypes?: string[]; ingress?: any[]; egress?: any[] } }[] } }>;
}

interface AppsV1Api {
  listDeploymentForAllNamespaces(): Promise<{ body: { items: { metadata?: { name: string; namespace: string }; spec?: { replicas?: number; template?: { spec?: { containers: any[] } } } }[] } }>;
}

export interface K8sConfig extends AdapterConfig {
  kubeconfigPath?: string;
  context?: string;
  namespaces?: string[]; // empty = all
}

export class K8sAdapter extends BaseAdapter {
  private core: CoreV1Api;
  private rbac: RbacAuthorizationV1Api;
  private network: NetworkingV1Api;
  private apps: AppsV1Api;

  constructor(config: K8sConfig) {
    super(config);
    // In real usage: const k8s = require('@kubernetes/client-node');
    this.core = {} as CoreV1Api;
    this.rbac = {} as RbacAuthorizationV1Api;
    this.network = {} as NetworkingV1Api;
    this.apps = {} as AppsV1Api;
  }

  get name(): string { return 'k8s'; }

  async scan(): Promise<AdapterScanResult> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    // --- CC6.1: RBAC & Identity ---
    const rbacFindings = await this.scanRBAC();
    findings.push(...rbacFindings.findings);
    evidence.push(...rbacFindings.evidence);

    // --- CC6.6: Secrets & Encryption ---
    const secretFindings = await this.scanSecrets();
    findings.push(...secretFindings.findings);
    evidence.push(...secretFindings.evidence);

    // --- CC6.7: Network Security ---
    const networkFindings = await this.scanNetwork();
    findings.push(...networkFindings.findings);
    evidence.push(...networkFindings.evidence);

    // --- CC7.2: Pod Security Standards ---
    const podFindings = await this.scanPods();
    findings.push(...podFindings.findings);
    evidence.push(...podFindings.evidence);

    // --- A1.1: Node Health & Availability ---
    const nodeFindings = await this.scanNodes();
    findings.push(...nodeFindings.findings);
    evidence.push(...nodeFindings.evidence);

    return { findings, evidence, adapter: this.name, timestamp: new Date() };
  }

  // ==================== CC6.1: RBAC ====================
  private async scanRBAC(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const clusterBindings = await this.rbac.listClusterRoleBinding();
      const bindings = clusterBindings.body.items || [];

      // Check for overly permissive cluster-admin bindings
      const adminBindings = bindings.filter(b =>
        b.roleRef?.name === 'cluster-admin' &&
        b.subjects?.some(s => s.kind === 'ServiceAccount' || s.kind === 'Group')
      );

      if (adminBindings.length > 0) {
        findings.push({
          id: `k8s-rbac-001`,
          controlId: 'CC6.1',
          title: 'Overly Permissive cluster-admin Bindings',
          description: `${adminBindings.length} ClusterRoleBinding(s) grant cluster-admin to service accounts or groups. Principle of least privilege violated.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: 'ClusterRoleBinding',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      // Check for wildcard permissions in ClusterRoles
      const clusterRoles = await this.rbac.listClusterRole();
      const wildcardRoles = (clusterRoles.body.items || []).filter(r =>
        r.rules?.some(rule =>
          rule.verbs.includes('*') &&
          rule.resources.includes('*') &&
          rule.apiGroups.includes('*')
        )
      );

      if (wildcardRoles.length > 0) {
        findings.push({
          id: `k8s-rbac-002`,
          controlId: 'CC6.1',
          title: 'ClusterRoles with Wildcard Permissions',
          description: `${wildcardRoles.length} ClusterRole(s) have wildcard (*) permissions on all resources and verbs.`,
          severity: 'critical',
          status: FindingStatus.OPEN,
          resource: 'ClusterRole',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `k8s-rbac-ev-${Date.now()}`,
        controlId: 'CC6.1',
        adapter: this.name,
        resource: 'RBAC',
        rawData: {
          clusterRoleBindings: bindings.length,
          adminBindings: adminBindings.length,
          wildcardRoles: wildcardRoles.length,
        },
        collectedAt: new Date(),
        severity: adminBindings.length > 0 ? EvidenceSeverity.HIGH : EvidenceSeverity.LOW,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('CC6.1', 'RBAC scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== CC6.6: Secrets ====================
  private async scanSecrets(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const secrets = await this.core.listSecretForAllNamespaces();
      const items = secrets.body.items || [];

      // Check for default secrets (auto-generated tokens)
      const defaultSecrets = items.filter(s =>
        s.metadata?.name?.startsWith('default-token-')
      );

      if (defaultSecrets.length > 0) {
        findings.push({
          id: `k8s-secret-001`,
          controlId: 'CC6.6',
          title: 'Default Service Account Tokens Present',
          description: `${defaultSecrets.length} default service account token secret(s) found. These auto-mounted tokens increase attack surface.`,
          severity: 'medium',
          status: FindingStatus.OPEN,
          resource: 'Secret',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      // Check for secrets in default namespace
      const defaultNsSecrets = items.filter(s => s.metadata?.namespace === 'default');
      if (defaultNsSecrets.length > 0) {
        findings.push({
          id: `k8s-secret-002`,
          controlId: 'CC6.6',
          title: 'Secrets Stored in Default Namespace',
          description: `${defaultNsSecrets.length} secret(s) found in the default namespace. Secrets should be in dedicated namespaces.`,
          severity: 'low',
          status: FindingStatus.OPEN,
          resource: 'Secret',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `k8s-secret-ev-${Date.now()}`,
        controlId: 'CC6.6',
        adapter: this.name,
        resource: 'Secret',
        rawData: {
          totalSecrets: items.length,
          defaultTokens: defaultSecrets.length,
          defaultNamespaceSecrets: defaultNsSecrets.length,
        },
        collectedAt: new Date(),
        severity: EvidenceSeverity.MEDIUM,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('CC6.6', 'Secret scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== CC6.7: Network Policies ====================
  private async scanNetwork(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const policies = await this.network.listNetworkPolicyForAllNamespaces();
      const items = policies.body.items || [];

      // Check for namespaces without network policies
      const allPods = await this.core.listPodForAllNamespaces();
      const namespacesWithPods = new Set(allPods.body.items?.map(p => p.metadata?.namespace).filter(Boolean));
      const namespacesWithPolicies = new Set(items.map(p => p.metadata?.namespace));

      const unprotectedNamespaces = Array.from(namespacesWithPods).filter(ns => !namespacesWithPolicies.has(ns));

      if (unprotectedNamespaces.length > 0) {
        findings.push({
          id: `k8s-net-001`,
          controlId: 'CC6.7',
          title: 'Namespaces Without Network Policies',
          description: `${unprotectedNamespaces.length} namespace(s) with pods have no NetworkPolicy. All pod-to-pod traffic is allowed by default.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: 'NetworkPolicy',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      // Check for overly permissive policies (allow all ingress)
      const allowAllIngress = items.filter(p =>
        !p.spec?.ingress || p.spec.ingress.length === 0 ||
        p.spec.ingress.some(i => !i.from || i.from.length === 0)
      );

      if (allowAllIngress.length > 0) {
        findings.push({
          id: `k8s-net-002`,
          controlId: 'CC6.7',
          title: 'Network Policies Allowing All Ingress',
          description: `${allowAllIngress.length} NetworkPolicy(s) allow unrestricted ingress traffic.`,
          severity: 'medium',
          status: FindingStatus.OPEN,
          resource: 'NetworkPolicy',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `k8s-net-ev-${Date.now()}`,
        controlId: 'CC6.7',
        adapter: this.name,
        resource: 'NetworkPolicy',
        rawData: {
          totalPolicies: items.length,
          unprotectedNamespaces: unprotectedNamespaces.length,
          allowAllIngress: allowAllIngress.length,
        },
        collectedAt: new Date(),
        severity: unprotectedNamespaces.length > 0 ? EvidenceSeverity.HIGH : EvidenceSeverity.LOW,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('CC6.7', 'Network scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== CC7.2: Pod Security ====================
  private async scanPods(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const pods = await this.core.listPodForAllNamespaces();
      const items = pods.body.items || [];

      let privilegedPods = 0;
      let rootPods = 0;
      let noReadOnlyRoot = 0;
      let missingDropAll = 0;
      let hostNetworkPods = 0;

      for (const pod of items) {
        const containers = pod.spec?.containers || [];

        for (const container of containers) {
          const sc = container.securityContext || {};

          if (sc.privileged) privilegedPods++;
          if (sc.runAsRoot || !sc.runAsNonRoot) rootPods++;
          if (sc.readOnlyRootFilesystem !== true) noReadOnlyRoot++;

          const caps = sc.capabilities || {};
          const dropped = caps.drop || [];
          if (!dropped.includes('ALL')) missingDropAll++;
        }

        if (pod.spec?.hostNetwork) hostNetworkPods++;
        if (pod.spec?.hostPID) hostNetworkPods++;
        if (pod.spec?.hostIPC) hostNetworkPods++;
      }

      if (privilegedPods > 0) {
        findings.push({
          id: `k8s-pod-001`,
          controlId: 'CC7.2',
          title: 'Privileged Containers Detected',
          description: `${privilegedPods} container(s) run in privileged mode. This grants full host access and violates Pod Security Standards.`,
          severity: 'critical',
          status: FindingStatus.OPEN,
          resource: 'Pod',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      if (rootPods > 0) {
        findings.push({
          id: `k8s-pod-002`,
          controlId: 'CC7.2',
          title: 'Containers Running as Root',
          description: `${rootPods} container(s) run as root or without runAsNonRoot. This increases container escape risk.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: 'Pod',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      if (hostNetworkPods > 0) {
        findings.push({
          id: `k8s-pod-003`,
          controlId: 'CC7.2',
          title: 'Pods Using Host Network/PID/IPC',
          description: `${hostNetworkPods} pod(s) use hostNetwork, hostPID, or hostIPC. This breaks container isolation.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: 'Pod',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      if (missingDropAll > 0) {
        findings.push({
          id: `k8s-pod-004`,
          controlId: 'CC7.2',
          title: 'Containers Without ALL Capabilities Dropped',
          description: `${missingDropAll} container(s) do not drop ALL capabilities. Only required capabilities should be added explicitly.`,
          severity: 'medium',
          status: FindingStatus.OPEN,
          resource: 'Pod',
          adapter: this.name,
          remediationAvailable: true,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `k8s-pod-ev-${Date.now()}`,
        controlId: 'CC7.2',
        adapter: this.name,
        resource: 'Pod',
        rawData: {
          totalPods: items.length,
          privilegedContainers: privilegedPods,
          rootContainers: rootPods,
          noReadOnlyRootFilesystem: noReadOnlyRoot,
          missingDropAll: missingDropAll,
          hostNetworkPods: hostNetworkPods,
        },
        collectedAt: new Date(),
        severity: privilegedPods > 0 ? EvidenceSeverity.CRITICAL : EvidenceSeverity.MEDIUM,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('CC7.2', 'Pod security scan failed', err));
    }

    return { findings, evidence };
  }

  // ==================== A1.1: Node Health ====================
  private async scanNodes(): Promise<{ findings: Finding[]; evidence: Evidence[] }> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    try {
      const nodes = await this.core.listNode();
      const items = nodes.body.items || [];

      // Check for outdated kubelet versions
      const outdatedNodes = items.filter(n => {
        const version = n.status?.nodeInfo?.kubeletVersion || '';
        // Simple check: if version doesn't start with v1.2x or v1.3x
        return !version.match(/^v1\.(2[0-9]|3[0-9])/);
      });

      if (outdatedNodes.length > 0) {
        findings.push({
          id: `k8s-node-001`,
          controlId: 'A1.1',
          title: 'Outdated Kubernetes Node Versions',
          description: `${outdatedNodes.length} node(s) run outdated kubelet versions. This poses availability and security risks.`,
          severity: 'high',
          status: FindingStatus.OPEN,
          resource: 'Node',
          adapter: this.name,
          remediationAvailable: false,
          createdAt: new Date(),
        });
      }

      evidence.push({
        id: `k8s-node-ev-${Date.now()}`,
        controlId: 'A1.1',
        adapter: this.name,
        resource: 'Node',
        rawData: {
          totalNodes: items.length,
          outdatedNodes: outdatedNodes.length,
          versions: items.map(n => n.status?.nodeInfo?.kubeletVersion),
        },
        collectedAt: new Date(),
        severity: outdatedNodes.length > 0 ? EvidenceSeverity.HIGH : EvidenceSeverity.LOW,
      });
    } catch (err) {
      findings.push(this.createErrorFinding('A1.1', 'Node scan failed', err));
    }

    return { findings, evidence };
  }

  private createErrorFinding(controlId: string, title: string, error: unknown): Finding {
    return {
      id: `k8s-error-${controlId}-${Date.now()}`,
      controlId,
      title,
      description: error instanceof Error ? error.message : String(error),
      severity: 'medium',
      status: FindingStatus.ERROR,
      resource: 'kubernetes',
      adapter: this.name,
      remediationAvailable: false,
      createdAt: new Date(),
    };
  }
}

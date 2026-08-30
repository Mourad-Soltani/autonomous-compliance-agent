import React, { useState } from 'react';

interface CustomControlForm {
  id: string;
  title: string;
  description: string;
  category: 'SECURITY' | 'AVAILABILITY' | 'CONFIDENTIALITY' | 'PROCESSING_INTEGRITY' | 'PRIVACY';
  soc2Mapping: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  adapter: 'aws' | 'azure' | 'gcp' | 'github' | 'custom';
  checkType: 'api' | 'cli' | 'config' | 'custom';
  checkConfig: string;
  remediationEnabled: boolean;
  remediationConfig: string;
  automated: boolean;
}

const SOC2_MAPPINGS = [
  'CC1.1', 'CC1.2', 'CC1.3', 'CC1.4', 'CC1.5',
  'CC2.1', 'CC2.2', 'CC2.3',
  'CC3.1', 'CC3.2', 'CC3.3', 'CC3.4',
  'CC4.1', 'CC4.2',
  'CC5.1', 'CC5.2', 'CC5.3',
  'CC6.1', 'CC6.2', 'CC6.3', 'CC6.4', 'CC6.5', 'CC6.6', 'CC6.7', 'CC6.8',
  'CC7.1', 'CC7.2', 'CC7.3', 'CC7.4', 'CC7.5',
  'CC8.1',
  'A1.1', 'A1.2', 'A1.3',
  'C1.1', 'C1.2',
  'PI1.1', 'PI1.2', 'PI1.3',
  'P1.1', 'P2.1', 'P3.1', 'P4.1', 'P5.1', 'P6.1', 'P7.1', 'P8.1',
];

const ADAPTER_OPTIONS = [
  { value: 'aws', label: 'AWS', icon: '☁️' },
  { value: 'azure', label: 'Azure', icon: '🔷' },
  { value: 'gcp', label: 'GCP', icon: '🔶' },
  { value: 'github', label: 'GitHub', icon: '🐙' },
  { value: 'custom', label: 'Custom / Manual', icon: '🔧' },
];

const CHECK_TEMPLATES: Record<string, string> = {
  aws: `// AWS SDK Check Template
const { EC2Client, DescribeSecurityGroupsCommand } = require('@aws-sdk/client-ec2');
const client = new EC2Client({ region: process.env.AWS_REGION });

async function check() {
  const result = await client.send(new DescribeSecurityGroupsCommand({}));
  // Return array of findings or empty array if compliant
  return result.SecurityGroups.map(sg => ({
    id: sg.GroupId,
    compliant: !sg.IpPermissions.some(p => p.IpRanges?.some(r => r.CidrIp === '0.0.0.0/0')),
    details: sg.GroupName,
  }));
}`,
  azure: `// Azure SDK Check Template
const { NetworkManagementClient } = require('@azure/arm-network');
const client = new NetworkManagementClient(credentials, subscriptionId);

async function check() {
  const nsgRules = await client.securityRules.list(resourceGroupName, nsgName);
  return nsgRules.map(rule => ({
    id: rule.id,
    compliant: rule.sourceAddressPrefix !== '*',
    details: rule.name,
  }));
}`,
  gcp: `// GCP SDK Check Template
const { Storage } = require('@google-cloud/storage');
const storage = new Storage();

async function check() {
  const [buckets] = await storage.getBuckets();
  return buckets.map(bucket => ({
    id: bucket.id,
    compliant: bucket.metadata.iamConfiguration?.uniformBucketLevelAccess?.enabled,
    details: bucket.name,
  }));
}`,
  github: `// GitHub API Check Template
const { Octokit } = require('@octokit/rest');
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

async function check() {
  const { data: repo } = await octokit.repos.get({ owner, repo });
  return [{
    id: repo.id,
    compliant: !!repo.security_and_analysis?.secret_scanning?.status,
    details: repo.full_name,
  }];
}`,
  custom: `// Custom Check Template
async function check() {
  // Implement your custom compliance check here
  // Must return array of { id, compliant, details }
  return [{
    id: 'custom-check-1',
    compliant: true,
    details: 'Custom check passed',
  }];
}`,
};

const REMEDIATION_TEMPLATES: Record<string, string> = {
  aws: `// AWS Remediation Template
async function remediate(finding) {
  // Implement AWS-specific remediation
  // Return { success, message, actionTaken }
}`,
  azure: `// Azure Remediation Template
async function remediate(finding) {
  // Implement Azure-specific remediation
}`,
  gcp: `// GCP Remediation Template
async function remediate(finding) {
  // Implement GCP-specific remediation
}`,
  github: `// GitHub Remediation Template
async function remediate(finding) {
  // Implement GitHub-specific remediation
}`,
  custom: `// Custom Remediation Template
async function remediate(finding) {
  // Implement your custom remediation logic
  return { success: true, message: 'Remediated', actionTaken: 'custom_fix' };
}`,
};

export default function CustomControlBuilder() {
  const [form, setForm] = useState<CustomControlForm>({
    id: '',
    title: '',
    description: '',
    category: 'SECURITY',
    soc2Mapping: 'CC6.1',
    severity: 'medium',
    adapter: 'aws',
    checkType: 'api',
    checkConfig: CHECK_TEMPLATES.aws,
    remediationEnabled: false,
    remediationConfig: '',
    automated: true,
  });

  const [preview, setPreview] = useState<string>('');
  const [saved, setSaved] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const updateForm = (field: keyof CustomControlForm, value: any) => {
    const newForm = { ...form, [field]: value };

    // Auto-update templates when adapter changes
    if (field === 'adapter') {
      newForm.checkConfig = CHECK_TEMPLATES[value] || CHECK_TEMPLATES.custom;
      if (newForm.remediationEnabled) {
        newForm.remediationConfig = REMEDIATION_TEMPLATES[value] || REMEDIATION_TEMPLATES.custom;
      }
    }

    setForm(newForm);
    setSaved(false);
  };

  const validate = (): boolean => {
    const errs: string[] = [];
    if (!form.id.trim()) errs.push('Control ID is required');
    if (!form.title.trim()) errs.push('Title is required');
    if (!form.description.trim()) errs.push('Description is required');
    if (!/^[A-Z0-9]+\.\d+$/.test(form.soc2Mapping)) errs.push('Invalid SOC 2 mapping format (e.g., CC6.1)');
    if (!form.checkConfig.trim()) errs.push('Check configuration is required');
    setErrors(errs);
    return errs.length === 0;
  };

  const generatePreview = () => {
    if (!validate()) return;

    const control = {
      id: form.id,
      title: form.title,
      description: form.description,
      category: form.category,
      soc2Mapping: form.soc2Mapping,
      severity: form.severity,
      adapter: form.adapter,
      checkType: form.checkType,
      checkConfig: form.checkConfig,
      remediation: form.remediationEnabled ? {
        enabled: true,
        config: form.remediationConfig,
      } : { enabled: false },
      automated: form.automated,
      createdAt: new Date().toISOString(),
    };

    setPreview(JSON.stringify(control, null, 2));
  };

  const handleSave = async () => {
    if (!validate()) return;

    try {
      const response = await fetch('/api/controls/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });

      if (response.ok) {
        setSaved(true);
        setPreview('');
      } else {
        const err = await response.json();
        setErrors([err.message || 'Failed to save control']);
      }
    } catch (e) {
      setErrors([`Network error: ${e instanceof Error ? e.message : String(e)}`]);
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">🛠️ Custom Control Builder</h1>
        <p className="text-gray-400">Create custom compliance controls without writing backend code.</p>
      </div>

      {errors.length > 0 && (
        <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-4 mb-6">
          {errors.map((err, i) => (
            <p key={i} className="text-red-400 text-sm">⚠️ {err}</p>
          ))}
        </div>
      )}

      {saved && (
        <div className="bg-green-900/30 border border-green-500/50 rounded-lg p-4 mb-6">
          <p className="text-green-400 text-sm">✅ Control saved successfully!</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Form */}
        <div className="space-y-6">
          {/* Basic Info */}
          <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
            <h2 className="text-lg font-semibold text-white mb-4">Basic Information</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Control ID</label>
                <input
                  type="text"
                  value={form.id}
                  onChange={e => updateForm('id', e.target.value)}
                  placeholder="e.g., CUSTOM-SEC-001"
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Title</label>
                <input
                  type="text"
                  value={form.title}
                  onChange={e => updateForm('title', e.target.value)}
                  placeholder="e.g., Ensure custom encryption policy"
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
                <textarea
                  value={form.description}
                  onChange={e => updateForm('description', e.target.value)}
                  placeholder="Describe what this control checks and why it matters..."
                  rows={3}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none resize-none"
                />
              </div>
            </div>
          </div>

          {/* Classification */}
          <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
            <h2 className="text-lg font-semibold text-white mb-4">Classification</h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Category</label>
                <select
                  value={form.category}
                  onChange={e => updateForm('category', e.target.value)}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="SECURITY">Security</option>
                  <option value="AVAILABILITY">Availability</option>
                  <option value="CONFIDENTIALITY">Confidentiality</option>
                  <option value="PROCESSING_INTEGRITY">Processing Integrity</option>
                  <option value="PRIVACY">Privacy</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">SOC 2 Mapping</label>
                <select
                  value={form.soc2Mapping}
                  onChange={e => updateForm('soc2Mapping', e.target.value)}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  {SOC2_MAPPINGS.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Severity</label>
                <select
                  value={form.severity}
                  onChange={e => updateForm('severity', e.target.value)}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="critical">🔴 Critical</option>
                  <option value="high">🟠 High</option>
                  <option value="medium">🟡 Medium</option>
                  <option value="low">🟢 Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Automation</label>
                <select
                  value={form.automated ? 'true' : 'false'}
                  onChange={e => updateForm('automated', e.target.value === 'true')}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="true">🤖 Automated</option>
                  <option value="false">👤 Manual</option>
                </select>
              </div>
            </div>
          </div>

          {/* Adapter & Check */}
          <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
            <h2 className="text-lg font-semibold text-white mb-4">Check Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Target Adapter</label>
                <div className="grid grid-cols-5 gap-2">
                  {ADAPTER_OPTIONS.map(opt => (
                    <button
                      key={opt.value}
                      onClick={() => updateForm('adapter', opt.value)}
                      className={`p-3 rounded-lg border text-center transition-all ${
                        form.adapter === opt.value
                          ? 'border-blue-500 bg-blue-500/20 text-blue-400'
                          : 'border-gray-600 bg-gray-900 text-gray-400 hover:border-gray-500'
                      }`}
                    >
                      <div className="text-xl mb-1">{opt.icon}</div>
                      <div className="text-xs">{opt.label}</div>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Check Type</label>
                <select
                  value={form.checkType}
                  onChange={e => updateForm('checkType', e.target.value)}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="api">API Call</option>
                  <option value="cli">CLI Command</option>
                  <option value="config">Configuration File</option>
                  <option value="custom">Custom Script</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Check Implementation</label>
                <textarea
                  value={form.checkConfig}
                  onChange={e => updateForm('checkConfig', e.target.value)}
                  rows={12}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-sm font-mono text-green-400 placeholder-gray-500 focus:border-blue-500 focus:outline-none resize-none"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Write JavaScript/TypeScript. Must export an async <code>check()</code> function returning{' '}
                  <code>{`{ id, compliant, details }[]`}</code>.
                </p>
              </div>
            </div>
          </div>

          {/* Remediation */}
          <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Remediation</h2>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.remediationEnabled}
                  onChange={e => {
                    updateForm('remediationEnabled', e.target.checked);
                    if (e.target.checked && !form.remediationConfig) {
                      updateForm('remediationConfig', REMEDIATION_TEMPLATES[form.adapter] || REMEDIATION_TEMPLATES.custom);
                    }
                  }}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-300">Enable auto-remediation</span>
              </label>
            </div>
            {form.remediationEnabled && (
              <div>
                <textarea
                  value={form.remediationConfig}
                  onChange={e => updateForm('remediationConfig', e.target.value)}
                  rows={8}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-sm font-mono text-orange-400 placeholder-gray-500 focus:border-blue-500 focus:outline-none resize-none"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Must export an async <code>remediate(finding)</code> function returning{' '}
                  <code>{`{ success, message, actionTaken }`}</code>.
                </p>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex gap-4">
            <button
              onClick={generatePreview}
              className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-medium py-3 px-6 rounded-lg transition-colors"
            >
              👁️ Preview JSON
            </button>
            <button
              onClick={handleSave}
              className="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-medium py-3 px-6 rounded-lg transition-colors"
            >
              💾 Save Control
            </button>
          </div>
        </div>

        {/* Preview Panel */}
        <div className="lg:sticky lg:top-6 h-fit">
          <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
            <h2 className="text-lg font-semibold text-white mb-4">Live Preview</h2>
            {preview ? (
              <pre className="bg-gray-900 rounded-lg p-4 text-sm font-mono text-green-400 overflow-x-auto">
                {preview}
              </pre>
            ) : (
              <div className="bg-gray-900 rounded-lg p-8 text-center">
                <p className="text-gray-500">Click "Preview JSON" to see the generated control definition.</p>
              </div>
            )}
          </div>

          <div className="mt-6 bg-gray-800/50 rounded-xl p-6 border border-gray-700">
            <h2 className="text-lg font-semibold text-white mb-4">Quick Tips</h2>
            <ul className="space-y-2 text-sm text-gray-400">
              <li>• Control IDs should be unique and descriptive</li>
              <li>• Use the adapter templates as starting points</li>
              <li>• Automated controls run on every audit scan</li>
              <li>• Manual controls require auditor sign-off</li>
              <li>• Always test remediation in a sandbox first</li>
              <li>• Custom controls can target any API or CLI</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

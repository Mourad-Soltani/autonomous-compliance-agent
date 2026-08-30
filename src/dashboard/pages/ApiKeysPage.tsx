import React, { useState, useEffect } from 'react';

interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  createdAt: string;
}

const AVAILABLE_SCOPES = [
  { value: 'read:audit', label: 'Read Audit Data', description: 'View audit runs, findings, and evidence' },
  { value: 'write:controls', label: 'Manage Controls', description: 'Create and modify compliance controls' },
  { value: 'write:remediate', label: 'Trigger Remediation', description: 'Execute auto-remediation actions' },
  { value: 'admin', label: 'Admin', description: 'Full access including user management' },
];

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState<{ name: string; scopes: string[]; expiresInDays: number }>({
    name: '',
    scopes: ['read:audit'],
    expiresInDays: 90,
  });
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [error, setError] = useState('');

  const token = localStorage.getItem('aca_token') || '';

  useEffect(() => {
    fetchKeys();
  }, []);

  const fetchKeys = async () => {
    try {
      const res = await fetch('/api/auth/api-keys', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setKeys(data.keys);
      }
    } catch {
      setError('Failed to load API keys');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const res = await fetch('/api/auth/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(newKey),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create key');

      setCreatedKey(data.key);
      setShowCreate(false);
      fetchKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create key');
    }
  };

  const handleRevoke = async (keyId: string) => {
    if (!confirm('Are you sure? This key will be immediately revoked.')) return;

    try {
      const res = await fetch(`/api/auth/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });

      if (res.ok) {
        setKeys(keys.filter(k => k.id !== keyId));
      }
    } catch {
      setError('Failed to revoke key');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const formatDate = (date: string | null) => {
    if (!date) return 'Never';
    return new Date(date).toLocaleDateString();
  };

  const getScopeBadge = (scope: string) => {
    const colors: Record<string, string> = {
      'read:audit': 'bg-blue-900/50 text-blue-400 border-blue-500/30',
      'write:controls': 'bg-green-900/50 text-green-400 border-green-500/30',
      'write:remediate': 'bg-orange-900/50 text-orange-400 border-orange-500/30',
      'admin': 'bg-red-900/50 text-red-400 border-red-500/30',
    };
    return colors[scope] || 'bg-gray-800 text-gray-400 border-gray-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">🔑 API Keys</h1>
          <p className="text-gray-400 mt-1">Manage programmatic access to the ACA API</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 px-4 rounded-lg transition-colors"
        >
          + New API Key
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-4 mb-6">
          <p className="text-red-400 text-sm">⚠️ {error}</p>
        </div>
      )}

      {/* New Key Created Banner */}
      {createdKey && (
        <div className="bg-green-900/30 border border-green-500/50 rounded-lg p-4 mb-6">
          <p className="text-green-400 text-sm font-medium mb-2">✅ API Key Created — Copy it now, it won't be shown again!</p>
          <div className="flex gap-2">
            <code className="flex-1 bg-gray-900 rounded px-3 py-2 text-green-400 text-sm font-mono break-all">
              {createdKey}
            </code>
            <button
              onClick={() => copyToClipboard(createdKey)}
              className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded-lg text-sm transition-colors"
            >
              Copy
            </button>
            <button
              onClick={() => setCreatedKey(null)}
              className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded-lg text-sm transition-colors"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Create Form */}
      {showCreate && (
        <div className="bg-gray-800/50 rounded-xl border border-gray-700 p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">Create New API Key</h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Key Name</label>
              <input
                type="text"
                value={newKey.name}
                onChange={e => setNewKey({ ...newKey, name: e.target.value })}
                placeholder="e.g., CI/CD Pipeline"
                required
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Scopes</label>
              <div className="space-y-2">
                {AVAILABLE_SCOPES.map(scope => (
                  <label key={scope.value} className="flex items-start gap-3 p-3 bg-gray-900 rounded-lg cursor-pointer hover:bg-gray-800 transition-colors">
                    <input
                      type="checkbox"
                      checked={newKey.scopes.includes(scope.value)}
                      onChange={e => {
                        if (e.target.checked) {
                          setNewKey({ ...newKey, scopes: [...newKey.scopes, scope.value] });
                        } else {
                          setNewKey({ ...newKey, scopes: newKey.scopes.filter(s => s !== scope.value) });
                        }
                      }}
                      className="mt-0.5 w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500"
                    />
                    <div>
                      <p className="text-sm font-medium text-white">{scope.label}</p>
                      <p className="text-xs text-gray-500">{scope.description}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Expires In (days)</label>
              <input
                type="number"
                value={newKey.expiresInDays}
                onChange={e => setNewKey({ ...newKey, expiresInDays: parseInt(e.target.value) })}
                min={1}
                max={365}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div className="flex gap-3">
              <button
                type="submit"
                className="bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 px-6 rounded-lg transition-colors"
              >
                Create Key
              </button>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-6 rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Keys List */}
      <div className="bg-gray-800/50 rounded-xl border border-gray-700 overflow-hidden">
        {keys.length === 0 ? (
          <div className="p-12 text-center">
            <p className="text-gray-500 text-lg">No API keys yet</p>
            <p className="text-gray-600 text-sm mt-1">Create one to get started with programmatic access</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left text-xs font-medium text-gray-400 uppercase px-6 py-3">Name</th>
                <th className="text-left text-xs font-medium text-gray-400 uppercase px-6 py-3">Key</th>
                <th className="text-left text-xs font-medium text-gray-400 uppercase px-6 py-3">Scopes</th>
                <th className="text-left text-xs font-medium text-gray-400 uppercase px-6 py-3">Last Used</th>
                <th className="text-left text-xs font-medium text-gray-400 uppercase px-6 py-3">Expires</th>
                <th className="text-right text-xs font-medium text-gray-400 uppercase px-6 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map(key => (
                <tr key={key.id} className="border-b border-gray-700/50 hover:bg-gray-800/50">
                  <td className="px-6 py-4">
                    <p className="text-white font-medium">{key.name}</p>
                  </td>
                  <td className="px-6 py-4">
                    <code className="text-sm text-gray-400 font-mono">{key.keyPrefix}••••••••</code>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-1">
                      {key.scopes.map(scope => (
                        <span key={scope} className={`text-xs px-2 py-0.5 rounded border ${getScopeBadge(scope)}`}>
                          {scope}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-400">{formatDate(key.lastUsedAt)}</td>
                  <td className="px-6 py-4 text-sm text-gray-400">{formatDate(key.expiresAt)}</td>
                  <td className="px-6 py-4 text-right">
                    <button
                      onClick={() => handleRevoke(key.id)}
                      className="text-red-400 hover:text-red-300 text-sm font-medium transition-colors"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="mt-6 bg-gray-800/30 rounded-lg p-4 border border-gray-700/50">
        <h3 className="text-sm font-medium text-white mb-2">📖 Using API Keys</h3>
        <code className="block bg-gray-900 rounded px-4 py-3 text-sm font-mono text-green-400">
          curl -H "Authorization: Bearer aca_xxxxxxxx" https://aca.example.com/api/audit/runs
        </code>
      </div>
    </div>
  );
}

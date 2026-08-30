/* ============================================
   Compliance Agent Dashboard — App Logic
   ============================================ */

const API_BASE = 'http://localhost:3000';

// Navigation
const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');
const pageTitle = document.getElementById('pageTitle');

navItems.forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const targetPage = item.dataset.page;
    switchPage(targetPage);
  });
});

function switchPage(pageId) {
  navItems.forEach(n => n.classList.remove('active'));
  pages.forEach(p => p.classList.remove('active'));

  const activeNav = document.querySelector(`[data-page="${pageId}"]`);
  if (activeNav) activeNav.classList.add('active');

  const activePage = document.getElementById(`page-${pageId}`);
  if (activePage) activePage.classList.add('active');

  const titles = {
    overview: 'Overview',
    audits: 'Audit Runs',
    controls: 'SOC 2 Controls',
    evidence: 'Evidence',
  };
  pageTitle.textContent = titles[pageId] || 'Overview';

  // Refresh data when switching pages
  if (pageId === 'audits') loadAudits();
  if (pageId === 'controls') loadControls();
  if (pageId === 'evidence') loadEvidence();
}

// API Helpers
async function apiGet(endpoint) {
  const res = await fetch(`${API_BASE}${endpoint}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(endpoint) {
  const res = await fetch(`${API_BASE}${endpoint}`, { method: 'POST' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  toast.innerHTML = `
    <span class="toast-icon">${icons[type]}</span>
    <span class="toast-message">${message}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// Loading State
function setLoading(show, text = 'Running compliance audit...') {
  const overlay = document.getElementById('loadingOverlay');
  overlay.querySelector('p').textContent = text;
  overlay.classList.toggle('active', show);
}

// Health Check
async function checkHealth() {
  const statusEl = document.getElementById('apiStatus');
  try {
    await apiGet('/health');
    statusEl.innerHTML = '<span class="status-dot connected"></span> API Connected';
    showToast('Connected to Compliance Agent API', 'success');
  } catch {
    statusEl.innerHTML = '<span class="status-dot error"></span> API Offline';
    showToast('Cannot connect to API. Is the server running on port 3000?', 'error');
  }
}

// Trigger Audit
async function triggerAudit() {
  setLoading(true, 'Running compliance audit...');
  try {
    const result = await apiPost('/audit');
    showToast(`Audit complete! ${result.summary.compliantCount}/${result.summary.totalControls} passed.`, 'success');
    await loadOverview();
    await loadAudits();
  } catch (err) {
    showToast(`Audit failed: ${err.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

// Trigger Remediate
async function triggerRemediate() {
  setLoading(true, 'Running audit + auto-remediation...');
  try {
    const result = await apiPost('/remediate');
    const fixed = result.remediations
      ? Object.values(result.remediations).filter(r => r.success).length
      : 0;
    showToast(`Audit complete! ${fixed} controls auto-remediated.`, 'success');
    await loadOverview();
    await loadAudits();
  } catch (err) {
    showToast(`Remediation failed: ${err.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

// Load Overview
async function loadOverview() {
  try {
    const runs = await apiGet('/audit/runs?limit=1');
    const controls = await apiGet('/controls');

    const latest = runs.runs?.[0];
    const totalControls = controls.count || 0;

    // Stats
    document.getElementById('statTotal').textContent = totalControls;

    if (latest) {
      const { compliantCount, nonCompliantCount, notEvaluatedCount, totalControls: total } = latest;
      const passRate = total > 0 ? Math.round((compliantCount / total) * 100) : 0;

      document.getElementById('statCompliant').textContent = compliantCount;
      document.getElementById('statCompliantPct').textContent = `${passRate}% pass rate`;
      document.getElementById('statNonCompliant').textContent = nonCompliantCount;
      document.getElementById('statNonCompliantPct').textContent = nonCompliantCount > 0 ? 'Action required' : 'All clear';
      document.getElementById('statNotEvaluated').textContent = notEvaluatedCount;

      // Latest audit details
      const statusClass = passRate === 100 ? 'badge-success' : passRate >= 70 ? 'badge-warning' : 'badge-danger';
      const statusText = passRate === 100 ? 'Fully Compliant' : passRate >= 70 ? 'Mostly Compliant' : 'Critical Issues';

      document.getElementById('latestStatus').className = `badge ${statusClass}`;
      document.getElementById('latestStatus').textContent = statusText;

      const date = new Date(latest.timestamp).toLocaleString();
      document.getElementById('latestAuditDetails').innerHTML = `
        <div class="remediation-list">
          <div class="remediation-item">
            <span class="remediation-icon">📅</span>
            <div class="remediation-content">
              <div class="remediation-title">Run ID</div>
              <div class="remediation-desc">${latest.id}</div>
            </div>
          </div>
          <div class="remediation-item">
            <span class="remediation-icon">⏰</span>
            <div class="remediation-content">
              <div class="remediation-title">Timestamp</div>
              <div class="remediation-desc">${date}</div>
            </div>
          </div>
          <div class="remediation-item">
            <span class="remediation-icon">📊</span>
            <div class="remediation-content">
              <div class="remediation-title">Results</div>
              <div class="remediation-desc">
                ${compliantCount} compliant · ${nonCompliantCount} non-compliant · ${notEvaluatedCount} not evaluated
              </div>
            </div>
          </div>
        </div>
      `;

      // Draw chart
      drawComplianceChart(compliantCount, nonCompliantCount, notEvaluatedCount);

      // Remediation activity
      if (latest.results) {
        const nonCompliantResults = latest.results.filter(r => r.status === 'NON_COMPLIANT');
        if (nonCompliantResults.length > 0) {
          document.getElementById('remediationActivity').innerHTML = `
            <div class="remediation-list">
              ${nonCompliantResults.map(r => `
                <div class="remediation-item failed">
                  <span class="remediation-icon">⚠️</span>
                  <div class="remediation-content">
                    <div class="remediation-title">${r.controlId} — ${r.control?.title || 'Unknown Control'}</div>
                    <div class="remediation-desc">${r.findings?.join('; ') || 'No findings recorded.'}</div>
                  </div>
                </div>
              `).join('')}
            </div>
          `;
        }
      }
    } else {
      document.getElementById('statCompliant').textContent = '0';
      document.getElementById('statCompliantPct').textContent = '—';
      document.getElementById('statNonCompliant').textContent = '0';
      document.getElementById('statNonCompliantPct').textContent = '—';
      document.getElementById('statNotEvaluated').textContent = '0';
    }
  } catch (err) {
    console.error('Failed to load overview:', err);
  }
}

// Draw Compliance Chart
function drawComplianceChart(compliant, nonCompliant, notEvaluated) {
  const canvas = document.getElementById('complianceChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const total = compliant + nonCompliant + notEvaluated;
  if (total === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '14px Inter';
    ctx.textAlign = 'center';
    ctx.fillText('No data', rect.width / 2, rect.height / 2);
    return;
  }

  const centerX = rect.width / 2;
  const centerY = rect.height / 2;
  const radius = Math.min(centerX, centerY) - 30;
  const innerRadius = radius * 0.6;

  const data = [
    { value: compliant, color: '#22c55e', label: 'Compliant' },
    { value: nonCompliant, color: '#ef4444', label: 'Non-Compliant' },
    { value: notEvaluated, color: '#f59e0b', label: 'Not Evaluated' },
  ];

  let currentAngle = -Math.PI / 2;

  data.forEach(segment => {
    const sliceAngle = (segment.value / total) * 2 * Math.PI;

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
    ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
    ctx.closePath();
    ctx.fillStyle = segment.color;
    ctx.fill();

    // Label
    const labelAngle = currentAngle + sliceAngle / 2;
    const labelRadius = radius + 20;
    const labelX = centerX + Math.cos(labelAngle) * labelRadius;
    const labelY = centerY + Math.sin(labelAngle) * labelRadius;

    ctx.fillStyle = '#94a3b8';
    ctx.font = '11px Inter';
    ctx.textAlign = 'center';
    ctx.fillText(`${segment.label}: ${segment.value}`, labelX, labelY);

    currentAngle += sliceAngle;
  });

  // Center text
  const passRate = Math.round((compliant / total) * 100);
  ctx.fillStyle = '#f1f5f9';
  ctx.font = 'bold 24px Inter';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${passRate}%`, centerX, centerY - 8);
  ctx.font = '12px Inter';
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('Pass Rate', centerX, centerY + 14);
}

// Load Audits
async function loadAudits() {
  try {
    const data = await apiGet('/audit/runs?limit=20');
    const tbody = document.querySelector('#auditsTable tbody');

    if (!data.runs || data.runs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No audit runs yet.</td></tr>';
      return;
    }

    tbody.innerHTML = data.runs.map(run => {
      const date = new Date(run.timestamp).toLocaleString();
      const total = run.totalControls;
      const passRate = total > 0 ? Math.round((run.compliantCount / total) * 100) : 0;
      const statusClass = passRate === 100 ? 'compliant' : passRate >= 70 ? 'not-evaluated' : 'non-compliant';
      const statusText = passRate === 100 ? 'Pass' : passRate >= 70 ? 'Warning' : 'Fail';

      return `
        <tr>
          <td>${date}</td>
          <td>${run.totalControls}</td>
          <td>${run.compliantCount}</td>
          <td>${run.nonCompliantCount}</td>
          <td>${run.notEvaluatedCount}</td>
          <td>${passRate}%</td>
          <td><span class="status-pill ${statusClass}">${statusText}</span></td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load audits:', err);
  }
}

// Load Controls
async function loadControls() {
  try {
    const data = await apiGet('/controls');
    const tbody = document.querySelector('#controlsTable tbody');

    if (!data.controls || data.controls.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No controls configured.</td></tr>';
      return;
    }

    tbody.innerHTML = data.controls.map(c => {
      const severityClass = `severity-${c.severity.toLowerCase()}`;
      const date = new Date(c.updatedAt).toLocaleDateString();

      return `
        <tr>
          <td><strong>${c.id}</strong></td>
          <td>${c.title}</td>
          <td>${c.category}</td>
          <td><span class="severity ${severityClass}">${c.severity}</span></td>
          <td>${c.isAutomated ? '✅ Yes' : '❌ No'}</td>
          <td>${date}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load controls:', err);
  }
}

// Load Evidence
async function loadEvidence() {
  try {
    const data = await apiGet('/evidence?limit=50');
    const tbody = document.querySelector('#evidenceTable tbody');

    if (!data.evidence || data.evidence.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No evidence collected yet.</td></tr>';
      return;
    }

    tbody.innerHTML = data.evidence.map(e => {
      const date = new Date(e.timestamp).toLocaleString();
      const mode = e.rawPayload?.mode || 'LIVE';
      const modeBadge = mode === 'MOCK'
        ? '<span class="severity severity-medium">MOCK</span>'
        : '<span class="severity severity-low">LIVE</span>';

      return `
        <tr>
          <td><strong>${e.controlId}</strong> ${modeBadge}</td>
          <td>${e.sourceAdapter}</td>
          <td>${date}</td>
          <td class="truncate" title="${e.resourceArn || 'N/A'}">${e.resourceArn || 'N/A'}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load evidence:', err);
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  loadOverview();
  loadAudits();
  loadControls();
  loadEvidence();

  // Refresh every 30 seconds
  setInterval(() => {
    loadOverview();
    if (document.getElementById('page-audits').classList.contains('active')) loadAudits();
    if (document.getElementById('page-controls').classList.contains('active')) loadControls();
    if (document.getElementById('page-evidence').classList.contains('active')) loadEvidence();
  }, 30000);
});

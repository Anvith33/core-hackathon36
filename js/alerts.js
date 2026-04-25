/* ====================================================
   FraudShield – alerts.js (API Integration)
   Fetches risk-related notifications from the backend
   ==================================================== */

const API_BASE = 'http://localhost:5001/api';
const currentUser = (typeof getSession === 'function') ? getSession() : JSON.parse(localStorage.getItem('fraudshield_session'));

const ICON_SVG = {
  critical: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  warning:`<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
};

let allRiskAlerts = [];

async function fetchAlerts() {
  if (!currentUser) return;
  try {
    const res = await fetch(`${API_BASE}/alerts?user_id=${currentUser.id}`);
    const alerts = await res.json();
    // Filter to only show risk-relevant alerts (Critical/Warning)
    allRiskAlerts = alerts.filter(a => a.type === 'critical' || a.type === 'warning');
    renderAlerts(allRiskAlerts);
    updateSummary(allRiskAlerts);
  } catch (err) {
    console.error('Alerts fetch failed:', err);
  }
}

function filterAlerts(type, btn) {
  document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
  
  if (type === 'all') {
    renderAlerts(allRiskAlerts);
  } else {
    renderAlerts(allRiskAlerts.filter(a => a.type === type));
  }
}

function renderAlerts(alerts) {
  const container = document.getElementById('alertsContainer');
  if (!container) return;

  if (alerts.length === 0) {
    container.innerHTML = `
      <div class="glass-card" style="padding:4rem 2rem;text-align:center;border:1px solid rgba(255,255,255,0.05)">
        <div style="width:64px;height:64px;background:rgba(16,185,129,0.1);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 1.5rem">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>
        </div>
        <h3 style="font-family:var(--fhead);font-size:1.25rem;color:var(--t1);margin-bottom:8px">No Transaction Risks Detected</h3>
        <p style="color:var(--t3);font-size:0.9rem;max-width:320px;margin:0 auto">Your financial activity is currently clean. We'll notify you here if any suspicious patterns are found.</p>
      </div>`;
    return;
  }

  container.innerHTML = alerts.map(a => `
    <div class="full-alert-card ${a.type}">
      <div class="alert-card-header">
        <div class="alert-card-icon aci-${a.type}">${ICON_SVG[a.type]}</div>
        <div>
          <div class="alert-card-title">
            ${a.title}
            <span class="chip ${a.type === 'critical' ? 'chip-crimson' : 'chip-amber'}" style="font-size:0.62rem">${a.type.toUpperCase()}</span>
          </div>
        </div>
      </div>
      <div class="alert-card-desc">${a.message}</div>
      <div class="alert-card-footer">
        <div class="alert-card-time">${timeAgo(a.timestamp)}</div>
        <div class="alert-card-actions">
          <button class="alert-action-btn" onclick="showToast('Risk noted. Reviewing...','info')">Investigate</button>
          <button class="alert-action-btn btn-take-action" onclick="showToast('Reported to Anti-Fraud unit!','success')">Report Fraud</button>
        </div>
      </div>
    </div>
  `).join('');
}

function updateSummary(alerts) {
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('cnt-critical', alerts.filter(a => a.type === 'critical').length);
  el('cnt-warning', alerts.filter(a => a.type === 'warning').length);
}

document.addEventListener('DOMContentLoaded', () => {
  if (currentUser) fetchAlerts();
});

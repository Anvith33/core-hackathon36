/* ====================================================
   FraudShield – dashboard.js v3.1
   All logic runs INSIDE DOMContentLoaded so that
   auth.js is guaranteed to have loaded before we
   try to read the session.
   ==================================================== */

// ---- Session Check ----
const currentUser = JSON.parse(localStorage.getItem('fraudshield_user'));
if (!currentUser) {
  window.location.href = 'login.html';
}

function updateUserInfo() {
  if (!currentUser) return;
  const nameEl = document.querySelector('.user-name');
  const avatarEl = document.querySelector('.user-avatar');
  if (nameEl) nameEl.textContent = currentUser.name || 'User';
  if (avatarEl) {
    avatarEl.textContent = currentUser.initials || currentUser.name?.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) || 'U';
  }

}

document.addEventListener('DOMContentLoaded', updateUserInfo);










const SVG_ICONS = {
  shieldAlert: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  alertTriangle: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  lock: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
  checkCircle: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>`,
  check: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20,6 9,17 4,12"/></svg>`,
  shield: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/></svg>`,
  warn: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
};

    updateScoreUI(d.safetyScore || 0);

    // Alert badge
    const badge = el('alertBadge');
    if (badge) {
      const n = d.scannedTotal || 0;
      badge.textContent = n;
      badge.style.display = n > 0 ? 'flex' : 'none';
    }
  } catch (err) {
    console.error('fetchStats error:', err);
    const level = el('safetyLevel');
    if (level) level.innerHTML = `<span style="color:var(--crimson-lt)">Backend Error — refresh page</span>`;
  }
}

// ── Activity list ────────────────────────────────────────────────
function renderActivity(txns) {
  const list = el('txnList');
  if (!list) return;
  if (!txns.length) {
    list.innerHTML = `<div style="text-align:center;padding:2rem;color:var(--t3);font-size:0.875rem">No transactions yet. Send money to see activity!</div>`;
    return;
  }
  list.innerHTML = txns.map(t => {
    const isSafe  = t.status === 'safe';
    const isWarn  = t.status === 'warn';
    const color   = t.status === 'blocked' ? '#ef4444' : isWarn ? '#f59e0b' : '#10b981';
    const init    = (t.recipient_name || '??').substring(0,2).toUpperCase();
    const ago     = typeof timeAgo === 'function' ? timeAgo(t.timestamp) : t.timestamp;
    const amount  = typeof formatCurrency === 'function' ? formatCurrency(t.amount) : '₹'+t.amount;
    return `
    <div class="txn-row">
      <div class="txn-avatar" style="background:${color}">${init}</div>
      <div class="txn-info">
        <div class="txn-name">${t.recipient_name || t.upi_id}</div>
        <div class="txn-sub">${t.upi_id} · ${ago}</div>
      </div>
      <div class="txn-right">
        <div class="txn-amount debit">-${amount}</div>
        <div class="txn-badge ${isSafe?'tb-safe':isWarn?'tb-warn':'tb-blocked'}">
          ${isSafe ? SVG.check+' Safe' : isWarn ? SVG.warn+' Review' : SVG.block+' Blocked'}
        </div>
      </div>
    </div>`;
  }).join('');
}

async function fetchActivity(userId) {
  try {
    const res = await fetch(`${API_BASE}/transactions?user_id=${userId}&cb=${Date.now()}`);
    const txns = await res.json();
    renderActivity(txns);
  } catch (err) { console.warn('fetchActivity:', err); }
}

// ── Alerts list ────────────────────────────────────────────────
function renderAlerts(alerts) {
  const list = el('alertList');
  if (!list) return;
  if (!alerts.length) {
    list.innerHTML = `<div style="text-align:center;padding:1rem;color:var(--t3);font-size:0.82rem">No risk alerts found.</div>`;
    return;
  }
  const ago = typeof timeAgo === 'function' ? timeAgo : s => s;
  list.innerHTML = alerts.slice(0, 5).map(a => `
    <div class="alert-row ${a.type}" onclick="window.location='alerts.html'" style="cursor:pointer">
      <div class="alert-row-icon ai-${a.type}">${a.type==='critical'?SVG.shieldAlert:SVG.alertTri}</div>
      <div>
        <div class="alert-row-title">${a.title}</div>
        <div class="alert-row-desc">${(a.message||'').substring(0,60)}…</div>
        <div class="alert-row-time">${ago(a.timestamp)}</div>
      </div>
    </div>
  `).join('');
}

async function fetchAlerts(userId) {
  try {
    const res = await fetch(`${API_BASE}/alerts?user_id=${userId}&cb=${Date.now()}`);
    const alerts = await res.json();
    renderAlerts(alerts);
  } catch (err) { console.warn('fetchAlerts:', err); }
}

// ── MAIN INIT — inside DOMContentLoaded so auth.js is ready ───────
document.addEventListener('DOMContentLoaded', () => {
  // Read session HERE (not at file top) so auth.js is already parsed
  const user = (typeof getSession === 'function')
    ? getSession()
    : JSON.parse(localStorage.getItem('fraudshield_session') || 'null');

  if (!user) {
    console.warn('Dashboard: no session — redirecting to login');
    // Let auth.js handle the redirect
    return;
  }

  console.log(`Dashboard: user=${user.fullName} id=${user.id}`);

  // Load all data
  fetchStats(user.id);
  fetchActivity(user.id);
  fetchAlerts(user.id);

  // Refresh every 30 seconds for "live monitoring"
  setInterval(() => {
    fetchStats(user.id);
    fetchActivity(user.id);
  }, 30000);
});

/* ====================================================
   FraudShield – app.js  v2 (SVG icons, no emojis)
   Shared utilities: sidebar, modals, toasts, data helpers
   ==================================================== */

// ---- Global Session Guard ----
(function() {
  const path = window.location.pathname;
  if (!path.endsWith('login.html') && !path.endsWith('index.html') && path !== '/' && !path.endsWith('/core-hackathon36/')) {
    const user = localStorage.getItem('fraudshield_user');
    if (!user) {
      window.location.href = 'login.html';
    }
  }
})();

// ---- Logout Handler ----
window.logout = function() {
  localStorage.removeItem('fraudshield_user');
  window.location.href = 'index.html';
};

// ---- Sidebar Toggle ----
function toggleSidebar() {
  const s = document.getElementById('sidebar');
  if (s) s.classList.toggle('open');
}
document.addEventListener('click', e => {
  const s = document.getElementById('sidebar');
  const btn = document.querySelector('.menu-toggle');
  if (s && s.classList.contains('open') && !s.contains(e.target) && e.target !== btn) {
    s.classList.remove('open');
  }
});

// ---- Notification Drawer ----
function showNotifications() {
  document.getElementById('notifDrawer')?.classList.add('open');
  document.getElementById('notifOverlay')?.classList.add('active');
  const b = document.getElementById('notifBadge');
  if (b) { b.style.display = 'none'; }
}
function hideNotifications() {
  document.getElementById('notifDrawer')?.classList.remove('open');
  document.getElementById('notifOverlay')?.classList.remove('active');
}

// ---- Modals ----
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
  }
});

// ---- Toast Notifications ----
let toastContainer = null;
function ensureToastContainer() {
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toastContainer';
    Object.assign(toastContainer.style, {
      position: 'fixed', bottom: '24px', right: '24px',
      zIndex: '9999', display: 'flex', flexDirection: 'column', gap: '10px',
      pointerEvents: 'none', maxWidth: '340px'
    });
    document.body.appendChild(toastContainer);
  }
}

const TOAST_ICONS = {
  success: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>`,
  danger:  `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  warning: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  info:    `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="8"/><line x1="12" y1="12" x2="12" y2="16"/></svg>`
};

const TOAST_STYLES = {
  success: { bg: 'rgba(5,150,105,0.12)', border: 'rgba(52,211,153,0.25)', color: '#34d399' },
  danger:  { bg: 'rgba(220,38,38,0.12)',  border: 'rgba(248,113,113,0.25)', color: '#f87171' },
  warning: { bg: 'rgba(217,119,6,0.12)',  border: 'rgba(251,191,36,0.25)', color: '#fbbf24' },
  info:    { bg: 'rgba(124,58,237,0.12)', border: 'rgba(167,139,250,0.25)', color: '#a78bfa' },
};

function showToast(message, type = 'info', duration = 3500) {
  ensureToastContainer();
  const st = TOAST_STYLES[type] || TOAST_STYLES.info;
  const icon = TOAST_ICONS[type] || TOAST_ICONS.info;

  const t = document.createElement('div');
  Object.assign(t.style, {
    display: 'flex', alignItems: 'flex-start', gap: '10px',
    padding: '12px 16px',
    background: st.bg, border: `1px solid ${st.border}`,
    borderRadius: '10px', color: st.color,
    fontSize: '0.84rem', fontWeight: '600', lineHeight: '1.5',
    backdropFilter: 'blur(16px)',
    boxShadow: '0 4px 24px rgba(0,0,0,0.4)',
    pointerEvents: 'all', cursor: 'pointer',
    animation: 'toastIn 0.3s ease',
    fontFamily: "'Inter', system-ui",
  });
  t.innerHTML = `
    <span style="flex-shrink:0;margin-top:1px">${icon}</span>
    <span style="color:#f8fafc;font-weight:500">${message}</span>
  `;
  t.addEventListener('click', () => removeToast(t));
  toastContainer.appendChild(t);

  if (!document.getElementById('toastStyleEl')) {
    const style = document.createElement('style');
    style.id = 'toastStyleEl';
    style.textContent = `
      @keyframes toastIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
      @keyframes toastOut{ from{opacity:1;transform:translateY(0)} to{opacity:0;transform:translateY(10px)} }
    `;
    document.head.appendChild(style);
  }
  setTimeout(() => removeToast(t), duration);
}

function removeToast(t) {
  t.style.animation = 'toastOut 0.3s ease forwards';
  setTimeout(() => t.remove(), 300);
}

// ---- Topbar Date ----
function setTopbarDate() {
  const el = document.getElementById('topbarDate');
  if (!el) return;
  el.textContent = new Date().toLocaleDateString('en-IN', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
}
document.addEventListener('DOMContentLoaded', setTopbarDate);

// ---- Animate Counter ----
function animateCount(el, target, suffix = '') {
  if (!el) return;
  const duration = 1200, start = performance.now();
  const step = now => {
    const progress = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    const val = Math.floor(ease * target);
    el.textContent = val.toLocaleString('en-IN') + suffix;
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = target.toLocaleString('en-IN') + suffix;
  };
  requestAnimationFrame(step);
}

// ---- Currency ----
function formatCurrency(n) {
  if (n >= 100000) return '₹' + (n / 100000).toFixed(1) + 'L';
  if (n >= 1000)   return '₹' + (n / 1000).toFixed(1).replace('.0', '') + 'K';
  return '₹' + n.toLocaleString('en-IN');
}

// ---- ID Generator ----
function genId(prefix = 'ID') {
  return prefix + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

// ---- Backend Alert Helper ----
async function createBackendAlert({ type, title, message }) {
  try {
    const session = typeof getSession === 'function' ? getSession() : JSON.parse(localStorage.getItem('fraudshield_session'));
    if (!session) return;
    await fetch('http://localhost:5001/api/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: session.id, type, title, message })
    });
  } catch (err) { console.error('Alert persistence failed'); }
}

// ---- Relative Time ----
function timeAgo(date) {
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)   return 'Just now';
  if (mins < 60)  return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)   return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// ---- Local Storage ----
const Store = {
  _getUserPrefix: () => {
    try {
      const u = JSON.parse(localStorage.getItem('fraudshield_user'));
      return u && u.email ? u.email + '_' : '';
    } catch { return ''; }
  },
  get: (key, def = null) => { try { return JSON.parse(localStorage.getItem('fraudshield_' + Store._getUserPrefix() + key)) ?? def; } catch { return def; } },
  set: (key, val) => { try { localStorage.setItem('fraudshield_' + Store._getUserPrefix() + key, JSON.stringify(val)); } catch {} },
  push: (key, item, max = 50) => {
    const arr = Store.get(key, []);
    arr.unshift(item);
    if (arr.length > max) arr.pop();
    Store.set(key, arr);
    return arr;
  },
  // Aggregated Safety Score
  getSafetyScore: () => {
    const base = 50; // Starting score for new users
    const eduXP = Object.values(Store.get('learn_progress', {})).filter(v => v === 'done').length * 5;
    const txns = Store.get('transactions', []);
    const blockedCount = txns.filter(t => t.status === 'blocked').length;
    const safeCount = txns.filter(t => t.status === 'safe').length;

    // Bonus for education, bonus for safe txns, penalty for blocks (alerts handled)
    let score = base + eduXP + (safeCount * 2) - (blockedCount * 5);
    return Math.max(10, Math.min(100, score));
  }
};

// ---- Observe animations (file:// compatible) ----
function initScrollAnimations() {
  const els = document.querySelectorAll('.anim-up');
  if ('IntersectionObserver' in window && location.protocol !== 'file:') {
    const obs = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.style.opacity = '1'; obs.unobserve(e.target); } });
    }, { threshold: 0.1 });
    els.forEach(el => { el.style.opacity = '0'; obs.observe(el); });
  }
  // On file:// just show everything
}
document.addEventListener('DOMContentLoaded', initScrollAnimations);

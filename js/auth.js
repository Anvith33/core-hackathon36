/* ====================================================
   FraudShield – auth.js (API Integration)
   Connects to Flask Backend for real persistence
   ==================================================== */

const API_URL = location.hostname === 'localhost' || location.hostname === '127.0.0.1' 
  ? `http://${location.hostname}:5001/api` 
  : 'http://localhost:5001/api';
const API_BASE = API_URL; // Alias for compatibility
const SESSION_KEY = 'fraudshield_session';

async function authRegister(fullName, email, password) {
  try {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: email, password, fullName })
    });
    return await res.json();
  } catch (err) {
    return { success: false, message: 'Backend server is offline.' };
  }
}

async function authLogin(email, password) {
  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: email, password })
    });
    const data = await res.json();
    if (data.success) {
      localStorage.setItem(SESSION_KEY, JSON.stringify(data.user));
    }
    return data;
  } catch (err) {
    return { success: false, message: 'Backend server is offline.' };
  }
}

function authLogout() {
  localStorage.removeItem(SESSION_KEY);
  window.location.href = 'login.html';
}

function getSession() {
  try { return JSON.parse(localStorage.getItem(SESSION_KEY)); }
  catch { return null; }
}

function requireAuth() {
  const session = getSession();
  if (!session) {
    window.location.href = 'login.html';
    return null;
  }
  return session;
}

function populateSidebarUser() {
  const session = getSession();
  if (!session) return;
  const nameEl   = document.getElementById('sidebarName');
  const avatarEl = document.getElementById('sidebarAvatar');
  if (nameEl)   nameEl.textContent = session.fullName;
  if (avatarEl) {
    const parts = session.fullName.trim().split(' ');
    const initials = parts.length >= 2 ? parts[0][0] + parts[parts.length - 1][0] : session.fullName.substring(0, 2);
    avatarEl.textContent = initials.toUpperCase();
  }
}

function addLogoutButton() {
  const footer = document.querySelector('.sidebar-footer');
  if (!footer || document.getElementById('logoutBtn')) return;
  const btn = document.createElement('button');
  btn.id = 'logoutBtn';
  btn.innerHTML = `
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
    Sign Out
  `;
  Object.assign(btn.style, {
    display: 'flex', alignItems: 'center', gap: '8px',
    width: '100%', marginTop: '12px', padding: '10px 14px',
    background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.2)',
    borderRadius: '10px', color: '#f87171', fontSize: '0.82rem',
    fontWeight: '700', cursor: 'pointer', fontFamily: 'var(--fbody)',
    transition: 'background 0.2s'
  });
  btn.onmouseenter = () => btn.style.background = 'rgba(244,63,94,0.18)';
  btn.onmouseleave = () => btn.style.background = 'rgba(244,63,94,0.08)';
  btn.onclick = () => { if (confirm('Are you sure you want to sign out?')) authLogout(); };
  footer.appendChild(btn);
}

document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  const isLoginPage = path.includes('login.html');
  const isIndexPage = path.endsWith('/') || path.endsWith('index.html');
  if (isLoginPage || isIndexPage) return;
  const session = requireAuth();
  if (session) {
    populateSidebarUser();
    addLogoutButton();
  }
});

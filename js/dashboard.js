/* ====================================================
   FraudShield – dashboard.js  v2 (SVG icons, no emojis)
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


const TRANSACTIONS = [
  { id:'T001', name:'Amazon India',    upi:'amazon@pay',       amount:1299,  type:'debit',  status:'safe',    time: new Date(Date.now()-3600000),   init:'AM', color:'#f97316' },
  { id:'T002', name:'Swiggy',          upi:'swiggy@sbi',       amount:380,   type:'debit',  status:'safe',    time: new Date(Date.now()-7200000),   init:'SW', color:'#ef4444' },
  { id:'T003', name:'Priya Sharma',    upi:'priya@paytm',      amount:5001,  type:'debit',  status:'warn',    time: new Date(Date.now()-10800000),  init:'PS', color:'#7c3aed' },
  { id:'T004', name:'Salary Credit',   upi:'hdfc@corp',        amount:45001, type:'credit', status:'safe',    time: new Date(Date.now()-86400000),  init:'HD', color:'#059669' },
  { id:'T005', name:'Fake Lottery Co', upi:'prize.winner@pay', amount:15001, type:'debit',  status:'blocked', time: new Date(Date.now()-172800000), init:'FL', color:'#dc2626' },
  { id:'T006', name:'Netflix India',   upi:'netflix@upi',      amount:649,   type:'debit',  status:'safe',    time: new Date(Date.now()-259200000), init:'NF', color:'#7c3aed' },
];

const ALERTS_DATA = [
  { id:'A001', level:'critical', iconType:'shieldAlert', title:'Phishing SMS Detected',        desc:'A link via SMS matches phishing patterns for SBI bank impersonation.', time: new Date(Date.now()-1800000) },
  { id:'A002', level:'warning',  iconType:'alertTriangle', title:'Large Transaction Paused',   desc:'A payment of ₹25,000 to "prize.claim@pay" was automatically paused.', time: new Date(Date.now()-3600000) },
  { id:'A003', level:'warning',  iconType:'lock', title:'New Device Login Detected',           desc:'Your account was accessed from a new device in Mumbai.', time: new Date(Date.now()-7200000) },
];

const NOTIFICATIONS_DATA = [
  { iconType:'shieldAlert', level:'critical', title:'Critical Alert',        body:'Phishing SMS detected targeting your bank!', time:'2 min ago' },
  { iconType:'alertTriangle', level:'warning', title:'Large Transaction',    body:'A ₹25,000 transfer was paused for review.', time:'1 hr ago' },
  { iconType:'checkCircle',   level:'success', title:'Safety Tip',          body:'Your Safety Score improved after completing a lesson.', time:'3 hr ago' },
];

const RADAR_DATA = [
  { label:'Phishing Risk',      pct: 22, color:'#dc2626' },
  { label:'UPI Fraud Risk',     pct: 15, color:'#f97316' },
  { label:'SIM Swap Risk',      pct: 8,  color:'#d97706' },
  { label:'Social Eng. Risk',   pct: 30, color:'#7c3aed' },
  { label:'Account Takeover',   pct: 12, color:'#0284c7' },
  { label:'OTP Exposure Risk',  pct: 18, color:'#0d9488' },
];

const SVG_ICONS = {
  shieldAlert: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  alertTriangle: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  lock: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
  checkCircle: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>`,
  check: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20,6 9,17 4,12"/></svg>`,
  shield: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/></svg>`,
  warn: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
};

function renderTransactions() {
  const list = document.getElementById('txnList');
  if (!list) return;

  const localTxns = Store.get('transactions', []);
  const allTxns = [...localTxns, ...TRANSACTIONS].slice(0, 10);

  list.innerHTML = allTxns.map(t => `
    <div class="txn-row" id="txn_${t.id}">
      <div class="txn-avatar" style="background:${t.color}">${t.init}</div>
      <div class="txn-info">
        <div class="txn-name">${t.name}</div>
        <div class="txn-sub">${t.upi} · ${timeAgo(t.time)}</div>
      </div>
      <div class="txn-right">
        <div class="txn-amount ${t.type}">${t.type==='debit'?'-':'+'}${formatCurrency(t.amount)}</div>
        <div class="txn-badge ${t.status==='safe'?'tb-safe':t.status==='warn'?'tb-warn':'tb-blocked'}">
          ${t.status==='safe'
            ? SVG_ICONS.check + ' Safe'
            : t.status==='warn'
              ? SVG_ICONS.warn + ' Review'
              : SVG_ICONS.shield + ' Blocked'
          }
        </div>
      </div>
    </div>
  `).join('');
}

function renderAlerts() {
  const list = document.getElementById('alertList');
  if (!list) return;
  list.innerHTML = ALERTS_DATA.map(a => `
    <div class="alert-row ${a.level}" id="alert_${a.id}" onclick="window.location='alerts.html'" style="cursor:pointer">
      <div class="alert-row-icon ai-${a.level}">${SVG_ICONS[a.iconType]}</div>
      <div>
        <div class="alert-row-title">${a.title}</div>
        <div class="alert-row-desc">${a.desc.substring(0,75)}…</div>
        <div class="alert-row-time">${timeAgo(a.time)}</div>
      </div>
    </div>
  `).join('');
}

function renderNotifications() {
  const list = document.getElementById('notifList');
  if (!list) return;
  const levelColors = { critical:'si-crimson', warning:'si-amber', success:'si-emerald' };
  list.innerHTML = NOTIFICATIONS_DATA.map(n => `
    <div class="notif-item">
      <div class="notif-item-icon ${levelColors[n.level]||'si-violet'}">${SVG_ICONS[n.iconType]}</div>
      <div>
        <div class="notif-body-title">${n.title}</div>
        <div class="notif-body-text">${n.body}</div>
        <div class="notif-time">${n.time}</div>
      </div>
    </div>
  `).join('');
}

function renderRadar() {
  const grid = document.getElementById('radarGrid');
  if (!grid) return;
  grid.innerHTML = RADAR_DATA.map((r,i) => `
    <div class="radar-item" id="ri${i}">
      <div class="radar-label">${r.label}</div>
      <div class="bar-track">
        <div class="bar-fill" id="rf${i}" style="width:0%;background:${r.color}"></div>
      </div>
      <div class="radar-pct" style="color:${r.color}">${r.pct}%</div>
    </div>
  `).join('');
  setTimeout(() => RADAR_DATA.forEach((r,i) => {
    const b = document.getElementById('rf'+i);
    if (b) b.style.width = r.pct + '%';
  }), 300);
}

function animateSafetyScore(score) {
  const circle = document.getElementById('scoreRingCircle');
  if (!circle) return;
  const circumference = 2 * Math.PI * 56; // ~351.86
  const offset = circumference - (circumference * score / 100);
  setTimeout(() => {
    circle.style.transition = 'stroke-dashoffset 1.5s cubic-bezier(0.4,0,0.2,1)';
    circle.setAttribute('stroke-dashoffset', offset);

    const level = document.getElementById('safetyLevel');
    const tip   = document.getElementById('safetyTip');

    if (score >= 85) {
      if (level) { level.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg> <span style="color:var(--emerald-lt)">Low Risk — Well Protected</span>`; }
      if (tip)   tip.textContent = 'Great job! Your account security is strong.';
    } else if (score >= 65) {
      if (level) { level.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> <span style="color:var(--amber-lt)">Moderate Risk</span>`; }
      if (tip)   tip.textContent = 'Complete your profile verification to boost your score!';
    } else {
      if (level) { level.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> <span style="color:var(--crimson-lt)">High Risk — Take Action</span>`; }
      if (tip)   tip.textContent = 'Review your security alerts immediately!';
    }

    animateCount(document.getElementById('safetyScore'), score);
    animateCount(document.getElementById('ringScorelabel'), score, '%');
  }, 400);
}

function simulateLiveAlert() {
  setTimeout(() => {
    showToast('New alert: Suspicious transaction pattern detected!', 'danger', 5001);
    const b = document.getElementById('alertBadge');
    const n = document.getElementById('notifBadge');
    if (b) b.textContent = '4';
    if (n) n.textContent = '4';
  }, 9000);
}

document.addEventListener('DOMContentLoaded', () => {
  const localTxns = Store.get('transactions', []);
  const blockedTxns = localTxns.filter(t => t.status === 'blocked');
  const safeTxns = localTxns.filter(t => t.status === 'safe');
  const totalSaved = blockedTxns.reduce((sum, t) => sum + t.amount, 47500); // 47500 is base mock

  renderTransactions();
  renderAlerts();
  renderNotifications();
  renderRadar();

  const finalScore = Store.getSafetyScore();
  animateSafetyScore(finalScore);

  simulateLiveAlert();

  setTimeout(() => {
    animateCount(document.getElementById('statBlockedVal'), 12 + blockedTxns.length);
    animateCount(document.getElementById('statSavedVal'), totalSaved);
    animateCount(document.getElementById('statTxnVal'), 47 + safeTxns.length);
    animateCount(document.getElementById('statAlertsVal'), 3 + localTxns.filter(t => t.status === 'warn').length);
  }, 600);
});

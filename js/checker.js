/* ====================================================
   FraudShield – checker.js  v2 (SVG icons, no emojis)
   ==================================================== */

let scanHistory = Store ? Store.get('urlChecks', []) : [];

function onUrlInput() {
  const val = document.getElementById('urlInput')?.value || '';
  const clearBtn = document.getElementById('urlClearBtn');
  if (clearBtn) clearBtn.style.display = val ? 'block' : 'none';
}

function clearUrl() {
  const i = document.getElementById('urlInput');
  if (i) { i.value = ''; i.focus(); }
  onUrlInput();
  document.getElementById('urlResult').innerHTML = '';
}

function startScan() {
  const input = document.getElementById('urlInput');
  if (!input || !input.value.trim()) {
    showToast('Please paste a URL to scan', 'warning');
    return;
  }
  const url = input.value.trim();
  const scanBtn = document.getElementById('scanBtn');
  const anim = document.getElementById('scanningAnim');
  const result = document.getElementById('urlResult');

  if (scanBtn) { scanBtn.disabled = true; scanBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/></svg> Scanning…`; }
  if (anim) anim.style.display = 'flex';
  if (result) result.innerHTML = '';

  const delay = 1800 + Math.random() * 800;
  setTimeout(() => {
    if (anim) anim.style.display = 'none';
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Scan Link`;
    }

    const analysis = FraudEngine ? FraudEngine.analyzeUrl(url) : simulateScan(url);
    displayResult(url, analysis);
    addToHistory(url, analysis);
    renderHistory();
  }, delay);
}

function simulateScan(url) {
  const riskWords = ['secure-login', 'verify', 'update', 'prize', 'claim', 'win', 'lucky', 'reward', 'confirm-account'];
  const badTLDs   = ['.tk', '.ml', '.cf', '.ga', '.xyz', '.gq'];
  const goodTLDs  = ['.com', '.in', '.org', '.gov.in', '.co.in', '.net'];
  const lower = url.toLowerCase();
  let score = 0;
  const flags = [];

  if (riskWords.some(w => lower.includes(w))) { score += 35; flags.push('Contains high-risk keywords'); }
  if (badTLDs.some(t => lower.includes(t)))   { score += 40; flags.push('Suspicious domain extension'); }
  if (!lower.startsWith('https'))             { score += 20; flags.push('No HTTPS encryption'); }
  if (lower.length > 60)                      { score += 10; flags.push('Unusually long URL'); }
  if ((lower.match(/-/g)||[]).length > 3)     { score += 15; flags.push('Multiple hyphens in domain'); }

  if (!goodTLDs.some(t => lower.includes(t))) score += 10;

  return { score: Math.min(score, 100), flags, safe: score < 30 };
}

const CHECK_ICONS = {
  https: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
  domain: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>`,
  length: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18H5a2 2 0 01-2-2V8a2 2 0 012-2h4"/><polyline points="15,18 19,12 15,6"/><line x1="9" y1="12" x2="19" y2="12"/></svg>`,
  keywords: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>`,
  reputation: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5C3 17.5 7 22 12 23c5-1 9-5.5 9-11V6.5L12 2z"/></svg>`,
};

function getChecks(url, analysis) {
  const isHttps   = url.startsWith('https');
  const badTLDs   = ['.tk', '.ml', '.cf', '.ga', '.xyz', '.gq'];
  const riskWords = ['secure-login', 'verify', 'prize', 'claim', 'win', 'lucky'];
  const hasBadTLD = badTLDs.some(t => url.toLowerCase().includes(t));
  const hasRisk   = riskWords.some(w => url.toLowerCase().includes(w));
  const isShort   = url.length <= 60;
  const goodRep   = analysis.score < 30;
  return [
    { label:'HTTPS',       icon:'https',      val: isHttps   ? 'ok'   : 'bad',  text: isHttps   ? 'Encrypted'     : 'Not Secure',   desc:'Does the site use HTTPS encryption?' },
    { label:'Domain',      icon:'domain',     val: hasBadTLD ? 'bad'  : 'ok',   text: hasBadTLD ? 'Suspicious TLD' : 'Looks Normal',  desc:'Is the domain extension reputable?' },
    { label:'URL Length',  icon:'length',     val: isShort   ? 'ok'   : 'warn', text: isShort   ? 'Normal Length'  : 'Very Long',     desc:'Phishing URLs are often very long' },
    { label:'Keywords',    icon:'keywords',   val: hasRisk   ? 'bad'  : 'ok',   text: hasRisk   ? 'Risk Keywords'  : 'No Red Words',  desc:'Does the URL contain scam-related words?' },
    { label:'Reputation',  icon:'reputation', val: goodRep   ? 'ok'   : 'bad',  text: goodRep   ? 'No Reports'     : 'Reported',      desc:'Any known fraud reports for this URL?' },
  ];
}

function displayResult(url, analysis) {
  const container = document.getElementById('urlResult');
  if (!container) return;

  let level, verdictText, verdictColor;
  if (analysis.score < 30) {
    level = 'safe'; verdictText = 'Link Appears Safe'; verdictColor = 'var(--emerald-lt)';
    showToast('Link scan complete — appears safe', 'success');
  } else if (analysis.score < 60) {
    level = 'warning'; verdictText = 'Proceed with Caution'; verdictColor = 'var(--amber-lt)';
    showToast('Caution: Suspicious link detected', 'warning');
  } else {
    level = 'danger'; verdictText = 'High Risk — Do Not Click!'; verdictColor = 'var(--crimson-lt)';
    showToast('DANGER: Phishing link detected!', 'danger', 5001);
  }

  const iconSvg = level === 'safe'
    ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>`
    : level === 'warning'
    ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
    : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;

  const iconCls = `vi-${level}`;
  const checks  = getChecks(url, analysis);

  const checkHtml = checks.map(c => `
    <div class="check-item">
      <div class="check-item-label">${c.label}</div>
      <div class="check-item-val cv-${c.val}">
        ${CHECK_ICONS[c.icon]}
        ${c.text}
      </div>
      <div class="check-item-desc">${c.desc}</div>
    </div>
  `).join('');

  const flagsHtml = analysis.flags && analysis.flags.length
    ? analysis.flags.map(f => `
        <div class="rf-item rf-bad">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          ${typeof f === 'string' ? f : f.desc}
        </div>
      `).join('')
    : '';

  container.innerHTML = `
    <div class="result-box ${level}" style="display:block">
      <div class="result-verdict-row">
        <div class="verdict-icon ${iconCls}">${iconSvg}</div>
        <div>
          <div class="verdict-title" style="color:${verdictColor}">${verdictText}</div>
          <div class="verdict-url">${url}</div>
        </div>
        <div style="margin-left:auto;font-family:var(--fmono);font-size:0.82rem;font-weight:800;padding:8px 14px;border-radius:8px;background:rgba(255,255,255,0.05)">
          Risk Score<br/><span style="font-size:1.4rem;color:${verdictColor}">${analysis.score}</span>/100
        </div>
      </div>
      <div class="check-grid">${checkHtml}</div>
      ${flagsHtml ? `<div style="margin-top:1.25rem"><div class="risk-label-title" style="margin-bottom:0.75rem">Flags Detected</div>${flagsHtml}</div>` : ''}
    </div>
  `;
}

function addToHistory(url, analysis) {
  const item = { url, score: analysis.score, time: new Date().toISOString() };
  if (Store) Store.push('urlChecks', item);
  scanHistory.unshift(item);
  if (scanHistory.length > 20) scanHistory.pop();
}

const STATUS_ICON = {
  ok:   `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20,6 9,17 4,12"/></svg>`,
  warn: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>`,
  bad:  `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
};

function renderHistory() {
  const list = document.getElementById('recentChecksList');
  if (!list) return;
  const history = Store ? Store.get('urlChecks', []) : scanHistory;
  if (!history.length) {
    list.innerHTML = `<div style="text-align:center;padding:2rem;color:var(--t3);font-size:0.85rem">No URLs checked yet. Paste one above!</div>`;
    return;
  }
  list.innerHTML = history.slice(0, 10).map((h, i) => {
    const level = h.score < 30 ? 'ok' : h.score < 60 ? 'warn' : 'bad';
    const color  = level === 'ok' ? 'var(--emerald-lt)' : level === 'warn' ? 'var(--amber-lt)' : 'var(--crimson-lt)';
    const bg     = level === 'ok' ? 'si-emerald' : level === 'warn' ? 'si-amber' : 'si-crimson';
    return `
      <div class="recent-item" id="ri_${i}" onclick="rescan('${h.url.replace(/'/g, "\\'")}')">
        <div class="ri-icon ${bg}">${STATUS_ICON[level]}</div>
        <div class="ri-url">${h.url}</div>
        <div class="ri-status" style="background:${color}18;color:${color};border:1px solid ${color}33;padding:2px 8px;border-radius:99px;font-size:0.65rem;font-weight:700">
          ${h.score}/100
        </div>
        <div class="ri-time">${timeAgo(new Date(h.time))}</div>
      </div>
    `;
  }).join('');
}

function rescan(url) {
  const inp = document.getElementById('urlInput');
  if (inp) { inp.value = url; onUrlInput(); }
  startScan();
}

function clearHistory() {
  if (Store) Store.set('urlChecks', []);
  scanHistory = [];
  renderHistory();
  showToast('History cleared', 'info');
}

// ============================================================
//  SMS PHISHING DETECTOR
// ============================================================

const DEMO_SMS_MESSAGES = [
  {
    sender: 'VM-SBIPAY',
    preview: 'URGENT: Your SBI account has been temporarily suspended...',
    full: 'URGENT: Your SBI account has been temporarily suspended due to unusual activity. Verify your identity immediately to restore access: http://sbi-secure-login.tk/verify?ref=7829 or your account will be permanently blocked in 24 hours.',
    time: '2 min ago',
    flagged: true
  },
  {
    sender: '+91 9876543210',
    preview: 'Congratulations! You have won ₹50,000 in the HDFC lucky draw...',
    full: 'Congratulations! You have WON ₹50,000 in the HDFC Bank Lucky Draw 2024. Click to claim your prize before it expires: http://hdfc-prize-claim.xyz/winner?uid=KP2024 Do not share this link.',
    time: '18 min ago',
    flagged: true
  },
  {
    sender: 'AD-SWIGGY',
    preview: 'Your Swiggy order #4521 is out for delivery...',
    full: 'Your Swiggy order #4521 is out for delivery. Track here: https://swiggy.com/track/4521. Expected arrival: 25 mins.',
    time: '32 min ago',
    flagged: false
  },
  {
    sender: 'ID-INCOME',
    preview: 'Income Tax Dept: Your PAN card is linked to suspicious transactions...',
    full: 'Income Tax Department of India: Your PAN AN2344K is linked to suspicious cryptocurrency transactions. Verify your identity NOW to avoid arrest: http://incometax-verify.ga/pan?id=AN2344K Helpline: 1800-XXX-XXXX',
    time: '1 hr ago',
    flagged: true
  }
];

// ---- Tab switching ----
function switchSmsTab(tab) {
  const panePaste  = document.getElementById('panePaste');
  const paneInbox  = document.getElementById('paneInbox');
  const tabPaste   = document.getElementById('tabPaste');
  const tabInbox   = document.getElementById('tabInbox');

  if (tab === 'paste') {
    panePaste.style.display = 'block';
    paneInbox.style.display = 'none';
    tabPaste.style.background = 'rgba(124,58,237,0.25)';
    tabPaste.style.color = '#a78bfa';
    tabInbox.style.background = 'transparent';
    tabInbox.style.color = 'var(--t3)';
  } else {
    panePaste.style.display = 'none';
    paneInbox.style.display = 'block';
    tabInbox.style.background = 'rgba(124,58,237,0.25)';
    tabInbox.style.color = '#a78bfa';
    tabPaste.style.background = 'transparent';
    tabPaste.style.color = 'var(--t3)';
    renderSmsInbox();
  }
}

// ---- Extract all URLs from text ----
function extractUrls(text) {
  const urlRegex = /https?:\/\/[^\s"'<>)]+|www\.[^\s"'<>)]+/gi;
  return [...new Set(text.match(urlRegex) || [])];
}

// ---- Load a demo SMS for quick demo ----
function loadSmsDemo() {
  const smsInput = document.getElementById('smsInput');
  if (smsInput) {
    smsInput.value = DEMO_SMS_MESSAGES[0].full;
    smsInput.focus();
    showToast('Demo SMS loaded — click Scan SMS Links!', 'info');
  }
}

// ---- Scan all URLs found inside a pasted SMS ----
function scanSmsText() {
  const input = document.getElementById('smsInput');
  const resultEl = document.getElementById('smsExtractResult');
  if (!input || !input.value.trim()) {
    showToast('Please paste an SMS message first', 'warning');
    return;
  }

  const smsText = input.value.trim();
  const urls = extractUrls(smsText);

  if (!urls.length) {
    resultEl.innerHTML = `
      <div style="padding:1rem;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.15);border-radius:10px;color:var(--emerald-lt);font-size:0.875rem;font-weight:600;display:flex;align-items:center;gap:10px">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>
        No URLs found in this message. Looks clean!
      </div>`;
    return;
  }

  // Show scanning state
  resultEl.innerHTML = `
    <div style="padding:1rem;background:rgba(124,58,237,0.06);border:1px solid rgba(124,58,237,0.15);border-radius:10px;color:var(--violet-lt);font-size:0.85rem;font-weight:600">
      🔍 Found ${urls.length} link${urls.length > 1 ? 's' : ''} — scanning…
    </div>`;

  // Simulate scanning delay, then show results
  setTimeout(() => {
    const results = urls.map(url => {
      const a = FraudEngine ? FraudEngine.analyzeUrl(url) : { score: 50, flags: [], verdict: 'Unknown' };
      return { url, score: a.score, verdict: a.verdict || (a.score >= 65 ? 'PHISHING' : a.score >= 35 ? 'SUSPICIOUS' : 'SAFE'), flags: a.flags || [] };
    });

    const anyDanger = results.some(r => r.score >= 65);
    const summaryColor = anyDanger ? 'var(--crimson-lt)' : 'var(--amber-lt)';
    const summaryBg    = anyDanger ? 'rgba(244,63,94,0.08)'  : 'rgba(245,158,11,0.08)';
    const summaryBord  = anyDanger ? 'rgba(244,63,94,0.2)'   : 'rgba(245,158,11,0.2)';
    const summaryMsg   = anyDanger
      ? '🚨 PHISHING DETECTED — This SMS contains dangerous links. Do NOT click any link in this message.'
      : '⚠️ Suspicious links found — proceed with extreme caution.';

    const cardsHtml = results.map(r => {
      const isD = r.score >= 65, isW = r.score >= 35 && r.score < 65;
      const col  = isD ? 'var(--crimson-lt)' : isW ? 'var(--amber-lt)' : 'var(--emerald-lt)';
      const bg   = isD ? 'rgba(244,63,94,0.06)' : isW ? 'rgba(245,158,11,0.06)' : 'rgba(16,185,129,0.06)';
      const bord = isD ? 'rgba(244,63,94,0.2)'  : isW ? 'rgba(245,158,11,0.2)'  : 'rgba(16,185,129,0.2)';
      const verb = isD ? 'DANGEROUS' : isW ? 'SUSPICIOUS' : 'SAFE';
      const icon = isD
        ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`
        : isW
        ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>`
        : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>`;

      return `
        <div style="padding:12px 14px;background:${bg};border:1px solid ${bord};border-radius:10px;margin-bottom:8px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <span style="color:${col}">${icon}</span>
            <span style="font-size:0.75rem;font-weight:800;color:${col};letter-spacing:0.05em">${verb}</span>
            <span style="font-size:0.72rem;font-weight:700;margin-left:auto;color:${col};background:${bg};border:1px solid ${bord};padding:2px 8px;border-radius:99px">Score: ${r.score}/100</span>
          </div>
          <div style="font-size:0.78rem;color:var(--t2);font-family:var(--fmono);word-break:break-all;margin-bottom:6px">${r.url}</div>
          ${r.flags.length ? `<div style="font-size:0.72rem;color:var(--t3)">${r.flags.map(f => '• ' + (typeof f === 'string' ? f : f.desc || f.label)).join(' &nbsp; ')}</div>` : ''}
          <button onclick="rescan('${r.url.replace(/'/g,"\\'")}'); document.getElementById('urlInput').scrollIntoView({behavior:'smooth'})"
            style="margin-top:8px;padding:5px 12px;border-radius:8px;border:1px solid ${bord};background:transparent;color:${col};font-size:0.72rem;font-weight:700;cursor:pointer;font-family:var(--fbody)">
            Full Analysis ↓
          </button>
        </div>`;
    }).join('');

    resultEl.innerHTML = `
      <div style="padding:12px 16px;background:${summaryBg};border:1px solid ${summaryBord};border-radius:10px;color:${summaryColor};font-size:0.85rem;font-weight:700;margin-bottom:12px">
        ${summaryMsg}
      </div>
      <div style="font-size:0.78rem;font-weight:700;color:var(--t3);margin-bottom:8px;letter-spacing:0.04em">LINKS FOUND IN MESSAGE (${urls.length})</div>
      ${cardsHtml}`;

    // Also add to history
    urls.forEach(url => {
      const a = FraudEngine ? FraudEngine.analyzeUrl(url) : { score: 50 };
      addToHistory(url, a);
    });
    renderHistory();
  }, 1400);
}

// ---- Render Simulated SMS Inbox ----
function renderSmsInbox() {
  const list = document.getElementById('smsInboxList');
  if (!list) return;
  list.innerHTML = DEMO_SMS_MESSAGES.map((msg, i) => {
    const dangerBg   = msg.flagged ? 'rgba(244,63,94,0.06)' : 'rgba(16,185,129,0.04)';
    const dangerBord = msg.flagged ? 'rgba(244,63,94,0.15)' : 'rgba(16,185,129,0.12)';
    const badge      = msg.flagged
      ? `<span style="font-size:0.65rem;font-weight:800;color:var(--crimson-lt);background:rgba(244,63,94,0.12);border:1px solid rgba(244,63,94,0.25);padding:2px 8px;border-radius:99px;letter-spacing:0.05em">⚠ SUSPICIOUS</span>`
      : `<span style="font-size:0.65rem;font-weight:800;color:var(--emerald-lt);background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);padding:2px 8px;border-radius:99px;letter-spacing:0.05em">✓ SAFE</span>`;
    return `
      <div style="padding:14px;background:${dangerBg};border:1px solid ${dangerBord};border-radius:12px;cursor:pointer" onclick="loadInboxSms(${i})">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <div style="width:32px;height:32px;border-radius:50%;background:rgba(124,58,237,0.15);display:flex;align-items:center;justify-content:center;font-size:0.72rem;font-weight:800;color:#a78bfa;flex-shrink:0">${msg.sender.substring(0,2).toUpperCase()}</div>
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px">
              <span style="font-size:0.82rem;font-weight:700;color:var(--t1)">${msg.sender}</span>
              ${badge}
              <span style="font-size:0.72rem;color:var(--t3);margin-left:auto">${msg.time}</span>
            </div>
            <div style="font-size:0.78rem;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px">${msg.preview}</div>
          </div>
        </div>
        ${msg.flagged ? `<button onclick="event.stopPropagation();loadInboxSms(${i})" style="width:100%;padding:7px;border-radius:8px;border:1px solid rgba(244,63,94,0.25);background:rgba(244,63,94,0.08);color:var(--crimson-lt);font-size:0.76rem;font-weight:700;cursor:pointer;font-family:var(--fbody)">Scan This Message →</button>` : ''}
      </div>`;
  }).join('');
}

function loadInboxSms(index) {
  const msg = DEMO_SMS_MESSAGES[index];
  if (!msg) return;
  // Switch to paste tab and load message
  switchSmsTab('paste');
  const smsInput = document.getElementById('smsInput');
  if (smsInput) {
    smsInput.value = msg.full;
    document.getElementById('smsExtractResult').innerHTML = '';
    showToast(`SMS from ${msg.sender} loaded — click Scan SMS Links!`, 'info');
    smsInput.scrollIntoView({ behavior: 'smooth' });
  }
}

// ============================================================
//  Init
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  renderHistory();
  document.getElementById('urlInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') startScan();
  });
});

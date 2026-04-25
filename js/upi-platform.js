/* ====================================================
   FraudShield – upi-platform.js
   Real smartphone mockup UPI payment flow
   ==================================================== */

let selectedPlatform = null;
let pinDigits = [];

const UPI_PLATFORMS = {
  'PhonePe':    { id:'plat-phonepe', color:'#5f259f', bg:'linear-gradient(160deg,#3d1273,#7c3aed)', label:'Pe', textColor:'white' },
  'Google Pay': { id:'plat-gpay',    color:'#4285f4', bg:'linear-gradient(160deg,#1a73e8,#34a853)', label:'G',  textColor:'white' },
  'Paytm':      { id:'plat-paytm',   color:'#00baf2', bg:'linear-gradient(160deg,#003f8a,#00baf2)', label:'PT', textColor:'white' },
  'BHIM':       { id:'plat-bhim',    color:'#1a56db', bg:'linear-gradient(160deg,#0a2e6e,#1a56db)', label:'B',  textColor:'white' },
  'Amazon Pay': { id:'plat-amazon',  color:'#ff9900', bg:'linear-gradient(160deg,#131921,#ff9900)', label:'a',  textColor:'white' },
};

/* ─── Show Platform Picker ─── */
function showPlatformPicker(value) {
  const section = document.getElementById('platformSection');
  if (!section) return;
  const isValid = value && value.length >= 4 && (value.includes('@') || /^\d{10}$/.test(value.trim()));
  if (isValid) { section.style.display = 'block'; section.style.animation = 'fadeInUp 0.35s ease'; }
  else { section.style.display = 'none'; selectedPlatform = null; updateSelectedLabel(); }
}

/* ─── Select a Platform ─── */
function selectPlatform(name) {
  selectedPlatform = name;
  Object.values(UPI_PLATFORMS).forEach(p => {
    const btn = document.getElementById(p.id);
    if (btn) { btn.classList.remove('platform-btn-active'); btn.style.borderColor=''; btn.style.boxShadow=''; }
  });
  const sel = UPI_PLATFORMS[name];
  if (sel) {
    const btn = document.getElementById(sel.id);
    if (btn) { btn.classList.add('platform-btn-active'); btn.style.borderColor=sel.color; btn.style.boxShadow=`0 0 0 2px ${sel.color}44`; }
  }
  updateSelectedLabel(name, sel?.color);
}
function updateSelectedLabel(name, color) {
  const label = document.getElementById('selectedPlatformLabel');
  if (!label) return;
  label.innerHTML = name ? `✅ <span style="color:${color}">${name}</span> selected — fill amount & proceed ↓` : '';
}

/* ─── Inject Phone Mockup Modal ─── */
function injectPhoneMockup() {
  if (document.getElementById('phoneMockupOverlay')) return;
  document.head.insertAdjacentHTML('beforeend', `<style>
    #phoneMockupOverlay {
      display:none; position:fixed; inset:0; z-index:9999;
      background:rgba(0,0,0,0.85); backdrop-filter:blur(12px);
      align-items:center; justify-content:center;
    }
    .phone-frame {
      width:320px; height:640px; position:relative;
      background:#0a0a0a;
      border-radius:48px;
      padding:4px;
      box-shadow:
        0 0 0 1px rgba(255,255,255,0.08),
        0 0 0 3px #1a1a1a,
        0 0 0 4px rgba(255,255,255,0.06),
        0 40px 120px rgba(0,0,0,0.9),
        inset 0 0 0 1px rgba(255,255,255,0.04);
    }
    .phone-screen {
      width:100%; height:100%; border-radius:44px; overflow:hidden;
      position:relative; display:flex; flex-direction:column;
      background:#fff;
    }
    /* Dynamic Island */
    .phone-island {
      position:absolute; top:10px; left:50%; transform:translateX(-50%);
      width:108px; height:34px; background:#000;
      border-radius:20px; z-index:10;
    }
    /* Side buttons */
    .phone-btn-vol-up { position:absolute; left:-5px; top:110px; width:4px; height:32px; background:#2a2a2a; border-radius:2px; }
    .phone-btn-vol-dn { position:absolute; left:-5px; top:152px; width:4px; height:32px; background:#2a2a2a; border-radius:2px; }
    .phone-btn-power  { position:absolute; right:-5px; top:130px; width:4px; height:52px; background:#2a2a2a; border-radius:2px; }

    /* Status Bar */
    .phone-status {
      display:flex; justify-content:space-between; align-items:center;
      padding:14px 24px 6px 18px; font-size:12px; font-weight:700;
      color:white; position:relative; z-index:5; flex-shrink:0;
    }
    .phone-status .time { font-size:14px; }
    .phone-status .icons { display:flex; gap:5px; align-items:center; }

    /* App Header */
    .app-header {
      padding:10px 20px 20px;
      text-align:center;
      flex-shrink:0;
    }
    .app-logo-area {
      display:flex; align-items:center; justify-content:center; gap:8px;
      margin-bottom:4px;
    }
    .app-logo-circle {
      width:36px; height:36px; border-radius:50%;
      background:rgba(255,255,255,0.2);
      display:flex; align-items:center; justify-content:center;
      font-size:14px; font-weight:900; color:white;
    }
    .app-logo-name { font-size:18px; font-weight:800; color:white; }
    .app-subtitle  { font-size:11px; color:rgba(255,255,255,0.65); }

    /* Recipient Card */
    .recipient-card {
      margin:0 16px 12px;
      background:rgba(0,0,0,0.18);
      border-radius:20px; padding:14px 16px;
      display:flex; align-items:center; gap:12px;
      backdrop-filter:blur(6px);
    }
    .recipient-avatar {
      width:44px; height:44px; border-radius:50%;
      background:rgba(255,255,255,0.25);
      display:flex; align-items:center; justify-content:center;
      font-size:16px; font-weight:800; color:white; flex-shrink:0;
    }
    .recipient-info {}
    .recipient-name { font-size:14px; font-weight:700; color:white; }
    .recipient-upi  { font-size:11px; color:rgba(255,255,255,0.65); font-family:monospace; }

    /* Amount Card */
    .amount-card {
      margin:0 16px 12px;
      background:rgba(0,0,0,0.18);
      border-radius:20px; padding:12px 16px;
      text-align:center;
      backdrop-filter:blur(6px);
    }
    .amount-label { font-size:10px; color:rgba(255,255,255,0.6); text-transform:uppercase; letter-spacing:0.06em; }
    .amount-value { font-size:30px; font-weight:900; color:white; letter-spacing:-0.02em; }

    /* White Bottom Sheet */
    .bottom-sheet {
      flex:1; background:white;
      border-radius:28px 28px 0 0;
      padding:16px 20px 12px;
      display:flex; flex-direction:column;
      margin-top:4px;
    }
    .bs-handle {
      width:36px; height:4px; background:#ddd;
      border-radius:2px; margin:0 auto 16px;
    }
    .bs-title { font-size:12px; font-weight:700; color:#aaa; text-align:center; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px; }

    /* PIN dots */
    .pin-dots { display:flex; justify-content:center; gap:12px; margin-bottom:18px; }
    .pin-dot-m {
      width:13px; height:13px; border-radius:50%;
      background:#e0e0e0; border:2px solid #ccc;
      transition:all 0.15s ease;
    }
    .pin-dot-m.filled { background:#333; border-color:#333; transform:scale(1.15); }

    /* Numpad */
    .numpad {
      display:grid; grid-template-columns:repeat(3,1fr);
      gap:8px; flex:1; align-items:center;
    }
    .nkey {
      background:none; border:none;
      width:100%; aspect-ratio:1;
      max-height:58px;
      font-size:20px; font-weight:600; color:#1a1a2e;
      border-radius:50%; cursor:pointer;
      display:flex; align-items:center; justify-content:center;
      transition:background 0.12s ease;
    }
    .nkey:active, .nkey:hover { background:#f0f0f0; }
    .nkey.disabled { opacity:0; pointer-events:none; }

    /* Processing screen */
    #mprocScreen {
      display:none; flex-direction:column;
      align-items:center; justify-content:center;
      flex:1; background:white;
      border-radius:28px 28px 0 0; margin-top:4px;
      padding:24px; text-align:center;
    }
    .proc-ring {
      width:64px; height:64px; border-radius:50%;
      border:5px solid #eee;
      animation:pringSpin 0.8s linear infinite;
    }
    @keyframes pringSpin { to { transform:rotate(360deg); } }
    #mprocText { font-size:14px; font-weight:600; color:#555; margin-top:16px; }

    /* Success screen */
    #msuccessScreen {
      display:none; flex-direction:column;
      align-items:center; justify-content:center;
      flex:1; background:white;
      border-radius:28px 28px 0 0; margin-top:4px; padding:24px;
      text-align:center;
    }
    .checkmark-circle {
      width:80px; height:80px; border-radius:50%;
      background:linear-gradient(135deg,#22c55e,#16a34a);
      display:flex; align-items:center; justify-content:center;
      animation:mkpop 0.45s cubic-bezier(0.34,1.56,0.64,1);
    }
    @keyframes mkpop { from{transform:scale(0);opacity:0;} to{transform:scale(1);opacity:1;} }
    .success-title { font-size:18px; font-weight:800; color:#111; margin:14px 0 4px; }
    .success-amt   { font-size:14px; color:#444; margin-bottom:4px; }
    .success-ref   { font-size:11px; color:#aaa; font-family:monospace; }
    .success-confetti { font-size:28px; margin-top:10px; animation:confettiBounce 0.6s ease; }
    @keyframes confettiBounce { 0%{transform:scale(0.5);} 60%{transform:scale(1.2);} 100%{transform:scale(1);} }
  </style>`);

  document.body.insertAdjacentHTML('beforeend', `
  <div id="phoneMockupOverlay" style="display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.85);backdrop-filter:blur(12px);align-items:center;justify-content:center">
    <div class="phone-frame">
      <!-- Physical buttons -->
      <div class="phone-btn-vol-up"></div>
      <div class="phone-btn-vol-dn"></div>
      <div class="phone-btn-power"></div>

      <div class="phone-screen" id="phoneScreen">
        <!-- Dynamic Island -->
        <div class="phone-island"></div>

        <!-- App Gradient Background (top portion) -->
        <div id="appGradient" style="padding-top:0;display:flex;flex-direction:column">

          <!-- Status Bar -->
          <div class="phone-status" id="phoneStatus">
            <span class="time" id="phoneTime">9:41</span>
            <div class="icons">
              <svg width="15" height="11" viewBox="0 0 15 11" fill="white"><rect x="0" y="4" width="3" height="7" rx="1"/><rect x="4" y="2" width="3" height="9" rx="1"/><rect x="8" y="0" width="3" height="11" rx="1"/><rect x="12" y="0" width="3" height="11" rx="1" opacity=".3"/></svg>
              <svg width="15" height="11" viewBox="0 0 15 11" fill="white"><path d="M7.5 2.5C9.5 2.5 11.3 3.3 12.5 4.6L14 3C12.4 1.1 10.1 0 7.5 0S2.6 1.1 1 3l1.5 1.6C3.7 3.3 5.5 2.5 7.5 2.5z" opacity=".5"/><path d="M7.5 5C8.8 5 9.9 5.5 10.7 6.3L12.2 4.8C11 3.7 9.3 3 7.5 3S4 3.7 2.8 4.8L4.3 6.3C5.1 5.5 6.2 5 7.5 5z" opacity=".75"/><circle cx="7.5" cy="9" r="2"/></svg>
              <svg width="25" height="12" viewBox="0 0 25 12" fill="none"><rect x="0.5" y="0.5" width="21" height="11" rx="3.5" stroke="white" stroke-opacity=".35"/><rect x="1.5" y="1.5" width="16" height="9" rx="2.5" fill="white"/><path d="M23 4v4a2 2 0 000-4z" fill="white" opacity=".4"/></svg>
            </div>
          </div>

          <!-- App Logo -->
          <div class="app-header" id="appHeader">
            <div class="app-logo-area">
              <div class="app-logo-circle" id="appLogoCircle"></div>
              <div class="app-logo-name" id="appLogoName"></div>
            </div>
            <div class="app-subtitle">Powered by UPI</div>
          </div>

          <!-- Recipient Card -->
          <div class="recipient-card">
            <div class="recipient-avatar" id="mRecipAvatar"></div>
            <div class="recipient-info">
              <div class="recipient-name" id="mRecipName"></div>
              <div class="recipient-upi" id="mRecipUpi"></div>
            </div>
          </div>

          <!-- Amount -->
          <div class="amount-card">
            <div class="amount-label">Paying</div>
            <div class="amount-value" id="mAmountVal"></div>
          </div>
        </div>

        <!-- PIN bottom sheet -->
        <div class="bottom-sheet" id="pinSheet">
          <div class="bs-handle"></div>
          <div class="bs-title">Enter UPI PIN</div>
          <div class="pin-dots">
            <div class="pin-dot-m" id="pd1"></div>
            <div class="pin-dot-m" id="pd2"></div>
            <div class="pin-dot-m" id="pd3"></div>
            <div class="pin-dot-m" id="pd4"></div>
            <div class="pin-dot-m" id="pd5"></div>
            <div class="pin-dot-m" id="pd6"></div>
          </div>
          <div class="numpad">
            ${[1,2,3,4,5,6,7,8,9,'','0','⌫'].map((k,i) => `
              <button class="nkey${k==='' ? ' disabled' : ''}" onclick="mPinKey('${k}')">${k}</button>
            `).join('')}
          </div>
        </div>

        <!-- Processing -->
        <div id="mprocScreen">
          <div class="proc-ring" id="procRing"></div>
          <div id="mprocText">Processing…</div>
        </div>

        <!-- Success -->
        <div id="msuccessScreen">
          <div class="checkmark-circle">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          <div class="success-title">Payment Done!</div>
          <div class="success-amt" id="mSuccessAmt"></div>
          <div class="success-ref" id="mSuccessRef"></div>
          <div class="success-confetti">🎉</div>
        </div>
      </div>
    </div>

    <!-- Close hint -->
    <div onclick="closePhoneMockup()" style="position:absolute;top:20px;right:24px;color:rgba(255,255,255,0.5);font-size:13px;cursor:pointer;font-weight:600">✕ Close</div>
  </div>`);
}

/* ─── Open Phone Mockup ─── */
function openPhoneMockup({ upi, amount, recipientName, platform }) {
  injectPhoneMockup();
  pinDigits = [];
  for (let i=1;i<=6;i++) { const d=document.getElementById(`pd${i}`); if(d) d.classList.remove('filled'); }

  const plat = UPI_PLATFORMS[platform] || UPI_PLATFORMS['PhonePe'];
  const name = recipientName || upi;

  // Set live clock
  const setTime = () => {
    const now = new Date();
    const t = document.getElementById('phoneTime');
    if(t) t.textContent = now.toLocaleTimeString('en-IN', {hour:'2-digit', minute:'2-digit', hour12:false});
  };
  setTime();
  clearInterval(window._phoneClockInterval);
  window._phoneClockInterval = setInterval(setTime, 1000);

  // Gradient
  const grad = document.getElementById('appGradient');
  if(grad) grad.style.background = plat.bg;
  const status = document.getElementById('phoneStatus');
  if(status) status.style.color = plat.textColor;

  // Logo
  document.getElementById('appLogoCircle').textContent = plat.label;
  document.getElementById('appLogoName').textContent = platform;

  // Recipient
  document.getElementById('mRecipAvatar').textContent = name.substring(0,2).toUpperCase();
  document.getElementById('mRecipName').textContent = name;
  document.getElementById('mRecipUpi').textContent = upi;
  document.getElementById('mAmountVal').textContent = `₹${Number(amount).toLocaleString('en-IN')}`;

  // Proc ring color
  const ring = document.getElementById('procRing');
  if(ring) ring.style.borderTopColor = plat.color;

  // Show sheets
  document.getElementById('pinSheet').style.display = 'flex';
  document.getElementById('mprocScreen').style.display = 'none';
  document.getElementById('msuccessScreen').style.display = 'none';

  const overlay = document.getElementById('phoneMockupOverlay');
  overlay.style.display = 'flex';
  overlay._txnData = { upi, amount, recipientName, platform };
}

function closePhoneMockup() {
  const o = document.getElementById('phoneMockupOverlay');
  if(o) o.style.display = 'none';
  clearInterval(window._phoneClockInterval);
  pinDigits = [];
}

function mPinKey(k) {
  if(k === '⌫') { pinDigits.pop(); }
  else if(k !== '' && pinDigits.length < 6) { pinDigits.push(k); }
  for(let i=1;i<=6;i++) {
    const d = document.getElementById(`pd${i}`);
    if(d) d.classList.toggle('filled', i <= pinDigits.length);
  }
  if(pinDigits.length === 6) setTimeout(startMobileProcessing, 300);
}

function startMobileProcessing() {
  document.getElementById('pinSheet').style.display = 'none';
  document.getElementById('mprocScreen').style.display = 'flex';
  const steps = ['Verifying UPI PIN…','Connecting to bank…','Authorizing payment…','Completing transfer…'];
  let i = 0;
  const iv = setInterval(() => {
    const el = document.getElementById('mprocText');
    if(el && steps[i]) el.textContent = steps[i];
    i++;
    if(i >= steps.length) { clearInterval(iv); setTimeout(showMobileSuccess, 800); }
  }, 700);
}

function showMobileSuccess() {
  const overlay = document.getElementById('phoneMockupOverlay');
  const data = overlay?._txnData || {};
  document.getElementById('mprocScreen').style.display = 'none';
  document.getElementById('msuccessScreen').style.display = 'flex';
  const refId = 'UPI' + Date.now().toString().slice(-8);
  document.getElementById('mSuccessAmt').textContent = `₹${Number(data.amount).toLocaleString('en-IN')} sent to ${data.recipientName||data.upi}`;
  document.getElementById('mSuccessRef').textContent = `Ref: ${refId}`;
  if(typeof showToast === 'function') showToast(`✅ Payment successful via ${data.platform}!`, 'success');
  setTimeout(() => { closePhoneMockup(); setTimeout(() => { window.location.href='dashboard.html'; }, 1000); }, 3000);
}

/* ─── Hook into form submit ─── */
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('transferForm');
  if(!form) return;
  form.addEventListener('submit', function(e) {
    e.preventDefault(); e.stopImmediatePropagation();
    const upi = document.getElementById('upiId')?.value?.trim();
    const amount = document.getElementById('amount')?.value;
    const purpose = document.getElementById('txnPurpose')?.value;
    const recipientName = document.getElementById('recipientName')?.value?.trim();
    if(!upi || !amount || !purpose) { if(typeof showToast==='function') showToast('Please fill all fields!','warning'); return; }
    if(!selectedPlatform) {
      if(typeof showToast==='function') showToast('Select a payment platform first!','warning');
      const s = document.getElementById('platformSection');
      if(s) { s.style.animation='none'; s.offsetHeight; s.style.animation='shake 0.4s ease'; }
      return;
    }
    if(typeof FraudEngine !== 'undefined') {
      const analysis = FraudEngine.analyzeTransaction({ upiId:upi, amount, purpose, recipientName });
      if(analysis.riskScore >= 35) {
        if(typeof showFraudWarning==='function') showFraudWarning(analysis, { upi, amount, purpose, recipientName });
        return;
      }
    }
    openPhoneMockup({ upi, amount, recipientName, platform: selectedPlatform });
  }, true);
});

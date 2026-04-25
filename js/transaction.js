/* ====================================================
   FraudShield – transaction.js
   ==================================================== */

let currentRiskScore = 0;
let currentAnalysis  = null;

// Central store — populated when user clicks Analyze, read by cancel/proceed
let _pendingTxn = { upi: '', amount: 0, name: '', purpose: 'p2p' };

// ---- Live UPI Check ----
function liveUpiCheck(value) {
  const status = document.getElementById('upiStatus');
  if (!value || value.length < 4) {
    if (status) status.innerHTML = '';
    return;
  }
  const result = FraudEngine.liveUpiCheck(value);
  if (!result) return;

  if (status) {
    const color = result.type === 'danger' ? 'var(--crimson-lt)' : result.type === 'safe' ? 'var(--emerald-lt)' : 'var(--amber-lt)';
    const icon = result.type === 'danger' ? Icons.render('xCircle', 16) : result.type === 'safe' ? Icons.render('checkCircle', 16) : Icons.render('alertTriangle', 16);
    status.innerHTML = `<span style="color:${color}" class="upi-status-icon">${icon}</span>`;
  }
  updateRiskMeter();
}

// ---- Check Amount ----
function checkAmount(value) {
  const warn = document.getElementById('amountWarning');
  if (!warn) return;
  const amt = Number(value);
  if (amt > 100000) {
    warn.textContent = '⚠️ Very large amount — are you sure? Scammers often ask for large transfers.';
    warn.className = 'amount-warning hint-danger';
  } else if (amt > 50010) {
    warn.textContent = '⚠️ Large amount detected — double-check the recipient UPI ID.';
    warn.className = 'amount-warning hint-warn';
  } else if (amt > 0) {
    warn.textContent = '';
  }
  updateRiskMeter();
}

// ---- Check Purpose ----
function checkPurpose(value) {
  const warn = document.getElementById('purposeWarning');
  if (!warn) return;
  const msgs = {
    prize: '🚨 WARNING: Paying to claim a prize is a guaranteed scam! You never need to pay to receive a prize.',
    investment: '⚠️ Caution: Verify the investment platform is SEBI/RBI registered before sending money.',
    job: '🚨 WARNING: Paying for a job opportunity is a scam. Legitimate employers will NEVER ask for money.',
    loan: '⚠️ Ensure you know the lender and have a proper agreement. Never pay processing fees upfront.',
  };
  if (msgs[value]) {
    warn.textContent = msgs[value];
    warn.className = 'purpose-warning ' + (['prize', 'job'].includes(value) ? 'hint-danger' : 'hint-warn');
  } else {
    warn.textContent = '';
  }
  updateRiskMeter();
}

// ---- Live Risk Meter Update ----
function updateRiskMeter() {
  const upi = document.getElementById('upiId')?.value || '';
  const amount = document.getElementById('amount')?.value || 0;
  const purpose = document.getElementById('txnPurpose')?.value || '';
  const recipientName = document.getElementById('recipientName')?.value || '';

  if (!upi && !amount && !purpose) return;

  const analysis = FraudEngine.analyzeTransaction({ upiId: upi, amount, purpose, recipientName });
  currentRiskScore = analysis.riskScore;
  currentAnalysis = analysis;

  const fill = document.getElementById('riskFill');
  const label = document.getElementById('riskLabel');
  const factors = document.getElementById('riskFactors');

  if (fill) {
    fill.style.width = analysis.riskScore + '%';
    fill.style.backgroundColor = analysis.color;
  }
  if (label) {
    label.textContent = analysis.label;
    label.style.color = analysis.color;
  }
  if (factors) {
    factors.innerHTML = analysis.risks.slice(0, 3).map(r => `
      <div class="risk-item ${r.level}">
        <span style="flex-shrink:0;margin-top:2px">${r.level === 'danger' ? Icons.render('shieldAlert', 14) : r.level === 'warn' ? Icons.render('alertTriangle', 14) : Icons.render('checkCircle', 14)}</span>
        <span>${r.text}</span>
      </div>
    `).join('');
  }
}

// ---- Analyze Transaction (Fast Backend AI Model) ----
async function analyzeTxn(e) {
  if (e) e.preventDefault();

  const upi     = document.getElementById('upiId')?.value?.trim();
  const amount  = document.getElementById('amount')?.value;
  const purpose = document.getElementById('txnPurpose')?.value;
  const recipientName = document.getElementById('recipientName')?.value?.trim();

  if (!upi || !amount || !purpose) {
    showToast('Please fill in all required fields!', 'warning');
    return;
  }

  // ★ Store for later use by cancel / proceed
  _pendingTxn = { upi, amount: Number(amount), name: recipientName || upi, purpose };

  const analysisBtn = document.querySelector('form button.btn-primary');
  const originalText = analysisBtn ? analysisBtn.innerHTML : 'Analyze & Proceed';
  if (analysisBtn) {
    analysisBtn.disabled = true;
    analysisBtn.innerHTML = `<span class="loader-sm"></span> Syncing with AI Model...`;
  }

  try {
    const res = await fetch('http://localhost:5001/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ upi, amount, purpose })
    });
    if (!res.ok) throw new Error('Analysis server error');
    const analysis = await res.json();
    currentAnalysis = analysis;

    if (analysis.riskScore >= 35) {
      showFraudWarning(analysis, { upi, amount, purpose, recipientName });
    } else {
      proceedSafely({ upi, amount, recipientName }, false);
    }
  } catch (err) {
    console.error('Backend Analysis Failed:', err);
    showToast('Fast Analysis Backend is currently offline.', 'danger');
  } finally {
    if (analysisBtn) {
      analysisBtn.disabled = false;
      analysisBtn.innerHTML = originalText;
    }
  }
}

// ---- Show Fraud Warning Modal ----
function showFraudWarning(analysis, data) {
  const header = document.getElementById('fraudModalHeader');
  const icon = document.getElementById('modalIcon');
  const title = document.getElementById('modalTitle');
  const subtitle = document.getElementById('modalSubtitle');
  const breakdown = document.getElementById('riskBreakdown');
  const education = document.getElementById('modalEducation');

  if (icon) {
    icon.innerHTML = analysis.riskScore >= 70 ? Icons.render('shieldAlert', 48) : Icons.render('alertTriangle', 48);
    icon.style.color = analysis.color || 'var(--crimson)';
  }
  if (title) {
    title.textContent = analysis.label || 'Risk Detected';
    title.style.color = analysis.color || 'var(--crimson)';
  }
  if (subtitle) subtitle.textContent = `Backend AI Model Score: ${analysis.riskScore}/100`;

  if (breakdown) {
    breakdown.innerHTML = (analysis.risks || []).map(r => `
      <div class="risk-item ${r.level}">
        <span style="flex-shrink:0">${r.level === 'danger' ? Icons.render('shieldAlert', 15) : r.level === 'warn' ? Icons.render('alertTriangle', 15) : Icons.render('checkCircle', 15)}</span>
        <span>${r.text}</span>
      </div>
    `).join('');
  }

  const eduTexts = {
    prize: '<strong>⚠️ Prize Scam Alert:</strong> Scammers call/message claiming you won a prize. They ask you to "pay a small fee" first. This is always a lie. No real prize needs payment upfront.',
    investment: '<strong>📈 Investment Fraud:</strong> Fake trading apps promise high returns. They show fake profits to lure more deposits. Only use SEBI-registered platforms.',
    job: '<strong>💼 Job Scam:</strong> Real employers never charge for jobs. "Registration fees", "training fees", or "security deposits" — all fake.',
    default: '<strong>🛡️ Stay Safe:</strong> Verify the recipient personally before sending money. Call them directly on a known number — don\'t rely on the number the "bank" or "official" gave you.'
  };

  const purpose = document.getElementById('txnPurpose')?.value;
  if (education) education.innerHTML = eduTexts[purpose] || eduTexts.default;

  openModal('fraudModal');
}

// ---- Cancel Transaction (Block) ----
async function cancelTransaction() {
  // Use _pendingTxn which was stored at analyze-time
  const { upi, amount, name, purpose } = _pendingTxn;
  const riskScore = currentAnalysis ? currentAnalysis.riskScore : 50;

  const session = (typeof getSession === 'function') ? getSession() : JSON.parse(localStorage.getItem('fraudshield_session'));
  if (session) {
    try {
      // 1. Save the blocked transaction
      await fetch('http://localhost:5001/api/transactions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: session.id,
          name, upi,
          amount: Number(amount),
          purpose, risk_score: riskScore,
          status: 'blocked'
        })
      });
      // 2. Create threat alert
      await fetch('http://localhost:5001/api/alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: session.id,
          type: riskScore >= 70 ? 'critical' : 'warning',
          title: 'Threat Blocked — Payment Cancelled',
          message: `You blocked a risky payment of ₹${amount} to ${upi}. Risk score: ${riskScore}%.`
        })
      });
    } catch (err) { console.error('cancelTransaction backend error:', err); }
  }

  closeModal('fraudModal');
  showToast('✅ Transaction blocked — threat recorded!', 'success');
  resetForm();
}

// ---- Proceed Anyway ----
function proceedAnyway() {
  closeModal('fraudModal');
  const upi = document.getElementById('upiId')?.value?.trim();
  const amount = document.getElementById('amount')?.value;
  const name = document.getElementById('recipientName')?.value?.trim();
  proceedSafely({ upi, amount, recipientName: name }, true);
}

// ---- Build UPI Deep Link ----
function buildUpiLink({ upi, amount, recipientName, purpose }) {
  const name = (recipientName || 'Recipient').replace(/&/g, 'and').replace(/[#?=%]/g, '');
  const amt = Number(amount);
  const amtStr = amt % 1 === 0 ? amt.toString() : amt.toFixed(2);
  const note = 'Payment via FraudShield';
  return `upi://pay?pa=${upi}&pn=${encodeURIComponent(name)}&am=${amtStr}&cu=INR&tn=${encodeURIComponent(note)}`;
}

// ---- Open UPI App (MOCK) ----
function openUpiApp(upiLink) {
  const upi = document.getElementById('upiId')?.value?.trim();
  const amount = document.getElementById('amount')?.value || 0;
  const name = document.getElementById('recipientName')?.value?.trim() || upi;

  // Update Mock UI
  document.getElementById('mockName').textContent = name;
  document.getElementById('mockId').textContent = upi;
  document.getElementById('mockAmount').textContent = Number(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 });
  document.getElementById('mockPayBtnVal').textContent = Number(amount).toLocaleString('en-IN');
  document.getElementById('mockAvatar').textContent = name.substring(0,1).toUpperCase();

  closeModal('successModal');
  openModal('upiCheckoutModal');
}

async function simulatePayment(btn) {
  const loader  = document.getElementById('paymentLoader');
  const success = document.getElementById('paymentSuccessAnim');
  
  if (loader)  loader.style.display  = 'block';
  if (success) success.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = `<span class="loader-sm"></span> Processing...`;
  openModal('paymentOverlay');
  
  setTimeout(() => {
    if (loader)  loader.style.display  = 'none';
    if (success) success.style.display = 'block';
    const name = _pendingTxn.name || document.getElementById('recipientName')?.value || 'Recipient';
    const finalMsg = document.getElementById('finalSuccessMsg');
    if (finalMsg) finalMsg.textContent = `Sent safely to ${name}`;
    // No extra alert creation here — the transaction save in proceedSafely already handles it
  }, 2000);
}

// ---- Proceed Safely ----
async function proceedSafely({ upi, amount, recipientName }, withWarning = false) {
  const name = recipientName || upi;
  const purpose = document.getElementById('txnPurpose')?.value || '';
  const score = currentAnalysis ? currentAnalysis.riskScore : 0;

  const upiLink = buildUpiLink({ upi, amount, recipientName: name, purpose });
  window._lastUpiLink = upiLink;

  const successDetails = document.getElementById('successDetails');
  const successStatus = document.querySelector('#successModal p');
  
  if (successStatus) {
    if (withWarning) {
      successStatus.innerHTML = `⚠️ Risk detected — Proceeding per user request`;
      successStatus.style.color = 'var(--amber-lt)';
    } else {
      successStatus.innerHTML = `✓ FraudShield analysis complete — Safe to pay`;
      successStatus.style.color = 'var(--emerald-lt)';
    }
  }

  if (successDetails) {
    successDetails.innerHTML = `
      <div style="text-align:left;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:10px;padding:1rem;margin-bottom:0.5rem">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px">
          <span style="font-size:0.75rem;color:var(--t3)">To</span>
          <span style="font-size:0.85rem;font-weight:700;color:var(--t1)">${name}</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="font-size:0.75rem;color:var(--t3)">Amount</span>
          <span style="font-size:1rem;font-weight:800;color:${withWarning ? 'var(--amber-lt)' : 'var(--emerald-lt)'}">${formatCurrency(amount)}</span>
        </div>
      </div>
    `;
  }

  // Record to backend
  const API_BASE = 'http://localhost:5001/api';
  const session = getSession();
  
  if (session) {
    try {
      const riskScore = currentAnalysis ? currentAnalysis.riskScore : 0;
      const res = await fetch(`${API_BASE}/transactions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: session.id,
          name: name,
          upi: upi,
          amount: Number(amount),
          purpose: purpose,
          risk_score: riskScore,
          status: withWarning ? 'warn' : 'safe'
        })
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Transaction recorded — protection active`, 'success');
      } else {
        console.error('Backend rejected txn:', data.error);
        showToast('System delay: Transaction not linked to history.', 'warning');
      }
    } catch (err) { 
      console.error('Backend sync failed:', err); 
      showToast('Offline mode: Transaction not saved to history.', 'danger');
    }
  }

  openModal('successModal');
}

// ---- Reset Form ----
function resetForm() {
  document.getElementById('transferForm')?.reset();
  document.getElementById('upiStatus').textContent = '';
  document.getElementById('amountWarning').textContent = '';
  document.getElementById('purposeWarning').textContent = '';
  document.getElementById('riskFill').style.width = '0%';
  document.getElementById('riskLabel').textContent = 'Not Analyzed Yet';
  document.getElementById('riskFactors').innerHTML = '';
}

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  const upiInput = document.getElementById('upiId');
  if (upiInput) upiInput.focus();
});

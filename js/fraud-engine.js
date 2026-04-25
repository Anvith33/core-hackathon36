/* ====================================================
   FraudShield – fraud-engine.js
   Core AI fraud detection logic (rule-based simulation)
   ==================================================== */

const FraudEngine = {
  // Weights derived from FraudShieldModels.transactionModel
  get weights() {
    return (window.FraudShieldModels && window.FraudShieldModels.transactionModel.weights) || {
      isUnknownRecipient: 12, isSuspiciousUPI: 35, isHighRiskPurpose: 25, isLargeAmount: 18, 
      isUnusualHour: 15, isHighVelocity: 30, isSmurfingPattern: 20, isNewMerchant: 10
    };
  },

  // ---- Known suspicious UPI patterns ----
  suspiciousUpiPatterns: [
    /lottery/i, /prize/i, /winner/i, /lucky/i, /reward/i,
    /refund/i, /helpdesk/i, /support/i, /customer.?care/i,
    /rbi/i, /income.?tax/i, /police/i, /gov/i, /bank.?official/i,
    /free/i, /gift/i, /lucky/i, /jackpot/i
  ],

  // ---- Known safe patterns ----
  safeMerchantPatterns: [
    /amazon/i, /flipkart/i, /swiggy/i, /zomato/i, /paytm/i,
    /googlepay/i, /phonepe/i, /bigbasket/i, /myntra/i, /netflix/i
  ],

  // ---- High risk purposes ----
  highRiskPurposes: ['prize', 'investment', 'job'],
  mediumRiskPurposes: ['loan'],

  // ---- Advanced Pattern Detection ----
  analyzePatterns(data) {
    const history = Store.get('transactions', []);
    const now = Date.now();
    const patternRisks = [];
    let patternScore = 0;

    // 1. Velocity Check (Transactions in last 10 minutes)
    const recentTxns = history.filter(t => (now - new Date(t.time).getTime()) < 600000);
    if (recentTxns.length >= 3) {
      patternScore += 30;
      patternRisks.push({
        level: 'danger',
        icon: '⏳',
        text: `High Velocity: ${recentTxns.length} transactions attempted in 10 mins. Scammers often rush multiple transfers.`
      });
    }

    // 2. Smurfing / Testing Check (Same recipient, multiple small amounts)
    const sameRecipient = history.filter(t => t.upi.toLowerCase() === data.upiId.toLowerCase());
    if (sameRecipient.length >= 2) {
      const recentSameRecipient = sameRecipient.filter(t => (now - new Date(t.time).getTime()) < 3600000);
      if (recentSameRecipient.length >= 2) {
        patternScore += 20;
        patternRisks.push({
          level: 'warn',
          icon: '🔄',
          text: 'Repeat Recipient: Multiple transfers to the same person in 1 hour. Verify this isn\'t a testing scam.'
        });
      }
    }

    // 3. Suspicious Hour (Late night / Early morning)
    const hour = new Date().getHours();
    if (hour >= 2 && hour <= 5) {
      patternScore += 15;
      patternRisks.push({
        level: 'warn',
        icon: '🌙',
        text: 'Unusual Time: Transaction attempted late at night. Scammers use this time when you might be less alert.'
      });
    }

    // 4. Ghost Contact Cluster (New UPI ID after multiple other new IDs)
    const isNew = !this.isKnownPayee(data.upiId);
    if (isNew) {
      const last5 = history.slice(0, 5);
      const newInLast5 = last5.filter(t => !this.safeMerchantPatterns.some(p => p.test(t.upi))).length;
      if (newInLast5 >= 3) {
        patternScore += 25;
        patternRisks.push({
          level: 'danger',
          icon: '👤',
          text: 'Contact Cluster: Multiple new contacts added recently. This pattern is common in "mule account" distribution.'
        });
      }
    }

    return { patternScore, patternRisks };
  },

  // ---- Analyze transaction (Updated with Patterns) ----
  analyzeTransaction(data) {
    const { upiId, amount, purpose, recipientName } = data;
    const risks = [];
    let riskScore = 0;

    const model = this.weights;

    // 1. UPI ID pattern check
    if (this.suspiciousUpiPatterns.some(p => p.test(upiId))) {
      riskScore += model.isSuspiciousUPI;
      risks.push({ level: 'danger', icon: '🚨', text: 'UPI ID matches known fraudulent patterns used in phishing.' });
    } else if (this.safeMerchantPatterns.some(p => p.test(upiId))) {
      riskScore -= 10;
      risks.push({ level: 'ok', icon: '✅', text: 'UPI ID matches a known trusted merchant.' });
    }

    // 2. Amount risk
    const amt = Number(amount);
    if (amt > 50010) {
      riskScore += model.isLargeAmount;
      risks.push({ level: 'danger', icon: '⚠️', text: `Predictive model flagged large amount (${formatCurrency(amt)}) as outlier.` });
    }

    // 3. Purpose check
    if (this.highRiskPurposes.includes(purpose)) {
      riskScore += model.isHighRiskPurpose;
      risks.push({ level: 'danger', icon: '🚨', text: 'Transaction purpose flagged by NLP module as high-probability scam.' });
    }

    // 4. Pattern Detection
    const { patternScore, patternRisks } = this.analyzePatterns(data);
    riskScore += patternScore;
    risks.push(...patternRisks);

    // Clamp score
    riskScore = Math.max(0, Math.min(100, riskScore));

    const level = riskScore >= 70 ? 'critical'
                : riskScore >= 45 ? 'high'
                : riskScore >= 25 ? 'medium'
                : 'low';

    const label = { critical: 'CRITICAL RISK', high: 'High Risk', medium: 'Medium Risk', low: 'Low Risk' };
    const color = { critical: '#f43f5e', high: '#f97316', medium: '#f59e0b', low: '#10b981' };
    const cssClass = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

    return { riskScore, level, label: label[level], color: color[level], cssClass: cssClass[level], risks };
  },

  // ---- Live UPI check ----
  liveUpiCheck(upiId) {
    if (!upiId || upiId.length < 3) return null;
    const suspicious = this.suspiciousUpiPatterns.some(p => p.test(upiId));
    const safe = this.safeMerchantPatterns.some(p => p.test(upiId));
    const validFormat = /^[\w.\-]+@[\w]+$/.test(upiId);

    if (suspicious) return { type: 'danger', msg: '🚨 Suspicious UPI ID — this pattern is used in known scams!' };
    if (safe) return { type: 'safe', msg: '✅ Recognized trusted merchant' };
    if (!validFormat && upiId.length > 5) return { type: 'warn', msg: '⚠️ UPI ID format looks unusual — typical format: name@upi' };
    return { type: 'ok', msg: '✓ Format looks valid' };
  },

  // ---- URL phishing check ----
  analyzeUrl(url) {
    if (!url) return null;
    const result = { score: 0, flags: [], safe: true, verdict: 'Safe', icon: '✅', cssClass: 'safe' };

    const lUrl = url.toLowerCase();

    // Check for HTTPS
    if (!lUrl.startsWith('https://')) {
      result.score += 30;
      result.flags.push({ label: 'No HTTPS', value: 'bad', desc: 'Site does not use secure HTTPS connection' });
    } else {
      result.flags.push({ label: 'HTTPS', value: 'ok', desc: 'Uses secure HTTPS connection' });
    }

    // Check for suspicious bank keywords in non-bank domain
    const bankNames = ['sbi', 'hdfc', 'icici', 'axis', 'paytm', 'upi', 'npci', 'rbi', 'kotak', 'pnb', 'bob'];
    const trustedDomains = ['sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'paytm.com', 'npci.org.in'];
    const isTrusted = trustedDomains.some(d => lUrl.includes(d));
    const hasBankName = bankNames.some(b => lUrl.includes(b));

    if (hasBankName && !isTrusted) {
      result.score += 50;
      result.flags.push({ label: 'Fake Bank Site', value: 'bad', desc: 'URL contains bank name but is NOT on the official domain' });
    } else if (isTrusted) {
      result.score -= 20;
      result.flags.push({ label: 'Official Domain', value: 'ok', desc: 'URL matches an official banking domain' });
    } else {
      result.flags.push({ label: 'Domain', value: 'neutral', desc: 'Not a financial institution domain' });
    }

    // Suspicious TLDs
    const suspTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.pw'];
    if (suspTlds.some(t => lUrl.endsWith(t))) {
      result.score += 25;
      result.flags.push({ label: 'Suspicious TLD', value: 'bad', desc: 'Domain extension frequently used in phishing sites' });
    }

    // URL shorteners
    const shorteners = ['bit.ly', 'tiny.cc', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
    if (shorteners.some(s => lUrl.includes(s))) {
      result.score += 20;
      result.flags.push({ label: 'Shortened URL', value: 'bad', desc: 'Shortened links hide the real destination — always expand first' });
    }

    // Suspicious keywords in URL
    const suspWords = ['login', 'verify', 'update', 'secure', 'account', 'confirm', 'otp', 'kyc', 'suspend', 'blocked', 'urgent'];
    const foundWords = suspWords.filter(w => lUrl.includes(w));
    if (foundWords.length >= 2) {
      result.score += 20;
      result.flags.push({ label: 'Deceptive Keywords', value: 'bad', desc: `URL contains suspicious words: ${foundWords.join(', ')}` });
    }

    // IP address instead of domain
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      result.score += 35;
      result.flags.push({ label: 'IP Address URL', value: 'bad', desc: 'Real websites use domain names, not raw IP addresses' });
    }

    // Long subdomain (common in phishing)
    try {
      const domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
      const parts = domain.split('.');
      if (parts.length > 4) {
        result.score += 15;
        result.flags.push({ label: 'Suspicious Subdomain', value: 'bad', desc: 'Many subdomain levels often indicate phishing' });
      } else {
        result.flags.push({ label: 'Domain Structure', value: 'ok', desc: 'Normal domain structure' });
      }
    } catch {}

    result.score = Math.max(0, Math.min(100, result.score));
    result.safe = result.score < 35;

    if (result.score >= 65) { result.verdict = 'PHISHING / DANGEROUS'; result.icon = '🚨'; result.cssClass = 'danger'; }
    else if (result.score >= 35) { result.verdict = 'Suspicious — Proceed with Caution'; result.icon = '⚠️'; result.cssClass = 'warning'; }
    else { result.verdict = 'Looks Safe'; result.icon = '✅'; result.cssClass = 'safe'; }

    return result;
  },

  // ---- Simulated known payees ----
  isKnownPayee(upiId) {
    const known = Store.get('known_payees', ['amazon@pay', 'swiggy@sbi', 'zomato@upi']);
    return known.some(p => p.toLowerCase() === upiId.toLowerCase());
  },

  addKnownPayee(upiId) {
    const known = Store.get('known_payees', []);
    if (!this.isKnownPayee(upiId)) {
      known.push(upiId);
      Store.set('known_payees', known);
    }
  }
};

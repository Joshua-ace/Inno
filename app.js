/**
 * DaddyDefender: Multi-layer threat detection engine
 * Communicates with FastAPI backend with automatic client-side fallback.
 */

'use strict';

// ── Configuration ─────────────────────────────────────

const API_BASE = (window.location.origin.includes('5500') || window.location.protocol === 'file:')
  ? 'http://127.0.0.1:8000'
  : '';

// ── DOM References ────────────────────────────────────

const tabButtons    = document.querySelectorAll('.tab');
const urlInput      = document.getElementById('url-input');
const messageInput  = document.getElementById('message-input');
const analyzeBtn    = document.getElementById('analyze-btn');
const clearBtn      = document.getElementById('clear-btn');
const resultsSection = document.getElementById('results');
const sampleChips   = document.querySelectorAll('.sample-chip');
const scanAgainBtn  = document.getElementById('scan-again-btn');
const refreshHistoryBtn = document.getElementById('refresh-history-btn');

let activeTab = 'url';

// ── SVG icons used in dynamic indicator cards ─────────

const ICONS = {
  critical: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  warning:  `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><path d="M12 9v4m0 4h.01"/></svg>`,
  info:     `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>`,
};

// ── Tab switching ─────────────────────────────────────

tabButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;
    if (target === activeTab) return;
    activeTab = target;

    tabButtons.forEach(b => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));

    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    document.getElementById(`panel-${target}`).classList.remove('hidden');

    resultsSection.classList.add('hidden');
    clearInlineError();
  });
});

// ── Keyboard shortcut: Enter key triggers scan ─────────

if (urlInput) {
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      analyzeBtn.click();
    }
  });
}

// ── Sample threat examples ────────────────────────────

sampleChips.forEach(chip => {
  chip.addEventListener('click', () => {
    const type  = chip.dataset.type;
    const value = chip.dataset.value;

    if (type !== activeTab) {
      const targetTab = document.querySelector(`.tab[data-tab="${type}"]`);
      if (targetTab) targetTab.click();
    }

    if (type === 'url') {
      urlInput.value = value;
    } else {
      messageInput.value = value;
    }

    document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

// ── Clear ─────────────────────────────────────────────

clearBtn.addEventListener('click', () => {
  urlInput.value      = '';
  messageInput.value  = '';
  resultsSection.classList.add('hidden');
  clearInlineError();
});

// ── Scan again ────────────────────────────────────────

scanAgainBtn.addEventListener('click', () => {
  resultsSection.classList.add('hidden');
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  (activeTab === 'url' ? urlInput : messageInput).focus();
});

// ── Refresh History Button ────────────────────────────

if (refreshHistoryBtn) {
  refreshHistoryBtn.addEventListener('click', () => {
    loadScanHistory();
  });
}

// ── Analyze Action ────────────────────────────────────

analyzeBtn.addEventListener('click', async () => {
  const rawInput = activeTab === 'url'
    ? urlInput.value.trim()
    : messageInput.value.trim();

  if (!rawInput) {
    shake(activeTab === 'url' ? urlInput : messageInput);
    return;
  }

  clearInlineError();

  // Loading state
  const originalHTML = analyzeBtn.innerHTML;
  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML = `
    <svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
    </svg>
    Analyzing...
  `;

  let result;
  let usedFallback = false;

  try {
    result = await callAnalyzeAPI(activeTab, rawInput);
  } catch (err) {
    console.info('Backend request failed or offline; using local heuristic engine:', err.message);
    usedFallback = true;
    result = activeTab === 'url' ? analyzeURL(rawInput) : analyzeMessage(rawInput);
  }

  analyzeBtn.disabled = false;
  analyzeBtn.innerHTML = originalHTML;

  if (result.error) {
    showInlineError(result.error);
    return;
  }

  renderResults(result, rawInput, usedFallback);

  if (!usedFallback) {
    loadScanHistory();
  }
});

// ── Backend API Call ──────────────────────────────────

async function callAnalyzeAPI(type, input) {
  const endpoint = type === 'url' ? `${API_BASE}/api/analyze/url` : `${API_BASE}/api/analyze/message`;
  const body = type === 'url' ? { url: input } : { message: input };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12000);

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: controller.signal,
  });
  clearTimeout(timeoutId);

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || errData.error || `Server returned ${res.status}`);
  }

  return await res.json();
}

// ── Backend Health Check on Startup ───────────────────

async function checkBackendHealth() {
  const badge = document.getElementById('backend-status');
  const text = document.getElementById('backend-status-text');
  if (!badge || !text) return;

  try {
    const res = await fetch(`${API_BASE}/api/health`, { method: 'GET' });
    if (res.ok) {
      const data = await res.json();
      badge.className = 'backend-badge backend-badge--online';
      text.textContent = 'API Connected';
      badge.title = `DaddyDefender API v${data.version}`;
      loadScanHistory();
      return;
    }
  } catch (err) {
    // Offline or restricted file access
  }

  badge.className = 'backend-badge backend-badge--offline';
  text.textContent = 'Local Engine';
  badge.title = 'Running in browser sandbox mode. Start backend (python main.py) for persistent SQLite history.';
  renderEmptyHistory('Start backend with "python main.py" to enable persistent scan history.');
}

// ── Scan History ──────────────────────────────────────

async function loadScanHistory() {
  const container = document.getElementById('history-container');
  if (!container) return;

  try {
    const res = await fetch(`${API_BASE}/api/scans?limit=15`);
    if (!res.ok) throw new Error('Database fetch failed');
    const data = await res.json();
    renderHistoryTable(data.scans, data.total);
  } catch (err) {
    renderEmptyHistory('Scan records database is offline.');
  }
}

function renderHistoryTable(scans, total) {
  const container = document.getElementById('history-container');
  if (!container) return;

  if (!scans || scans.length === 0) {
    renderEmptyHistory('No scans recorded yet. Run a scan above to save it to the database.');
    return;
  }

  const rows = scans.map(s => {
    const level = (s.risk_level || 'low').toLowerCase();
    const config = RISK_CONFIG[level] || RISK_CONFIG.low;
    const timeFormatted = new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' });

    return `
      <tr>
        <td>${escapeHTML(timeFormatted)}</td>
        <td><span class="history-type-badge">${escapeHTML(s.scan_type)}</span></td>
        <td class="history-preview-cell" title="${escapeHTML(s.input_preview)}">${escapeHTML(s.input_preview)}</td>
        <td>
          <span class="risk-badge risk-badge--${level}" style="font-size: 11px; padding: 2px 7px;">
            ${config.badge} (${s.risk_score})
          </span>
        </td>
        <td>
          <div class="history-actions">
            <button class="btn-history-view" onclick="viewHistoricalScan('${escapeHTML(s.scan_id)}')">View</button>
            <button class="btn-history-del" onclick="deleteScanRecord('${escapeHTML(s.scan_id)}')">Delete</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  container.innerHTML = `
    <table class="history-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Type</th>
          <th>Target Preview</th>
          <th>Risk Assessment</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

function renderEmptyHistory(message) {
  const container = document.getElementById('history-container');
  if (container) {
    container.innerHTML = `<div class="history-empty">${escapeHTML(message)}</div>`;
  }
}

window.viewHistoricalScan = async function(scanId) {
  try {
    const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
    if (!res.ok) throw new Error('Scan not found');
    const scan = await res.json();

    const normalizedResult = {
      risk_score: scan.risk_score,
      risk_level: scan.risk_level,
      classification: scan.classification,
      indicators: scan.indicators || [],
      recommendations: scan.recommendations || [],
      providers: scan.providers || [],
      ai_explanation: scan.ai_explanation || null,
      analysis_metadata: scan.analysis_metadata || {},
      scan_type: scan.scan_type,
    };

    renderResults(normalizedResult, scan.input_preview, false);
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    showInlineError('Could not load scan details from database.');
  }
};

window.deleteScanRecord = async function(scanId) {
  try {
    const res = await fetch(`${API_BASE}/api/scans/${scanId}`, { method: 'DELETE' });
    if (res.ok) {
      loadScanHistory();
    }
  } catch (err) {
    console.error('Failed to delete scan:', err);
  }
};

// ── Local Heuristic URL Analysis (Offline Fallback) ───

function analyzeURL(raw) {
  let url = raw.trim();
  let parsed;

  try {
    if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
    parsed = new URL(url);
  } catch {
    return { error: 'Could not parse this URL. Check the format and try again.' };
  }

  let score = 0;
  const indicators = [];

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol;
  const pathname = parsed.pathname;
  const fullURL  = parsed.href.toLowerCase();
  const port     = parsed.port;

  // No HTTPS
  if (protocol === 'http:') {
    score += 15;
    indicators.push({
      severity: 'warning',
      name: 'No Encryption (HTTP)',
      detail: 'The connection is unencrypted. Any credentials or data submitted on this page can be intercepted by anyone on the same network.',
      points: 15,
      source: 'local',
    });
  }

  // IP address as hostname
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    score += 40;
    indicators.push({
      severity: 'critical',
      name: 'Raw IP Address Used Instead of Domain',
      detail: 'Legitimate websites use registered domain names. Hosting a phishing page on a raw IP address is a well-documented attack technique to avoid domain-based reputation checks.',
      points: 40,
      source: 'local',
    });
  }

  // URL shortener
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'is.gd', 'buff.ly', 'tiny.cc', 'ht.ly', 'rb.gy', 'shorturl.at', 'cutt.ly', 'adf.ly'];
  if (shorteners.some(s => hostname === s || hostname.endsWith('.' + s))) {
    score += 20;
    indicators.push({
      severity: 'warning',
      name: 'URL Shortener Detected',
      detail: 'URL shorteners mask the actual destination. They are commonly used in phishing campaigns to bypass email and browser filters.',
      points: 20,
      source: 'local',
    });
  }

  // Suspicious TLD
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.loan', '.win', '.download', '.racing', '.click', '.review', '.party', '.science', '.men', '.gdn', '.date', '.faith', '.stream', '.online'];
  const tld = '.' + hostname.split('.').pop();
  if (suspiciousTLDs.includes(tld)) {
    score += 20;
    indicators.push({
      severity: 'warning',
      name: `Suspicious Domain Extension: ${tld}`,
      detail: `"${tld}" is frequently used for malicious sites because it is free or very cheap to register. Established businesses almost never use it.`,
      points: 20,
      source: 'local',
    });
  }

  // @ symbol in URL
  if (raw.includes('@')) {
    score += 35;
    indicators.push({
      severity: 'critical',
      name: 'Credential Injection via @ Symbol',
      detail: 'Browsers ignore everything before @ in a URL, treating it as credentials. Attackers use this to make a URL appear to belong to a trusted site while routing to an attacker server.',
      points: 35,
      source: 'local',
    });
  }

  // Phishing keywords
  const phishingKeywords = ['login', 'signin', 'sign-in', 'verify', 'verification', 'update', 'confirm', 'secure', 'security', 'paypal', 'apple', 'google', 'microsoft', 'amazon', 'ebay', 'netflix', 'support', 'password', 'credential', 'wallet', 'recover', 'auth', 'webscr', 'banking', 'account-update'];
  const foundKeywords = phishingKeywords.filter(kw => fullURL.includes(kw));

  if (foundKeywords.length >= 3) {
    score += Math.min(foundKeywords.length * 7, 30);
    indicators.push({
      severity: 'critical',
      name: `High-Density Phishing Keywords (${foundKeywords.length} found)`,
      detail: `URL contains multiple terms used to impersonate legitimate services: ${foundKeywords.slice(0, 5).join(', ')}.`,
      points: 25,
      source: 'local',
    });
  } else if (foundKeywords.length >= 1) {
    score += foundKeywords.length * 7;
    indicators.push({
      severity: 'warning',
      name: 'Phishing Keywords in URL',
      detail: `Contains: "${foundKeywords.slice(0, 3).join('", "')}". These terms appear frequently in URLs designed to impersonate account login pages.`,
      points: foundKeywords.length * 7,
      source: 'local',
    });
  }

  // Too many subdomains
  const parts = hostname.split('.');
  if (parts.length > 4) {
    score += 20;
    indicators.push({
      severity: 'warning',
      name: `Deep Subdomain Structure (${parts.length} levels)`,
      detail: 'Attackers add legitimate-looking subdomains to make a fake domain appear trustworthy. Most real sites use 2-3 hostname parts.',
      points: 20,
      source: 'local',
    });
  }

  // URL length
  if (raw.length > 120) {
    score += 10;
    indicators.push({
      severity: 'info',
      name: `Long URL (${raw.length} characters)`,
      detail: 'Long URLs can obscure the actual domain and add noise to make inspection harder.',
      points: 10,
      source: 'local',
    });
  }

  // Hyphen-heavy domain
  const labelBeforeTLD = parts.slice(0, -1).join('.');
  const hyphenCount = (labelBeforeTLD.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 15;
    indicators.push({
      severity: 'warning',
      name: `${hyphenCount} Hyphens in Domain`,
      detail: 'Multiple hyphens are a lookalike-domain technique: hyphens are used to mimic official brand domain names.',
      points: 15,
      source: 'local',
    });
  }

  // Non-standard port
  if (port && !['80', '443', '8080', '8443'].includes(port)) {
    score += 15;
    indicators.push({
      severity: 'warning',
      name: `Non-Standard Port: ${port}`,
      detail: 'Public websites serve traffic on standard ports 80 and 443. An unusual port suggests a non-standard service.',
      points: 15,
      source: 'local',
    });
  }

  const riskScore = Math.min(score, 100);
  const riskLevel = getRiskLevel(riskScore);

  return {
    risk_level: riskLevel,
    risk_score: riskScore,
    classification: `${riskLevel.toUpperCase()} Risk Target`,
    indicators,
    recommendations: buildRecommendations(riskLevel, 'url', indicators),
    providers: [
      { name: 'VirusTotal', status: 'not_configured', detail: 'Local sandbox mode; start backend with VIRUSTOTAL_API_KEY.' },
      { name: 'URLhaus', status: 'not_configured', detail: 'Local sandbox mode; start backend to query live abuse.ch blocklists.' },
      { name: 'Gemini AI', status: 'not_configured', detail: 'Local sandbox mode; start backend with GEMINI_API_KEY for AI explanation.' },
    ],
    analysis_metadata: {
      hostname,
      protocol,
      port: port || 'Standard (80/443)',
      tld: tld || 'None',
      subdomains: parts.length > 2 ? parts.slice(0, -2).join('.') : 'None',
    },
    limitations: 'Static pattern heuristics generated locally in browser. Zero-day threats or legitimate brand domains require active reputation queries.',
    scan_type: 'url',
  };
}

// ── Local Heuristic Message Analysis (Offline Fallback) ──

function analyzeMessage(message) {
  let score = 0;
  const indicators = [];
  const msgLower = message.toLowerCase();

  // Urgency tactics
  const urgencyTerms = ['urgent', 'immediately', 'right now', 'act now', 'limited time', 'expires', 'expiring', 'last chance', 'final notice', 'action required', 'respond immediately', 'within 24 hours', 'within 48 hours', 'today only', 'must verify', 'must respond'];
  const foundUrgency = urgencyTerms.filter(t => msgLower.includes(t));
  if (foundUrgency.length > 0) {
    score += Math.min(foundUrgency.length * 10, 25);
    indicators.push({
      severity: 'warning',
      name: 'Urgency Pressure Tactics',
      detail: `Detected urgency trigger: "${foundUrgency[0]}". This technique is designed to prevent pausing to verify sender identity.`,
      points: Math.min(foundUrgency.length * 10, 25),
      source: 'local',
    });
  }

  // Threat language
  const threatTerms = ['suspended', 'terminated', 'closed', 'blocked', 'restricted', 'legal action', 'arrested', 'police', 'irs', 'fine', 'penalty', 'lawsuit', 'prosecute', 'criminal', 'warrant', 'deactivated', 'fraud detected', 'permanently closed'];
  const foundThreats = threatTerms.filter(t => msgLower.includes(t));
  if (foundThreats.length > 0) {
    score += Math.min(foundThreats.length * 12, 30);
    indicators.push({
      severity: 'critical',
      name: 'Threatening or Punitive Language',
      detail: `Found consequence threats: "${foundThreats[0]}". Threatening account closures or legal action is a scam technique.`,
      points: Math.min(foundThreats.length * 12, 30),
      source: 'local',
    });
  }

  // Sensitive data requests
  const sensitiveTerms = ['password', 'pin', 'social security', 'ssn', 'credit card', 'debit card', 'bank account', 'routing number', 'cvv', 'date of birth', 'one-time password', 'otp', 'security code'];
  const foundSensitive = sensitiveTerms.filter(t => msgLower.includes(t));
  if (foundSensitive.length > 0) {
    score += Math.min(foundSensitive.length * 15, 40);
    indicators.push({
      severity: 'critical',
      name: 'Request for Sensitive Credentials',
      detail: `Explicitly requests: "${foundSensitive.join('", "')}". Legitimate institutions never request this via unsolicited messages.`,
      points: Math.min(foundSensitive.length * 15, 40),
      source: 'local',
    });
  }

  // Prize claims
  const prizeTerms = ['you have won', 'you\'ve won', 'you are the winner', 'lottery', 'lucky winner', 'inheritance', 'you have been selected', 'congratulations', 'unclaimed funds', 'claim your prize', 'claim your reward'];
  const foundPrize = prizeTerms.filter(t => msgLower.includes(t));
  if (foundPrize.length > 0) {
    score += 25;
    indicators.push({
      severity: 'warning',
      name: 'Prize or Lottery Claim',
      detail: `Claims: "${foundPrize[0]}". Unsolicited prize claims are among the most common advance-fee fraud patterns.`,
      points: 25,
      source: 'local',
    });
  }

  // Payment requests
  const paymentTerms = ['gift card', 'bitcoin', 'crypto', 'wire transfer', 'western union', 'moneygram', 'cash app', 'venmo', 'zelle', 'prepaid card', 'itunes card', 'google play card'];
  const foundPayment = paymentTerms.filter(t => msgLower.includes(t));
  if (foundPayment.length > 0) {
    score += 25;
    indicators.push({
      severity: 'critical',
      name: 'Untraceable Payment Method Requested',
      detail: `Requests payment via: "${foundPayment.join('", "')}". These payment methods cannot be reversed once completed.`,
      points: 25,
      source: 'local',
    });
  }

  // Embedded links
  const urlMatches = message.match(/https?:\/\/[^\s]+|www\.[^\s]+/gi) || [];
  if (urlMatches.length > 0) {
    score += 10;
    indicators.push({
      severity: 'warning',
      name: `Contains ${urlMatches.length} Embedded Link(s)`,
      detail: 'Avoid clicking links in unexpected messages. Navigate to verified websites directly through browser bookmarks.',
      points: 10,
      source: 'local',
    });
  }

  const riskScore = Math.min(score, 100);
  const riskLevel = getRiskLevel(riskScore);

  return {
    risk_level: riskLevel,
    risk_score: riskScore,
    classification: `${riskLevel.toUpperCase()} Risk Message`,
    indicators,
    recommendations: buildRecommendations(riskLevel, 'message', indicators),
    providers: [
      { name: 'VirusTotal', status: 'not_configured', detail: 'Local sandbox mode; start backend with VIRUSTOTAL_API_KEY.' },
      { name: 'URLhaus', status: 'not_configured', detail: 'Local sandbox mode; start backend to query live abuse.ch blocklists.' },
      { name: 'Gemini AI', status: 'not_configured', detail: 'Local sandbox mode; start backend with GEMINI_API_KEY for AI explanation.' },
    ],
    analysis_metadata: {
      message_length: message.length,
      extracted_urls: urlMatches.length,
    },
    limitations: 'Static content heuristic assessment. Content without obvious keywords can still represent targeted social engineering.',
    scan_type: 'message',
  };
}

// ── Risk Level Mapping ────────────────────────────────

function getRiskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'moderate';
  return 'low';
}

const RISK_CONFIG = {
  critical: {
    color: '#ef4444',
    badge: 'Critical Risk',
    description: 'Multiple strong phishing or fraud indicators detected. Do not interact with this content under any circumstances.',
  },
  high: {
    color: '#f97316',
    badge: 'High Risk',
    description: 'Significant red flags found. Treat as potentially malicious until verified through a trusted official channel.',
  },
  moderate: {
    color: '#f59e0b',
    badge: 'Moderate Risk',
    description: 'Several suspicious patterns detected. Exercise caution and do not submit credentials or personal information.',
  },
  medium: {
    color: '#f59e0b',
    badge: 'Moderate Risk',
    description: 'Several suspicious patterns detected. Exercise caution and do not submit credentials or personal information.',
  },
  low: {
    color: '#60a5fa',
    badge: 'Low Risk',
    description: 'Minor indicators found. The content is likely safe but review the details below before interacting.',
  },
  safe: {
    color: '#22c55e',
    badge: 'No Threats Detected',
    description: 'No suspicious patterns found in this content. Standard caution still applies when sharing personal information online.',
  },
};

// ── Recommendations ───────────────────────────────────

function buildRecommendations(level, type, indicators) {
  const recs = [];
  const lvl = (level || 'low').toLowerCase();

  const hasSensitiveReq = indicators.some(i => i.name && i.name.includes('Sensitive'));
  const hasPayment      = indicators.some(i => i.name && i.name.includes('Payment'));

  if (lvl === 'low' || lvl === 'safe') {
    recs.push('No immediate action required based on this structural analysis.');
    recs.push('Even content that clears pattern checks can be malicious. Verify the sender independently before sharing personal data.');
    recs.push('Keep your browser, operating system, and security software updated.');
    return recs;
  }

  if (lvl === 'moderate' || lvl === 'medium') {
    if (type === 'url') {
      recs.push('Do not enter login credentials or personal information on this page until verifying its legitimacy.');
      recs.push('Check the full domain carefully. Look it up using a site reputation service like VirusTotal.');
    } else {
      recs.push('Do not click any links in this message. Navigate to the official website directly.');
      recs.push('Contact the organization the sender claims to represent through the verified phone number on their official website.');
    }
    recs.push('Report the content as phishing or spam to your email provider or mobile carrier.');
    return recs;
  }

  // HIGH or CRITICAL
  if (type === 'url') {
    recs.push('Do not visit this URL. If opened, close the tab immediately and clear your browser cache.');
    recs.push('If you entered any credentials or information, proceed to account recovery steps immediately.');
  } else {
    recs.push('Do not respond to this message, call numbers listed in it, or click any links.');
    recs.push('Block the sender and report the message as phishing to your carrier or provider.');
  }

  if (hasSensitiveReq) {
    recs.push('If you submitted personal data: contact your bank immediately to freeze affected accounts and place a fraud alert.');
  }

  if (hasPayment) {
    recs.push('If you sent money: contact your financial institution right away to attempt a transaction recall.');
  }

  recs.push('Report this threat to the Anti-Phishing Working Group at reportphishing@apwg.org.');
  return recs;
}

// ── Render Results ────────────────────────────────────

function renderResults(result, rawInput, usedFallback) {
  const riskScore = result.risk_score !== undefined ? result.risk_score : (result.riskScore || 0);
  const rawLevel  = (result.risk_level || result.riskLevel || 'low').toLowerCase();
  const config    = RISK_CONFIG[rawLevel] || RISK_CONFIG.low;
  const scanType  = result.scan_type || result.type || activeTab;

  // Badge & Summary
  const badge = document.getElementById('risk-badge');
  badge.textContent = config.badge;
  badge.className = `risk-badge risk-badge--${rawLevel}`;

  const descEl = document.getElementById('risk-description');
  descEl.textContent = result.classification || config.description;

  const truncated = rawInput.length > 70 ? rawInput.slice(0, 70) + '...' : rawInput;
  const sourceLabel = usedFallback ? 'Local Engine Fallback' : 'Live Threat API';
  document.getElementById('scan-meta').textContent = `Analyzed ${scanType === 'url' ? 'URL' : 'message'} via ${sourceLabel}: ${truncated}`;

  // Gauge
  animateGauge(riskScore, config.color);

  // Metadata / Architecture
  const metaSection = document.getElementById('metadata-section');
  const metaGrid = document.getElementById('metadata-grid');
  if (metaSection && metaGrid) {
    const meta = result.analysis_metadata || {};
    const entries = Object.entries(meta).filter(([k, v]) => v !== null && v !== undefined);
    if (entries.length > 0) {
      metaSection.classList.remove('hidden');
      metaGrid.innerHTML = entries.map(([k, v]) => `
        <div class="meta-item">
          <div class="meta-label">${escapeHTML(k.replace(/_/g, ' '))}</div>
          <div class="meta-value">${escapeHTML(String(v))}</div>
        </div>
      `).join('');
    } else {
      metaSection.classList.add('hidden');
    }
  }

  // Threat Intelligence Providers
  const providersSection = document.getElementById('providers-section');
  const providersGrid = document.getElementById('providers-grid');
  if (providersSection && providersGrid) {
    const providers = result.providers || [];
    if (providers.length > 0) {
      providersSection.classList.remove('hidden');
      providersGrid.innerHTML = providers.map(p => {
        const rawStatus = (p.status || 'not_configured').toLowerCase();
        const statusClass = `status-${rawStatus}`;
        const statusText = rawStatus.replace(/_/g, ' ');
        return `
          <div class="provider-card">
            <div class="provider-card-header">
              <span class="provider-name">${escapeHTML(p.name)}</span>
              <span class="provider-status-tag ${statusClass}">${escapeHTML(statusText)}</span>
            </div>
            <p class="provider-detail">${escapeHTML(p.detail || 'Status confirmed.')}</p>
          </div>
        `;
      }).join('');
    } else {
      providersSection.classList.add('hidden');
    }
  }

  // AI Explanation
  const aiSection = document.getElementById('ai-section');
  const aiText = document.getElementById('ai-explanation-text');
  if (aiSection && aiText) {
    if (result.ai_explanation) {
      aiSection.classList.remove('hidden');
      aiText.textContent = result.ai_explanation;
    } else {
      aiSection.classList.add('hidden');
    }
  }

  // Threat Indicators
  const indicators = result.indicators || [];
  const indicatorsList = document.getElementById('indicators-list');
  const indicatorsTitle = document.getElementById('indicators-title');

  if (indicators.length === 0) {
    indicatorsTitle.textContent = 'Threat Indicators (0)';
    indicatorsList.innerHTML = `<p class="no-indicators">No suspicious patterns detected for this input.</p>`;
  } else {
    indicatorsTitle.textContent = `Threat Indicators (${indicators.length})`;
    indicatorsList.innerHTML = indicators.map(ind => {
      const sev = (ind.severity || 'info').toLowerCase();
      const pointsTag = ind.points !== undefined ? `<span class="indicator-points-badge">+${ind.points} pts</span>` : '';
      const sourceTag = ind.source ? `<span class="indicator-source-tag">${escapeHTML(ind.source)}</span>` : '';

      return `
        <div class="indicator-card indicator--${sev}">
          <div class="indicator-icon indicator-icon--${sev}">
            ${ICONS[sev] || ICONS.info}
          </div>
          <div class="indicator-content">
            <div class="indicator-header">
              <h4 class="indicator-name">${escapeHTML(ind.name)}</h4>
              <div class="indicator-tags">
                ${pointsTag}
                ${sourceTag}
              </div>
            </div>
            <p class="indicator-detail">${escapeHTML(ind.detail)}</p>
          </div>
        </div>
      `;
    }).join('');
  }

  // Recommendations
  const recs = result.recommendations || [];
  const recsList = document.getElementById('recommendations-list');
  recsList.innerHTML = recs.map(r => `<li>${escapeHTML(r)}</li>`).join('');

  // Limitations Note
  const limitationsText = document.getElementById('limitations-text');
  if (limitationsText && result.limitations) {
    limitationsText.textContent = result.limitations;
  }

  // Reveal results
  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Gauge Animation ───────────────────────────────────

function animateGauge(targetScore, color) {
  const fill      = document.getElementById('gauge-fill');
  const scoreText = document.getElementById('gauge-score');
  const ARC_LEN   = 267;

  fill.style.stroke           = color;
  fill.style.strokeDashoffset = ARC_LEN * (1 - targetScore / 100);

  const startTime = performance.now();
  const duration  = 800;

  function tick(now) {
    const t        = Math.min((now - startTime) / duration, 1);
    const eased    = 1 - Math.pow(1 - t, 3);
    scoreText.textContent = Math.round(targetScore * eased);
    if (t < 1) requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}

// ── Utilities ─────────────────────────────────────────

function shake(el) {
  el.classList.remove('shake');
  void el.offsetWidth;
  el.classList.add('shake');
  el.addEventListener('animationend', () => el.classList.remove('shake'), { once: true });
  el.focus();
}

function showInlineError(msg) {
  clearInlineError();
  const el = document.createElement('p');
  el.id        = 'inline-error';
  el.className = 'inline-error';
  el.textContent = msg;
  const panel = document.querySelector('.tab-panel:not(.hidden)');
  if (panel) panel.appendChild(el);
  setTimeout(() => clearInlineError(), 5000);
}

function clearInlineError() {
  const el = document.getElementById('inline-error');
  if (el) el.remove();
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Initialize ────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
});

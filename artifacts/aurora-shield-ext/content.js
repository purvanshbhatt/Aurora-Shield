/**
 * AuroraShield Content Script
 * In-page threat warnings: input glow, floating warning cards, tooltips,
 * phishing banners, phrase highlighting, URL risk analysis.
 *
 * SETUP: Replace API_BASE with your deployed AuroraShield API URL.
 */

const DEFAULT_API_BASE = "https://aurora-shield--PurvanshBhatt.replit.app/api";
const MOCK_ANALYZE = {
  prompt: {
    risk_score: 72,
    category: "prompt_injection",
    explanation: "Instruction override detected",
    patterns: ["ignore previous", "system prompt", "role override"],
  },
  phishing: {
    risk_score: 68,
    category: "phishing",
    explanation: "Phishing language and credential bait detected",
    patterns: ["verify account", "password", "urgent action"],
  },
  url: {
    risk_score: 58,
    category: "suspicious_url",
    explanation: "Suspicious URL patterns detected",
    patterns: ["typosquatting", "long URL", "mixed subdomains"],
  },
};

const runtimeConfig = {
  backendUrl: DEFAULT_API_BASE,
  useMock: false,
};

function applyStoredConfig(items = {}) {
  if (typeof items.backendUrl === "string" && items.backendUrl.trim()) {
    runtimeConfig.backendUrl = items.backendUrl.trim();
  }
  if (typeof items.useMock === "boolean") {
    runtimeConfig.useMock = items.useMock;
  }
}

if (chrome?.storage?.local) {
  chrome.storage.local.get(["backendUrl", "useMock"], applyStoredConfig);
  chrome.storage.onChanged.addListener(changes => {
    if (changes.backendUrl) runtimeConfig.backendUrl = changes.backendUrl.newValue || DEFAULT_API_BASE;
    if (changes.useMock) runtimeConfig.useMock = !!changes.useMock.newValue;
  });
}

// ─── Inject shared CSS once ────────────────────────────────────────────────
(function injectStyles() {
  if (document.getElementById("aurora-styles")) return;
  const s = document.createElement("style");
  s.id = "aurora-styles";
  s.textContent = `
    /* Input glow */
    .aurora-glow-low {
      outline: none !important;
      box-shadow: 0 0 0 2px #FFC85755, 0 0 16px 2px #FFC85722 !important;
      transition: box-shadow 0.35s ease !important;
    }
    .aurora-glow-high {
      outline: none !important;
      box-shadow: 0 0 0 2.5px #FF4D4D99, 0 0 20px 4px #FF4D4D33 !important;
      transition: box-shadow 0.35s ease !important;
      animation: aurora-pulse-glow 1.8s ease-in-out infinite !important;
    }
    @keyframes aurora-pulse-glow {
      0%, 100% { box-shadow: 0 0 0 2.5px #FF4D4D99, 0 0 20px 4px #FF4D4D33; }
      50%       { box-shadow: 0 0 0 2.5px #FF4D4Dcc, 0 0 28px 6px #FF4D4D44; }
    }

    /* Floating warning card */
    .aurora-warning-card {
      position: fixed;
      z-index: 2147483647;
      min-width: 260px;
      max-width: 340px;
      background: rgba(11, 15, 20, 0.96);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-radius: 10px;
      padding: 12px 14px 10px;
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
      font-size: 12px;
      line-height: 1.45;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.06);
      pointer-events: none;
      animation: aurora-card-in 0.22s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes aurora-card-in {
      from { opacity: 0; transform: translateY(6px) scale(0.97); }
      to   { opacity: 1; transform: translateY(0)  scale(1);    }
    }
    .aurora-warning-card.aurora-card-out {
      animation: aurora-card-out 0.18s ease-in forwards;
    }
    @keyframes aurora-card-out {
      to { opacity: 0; transform: translateY(4px) scale(0.98); }
    }

    /* Card internals */
    .aurora-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 7px;
    }
    .aurora-card-brand {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .aurora-card-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 20px; height: 20px;
      border-radius: 5px;
      flex-shrink: 0;
    }
    .aurora-card-icon.low  { background: #FFC85720; }
    .aurora-card-icon.high { background: #FF4D4D20; }
    .aurora-card-label {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .aurora-card-label.low  { color: #FFC857; }
    .aurora-card-label.high { color: #FF4D4D; }
    .aurora-card-score {
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 18px;
      font-weight: 700;
      line-height: 1;
    }
    .aurora-card-score.low  { color: #FFC857; }
    .aurora-card-score.high { color: #FF4D4D; }
    .aurora-card-divider {
      height: 1px;
      background: rgba(255,255,255,0.06);
      margin: 7px 0;
    }
    .aurora-card-tooltip {
      font-size: 11.5px;
      color: rgba(226,234,244,0.75);
      line-height: 1.5;
    }
    .aurora-card-tooltip strong {
      color: rgba(226,234,244,0.95);
      font-weight: 600;
    }
    .aurora-card-patterns {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      margin-top: 7px;
    }
    .aurora-card-tag {
      font-size: 9.5px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      letter-spacing: 0.04em;
    }
    .aurora-card-tag.low  { background: #FFC85718; color: #FFC857; border: 1px solid #FFC85730; }
    .aurora-card-tag.high { background: #FF4D4D18; color: #FF4D4D; border: 1px solid #FF4D4D30; }

    /* Arrow pointer */
    .aurora-card-arrow {
      position: absolute;
      width: 10px; height: 6px;
      overflow: visible;
    }
    .aurora-card-arrow.down {
      bottom: -6px; left: 18px;
    }
    .aurora-card-arrow.up {
      top: -6px; left: 18px;
      transform: rotate(180deg);
    }
    .aurora-card-arrow polygon { fill: rgba(11,15,20,0.96); }

    /* Inline scanning shimmer on inputs */
    .aurora-scanning {
      position: relative;
    }
    .aurora-scanning::after {
      content: '';
      position: absolute;
      inset: 0;
      border-radius: inherit;
      background: linear-gradient(90deg, transparent 0%, rgba(0,255,156,0.06) 50%, transparent 100%);
      background-size: 200% 100%;
      animation: aurora-shimmer 1s linear infinite;
      pointer-events: none;
    }
    @keyframes aurora-shimmer {
      0%   { background-position: -200% center; }
      100% { background-position:  200% center; }
    }

    /* Fixed overlay (bottom-right) */
    #aurora-overlay {
      animation: aurora-overlay-in 0.22s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes aurora-overlay-in {
      from { opacity: 0; transform: translateY(10px); }
      to   { opacity: 1; transform: translateY(0);    }
    }

    /* Top banners */
    #aurora-banner, #aurora-phishing-banner {
      animation: aurora-banner-in 0.18s ease-out both;
    }
    @keyframes aurora-banner-in {
      from { opacity: 0; transform: translateY(-100%); }
      to   { opacity: 1; transform: translateY(0); }
    }
  `;
  (document.head || document.documentElement).appendChild(s);
})();

// ─── Helpers ───────────────────────────────────────────────────────────────

function getSiteContext() {
  const h = window.location.hostname;
  if (h.includes("chatgpt.com") || h.includes("openai.com")) return "chatgpt";
  if (h.includes("mail.google.com")) return "gmail";
  if (h.includes("outlook")) return "outlook";
  return h;
}

async function callAnalyze(type, data) {
  if (runtimeConfig.useMock) {
    return MOCK_ANALYZE[type] || MOCK_ANALYZE.prompt;
  }

  const res = await fetch(`${runtimeConfig.backendUrl}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, data }),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ─── Input Glow ────────────────────────────────────────────────────────────

function applyGlow(input, level) {
  // level: "safe" | "low" | "high"
  input.classList.remove("aurora-glow-low", "aurora-glow-high");
  if (level === "low")  input.classList.add("aurora-glow-low");
  if (level === "high") input.classList.add("aurora-glow-high");
}

function clearGlow(input) {
  input.classList.remove("aurora-glow-low", "aurora-glow-high");
}

// ─── Floating Warning Card (anchored to input) ─────────────────────────────

const cardsByInput = new WeakMap();

function removeWarningCard(input) {
  const existing = cardsByInput.get(input);
  if (!existing) return;
  existing.classList.add("aurora-card-out");
  setTimeout(() => existing.remove(), 200);
  cardsByInput.delete(input);
}

function positionCard(card, input) {
  const rect = input.getBoundingClientRect();
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const cardH = 110; // estimated; adjusted after render
  const cardW = 300;
  const gap = 8;

  let top, left, arrowDir;

  // Prefer placing card above the input
  if (rect.top > cardH + gap + 20) {
    top = rect.top - cardH - gap;
    arrowDir = "down";
  } else {
    top = rect.bottom + gap;
    arrowDir = "up";
  }

  // Horizontal: align left edge of card with left edge of input, clamp to viewport
  left = Math.max(8, Math.min(rect.left, vw - cardW - 8));

  card.style.top  = `${top}px`;
  card.style.left = `${left}px`;

  // Arrow horizontal offset relative to card left
  const arrowEl = card.querySelector(".aurora-card-arrow");
  if (arrowEl) {
    const arrowOffset = Math.max(10, Math.min(rect.left - left + 12, cardW - 20));
    arrowEl.style.left = `${arrowOffset}px`;
    arrowEl.classList.remove("up", "down");
    arrowEl.classList.add(arrowDir);
  }
}

function showWarningCard(input, riskScore, category, explanation, patterns) {
  removeWarningCard(input);

  const isHigh = riskScore > 60;
  const tier   = isHigh ? "high" : "low";

  const TOOLTIP_MAP = {
    prompt_injection: "This input may trigger a <strong>prompt injection attack</strong>. The text could override AI system instructions.",
    phishing:         "This content contains <strong>phishing indicators</strong>. Verify the source before proceeding.",
    suspicious_url:   "A <strong>suspicious URL pattern</strong> was detected. This link may redirect to a malicious site.",
    safe:             "No threats detected in this input.",
  };
  const tooltip = TOOLTIP_MAP[category] || TOOLTIP_MAP.prompt_injection;

  const ICON = {
    high: `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#FF4D4D" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    low:  `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#FFC857" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  };

  const patternTags = (patterns || []).slice(0, 4).map(p =>
    `<span class="aurora-card-tag ${tier}">${p}</span>`
  ).join("");

  const card = document.createElement("div");
  card.className = "aurora-warning-card";
  card.innerHTML = `
    <svg class="aurora-card-arrow down" width="10" height="6" viewBox="0 0 10 6">
      <polygon points="0,0 10,0 5,6"/>
    </svg>
    <div class="aurora-card-header">
      <div class="aurora-card-brand">
        <div class="aurora-card-icon ${tier}">${ICON[tier]}</div>
        <span class="aurora-card-label ${tier}">AuroraShield</span>
      </div>
      <span class="aurora-card-score ${tier}">${riskScore}<span style="font-size:10px;opacity:.5">%</span></span>
    </div>
    <div class="aurora-card-divider"></div>
    <div class="aurora-card-tooltip">${tooltip}</div>
    ${patternTags ? `<div class="aurora-card-patterns">${patternTags}</div>` : ""}
  `;

  document.body.appendChild(card);
  cardsByInput.set(input, card);

  // Position after render so we have real dimensions
  requestAnimationFrame(() => {
    const h = card.offsetHeight;
    positionCard(card, input);

    // Re-position if scrolled
    const onScroll = () => positionCard(card, input);
    window.addEventListener("scroll", onScroll, { passive: true });
    card._removeScroll = () => window.removeEventListener("scroll", onScroll);
  });

  // Auto-dismiss after delay based on severity
  const delay = isHigh ? 8000 : 5000;
  setTimeout(() => removeWarningCard(input), delay);
}

// ─── Global corner overlay (for non-input results) ─────────────────────────

let activeOverlay = null;

function showRiskOverlay(riskScore, category, explanation) {
  if (activeOverlay) activeOverlay.remove();

  const COLORS = {
    safe:             { bg: "rgba(15,35,24,0.95)",  border: "#22c55e44", text: "#22c55e" },
    prompt_injection: { bg: "rgba(26,15,15,0.95)",  border: "#FF4D4D44", text: "#FF4D4D" },
    phishing:         { bg: "rgba(26,14,0,0.95)",   border: "#FFC85744", text: "#FFC857" },
    suspicious_url:   { bg: "rgba(26,20,0,0.95)",   border: "#FFC85744", text: "#FFC857" },
  };
  const c = COLORS[category] || COLORS.prompt_injection;

  const el = document.createElement("div");
  el.id = "aurora-overlay";
  el.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:2147483647;
    background:${c.bg};
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border:1px solid ${c.border};border-radius:10px;
    padding:12px 16px;
    font-family:'Inter','Segoe UI',system-ui,sans-serif;font-size:12px;
    color:${c.text};min-width:240px;max-width:340px;
    box-shadow:0 8px 32px rgba(0,0,0,0.55),0 0 0 1px rgba(255,255,255,0.04);
  `;
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <div style="font-size:9px;letter-spacing:.12em;opacity:.5;font-weight:600">AURORASHIELD</div>
        <div style="font-size:12px;font-weight:700;margin-top:2px;text-transform:uppercase;letter-spacing:.04em">
          ${category.replace(/_/g," ")}
        </div>
      </div>
      <div style="font-family:'SF Mono','Fira Code',monospace;font-size:22px;font-weight:700">
        ${riskScore}<span style="font-size:10px;opacity:.5">%</span>
      </div>
    </div>
    <div style="height:1px;background:rgba(255,255,255,0.06);margin:8px 0"></div>
    <div style="font-size:11.5px;color:rgba(226,234,244,.7);line-height:1.5">${explanation}</div>
    <div onclick="this.parentElement.remove()" style="margin-top:8px;font-size:10px;opacity:.35;cursor:pointer;text-align:right;letter-spacing:.04em">dismiss</div>
  `;

  document.body.appendChild(el);
  activeOverlay = el;
  if (riskScore < 30) setTimeout(() => { if (el.parentNode) el.remove(); }, 3500);
}

// ─── Before-You-Send Banner ────────────────────────────────────────────────

let activeBanner = null;

function showBeforeYouSendWarning(riskScore, explanation, onBlock, onProceed) {
  if (activeBanner) activeBanner.remove();

  const el = document.createElement("div");
  el.id = "aurora-banner";
  el.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:2147483647;
    background:rgba(11,15,20,0.97);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border-bottom:2px solid #FF4D4D;
    padding:11px 20px;
    font-family:'Inter','Segoe UI',system-ui,sans-serif;
    display:flex;align-items:center;gap:16px;flex-wrap:wrap;
  `;
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;flex:1;min-width:200px">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF4D4D" stroke-width="2.5">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      <div>
        <span style="color:#FF4D4D;font-size:11px;font-weight:700;letter-spacing:.04em">PROMPT INJECTION RISK — ${riskScore}%</span>
        <span style="color:rgba(226,234,244,.55);font-size:11px;margin-left:10px">${explanation}</span>
      </div>
    </div>
    <div style="display:flex;gap:7px">
      <button id="aurora-block"
        style="background:#FF4D4D18;border:1px solid #FF4D4D55;color:#FF4D4D;
               font-family:inherit;font-size:11px;font-weight:600;padding:5px 14px;
               border-radius:6px;cursor:pointer;transition:all .15s">
        Block Send
      </button>
      <button id="aurora-proceed"
        style="background:transparent;border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.35);
               font-family:inherit;font-size:11px;padding:5px 14px;border-radius:6px;cursor:pointer">
        Send Anyway
      </button>
    </div>
  `;

  document.body.prepend(el);
  activeBanner = el;

  el.querySelector("#aurora-block").addEventListener("click",   () => { el.remove(); activeBanner = null; onBlock?.(); });
  el.querySelector("#aurora-proceed").addEventListener("click", () => { el.remove(); activeBanner = null; onProceed?.(); });
}

// ─── Phishing Page Banner ──────────────────────────────────────────────────

function showPhishingAlert(riskScore, explanation) {
  if (document.getElementById("aurora-phishing-banner")) return;

  const el = document.createElement("div");
  el.id = "aurora-phishing-banner";
  el.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:2147483647;
    background:rgba(11,15,20,0.97);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border-bottom:2px solid #FFC857;
    padding:10px 20px;
    font-family:'Inter','Segoe UI',system-ui,sans-serif;
    font-size:12px;
    display:flex;align-items:center;justify-content:space-between;gap:12px;
  `;
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#FFC857" stroke-width="2.5">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <span style="color:#FFC857;font-weight:700;font-size:11px;letter-spacing:.04em">PHISHING RISK — ${riskScore}%</span>
      <span style="color:rgba(226,234,244,.5);font-size:11px">${explanation}</span>
    </div>
    <button onclick="document.getElementById('aurora-phishing-banner').remove()"
      style="background:transparent;border:1px solid rgba(255,200,87,.3);color:#FFC857;
             font-family:inherit;font-size:10px;padding:3px 10px;border-radius:5px;cursor:pointer;white-space:nowrap">
      dismiss
    </button>
  `;
  document.body.prepend(el);
}

// ─── Email Phrase Highlighting ─────────────────────────────────────────────

function highlightPhrases(phrases) {
  if (!phrases?.length) return;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) {
    const n = walker.currentNode;
    const tag = n.parentElement?.tagName;
    if (tag && !["SCRIPT","STYLE","HEAD","NOSCRIPT"].includes(tag)) nodes.push(n);
  }
  for (const node of nodes) {
    let html = node.textContent || "";
    let changed = false;
    for (const phrase of phrases) {
      const re = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      if (re.test(html)) {
        changed = true;
        html = html.replace(re, m =>
          `<mark style="background:rgba(255,200,87,.15);color:#FFC857;border-bottom:1.5px solid #FFC85780;border-radius:2px;padding:0 2px">${m}</mark>`
        );
      }
    }
    if (changed) {
      const span = document.createElement("span");
      span.innerHTML = html;
      node.parentNode?.replaceChild(span, node);
    }
  }
}

// ─── Input Monitoring ──────────────────────────────────────────────────────

const monitored   = new WeakSet();
let   debounceMap = new WeakMap(); // per-input debounce timers

function monitorInput(input) {
  if (monitored.has(input)) return;
  monitored.add(input);

  // ── Live debounced analysis while typing ───────────────────────────────
  input.addEventListener("input", () => {
    clearTimeout(debounceMap.get(input));
    debounceMap.set(input, setTimeout(async () => {
      const text = getText(input);
      if (text.length < 20) { clearGlow(input); removeWarningCard(input); return; }

      try {
        const result = await callAnalyze("prompt", text);
        const score  = result.risk_score || 0;

        if (score < 25) {
          clearGlow(input);
          removeWarningCard(input);
        } else {
          const tier = score > 60 ? "high" : "low";
          applyGlow(input, tier);
          showWarningCard(input, score, result.category, result.explanation, result.patterns);
        }
      } catch (e) {
        console.warn("[AuroraShield] Live analysis failed:", e);
      }
    }, 900));
  });

  // ── On blur — final analysis ───────────────────────────────────────────
  input.addEventListener("blur", async () => {
    clearTimeout(debounceMap.get(input));
    const text = getText(input);
    if (text.length < 15) return;

    try {
      const result = await callAnalyze("prompt", text);
      const score  = result.risk_score || 0;

      if (score < 25) {
        clearGlow(input);
        removeWarningCard(input);
      } else {
        const tier = score > 60 ? "high" : "low";
        applyGlow(input, tier);
        showWarningCard(input, score, result.category, result.explanation, result.patterns);
        showRiskOverlay(score, result.category, result.explanation);
      }
    } catch (e) {
      console.warn("[AuroraShield] Blur analysis failed:", e);
    }
  });

  // ── On focus — remove card so it doesn't block typing ─────────────────
  input.addEventListener("focus", () => removeWarningCard(input));

  // ── Enter key — "Before You Send" blocker ─────────────────────────────
  input.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter" || e.shiftKey) return;
    const text = getText(input);
    if (text.length < 15) return;

    try {
      const result = await callAnalyze("prompt", text);
      if ((result.risk_score || 0) > 60) {
        e.preventDefault();
        e.stopImmediatePropagation();
        showBeforeYouSendWarning(result.risk_score, result.explanation, null, null);
      }
    } catch (e) {
      console.warn("[AuroraShield] Pre-send check failed:", e);
    }
  }, true);
}

function getText(el) {
  return (el.value || el.textContent || el.innerText || "").trim();
}

function findAndMonitorInputs() {
  document.querySelectorAll(
    "textarea, input[type='text'], [contenteditable='true'], [contenteditable=''], [role='textbox']"
  ).forEach(el => monitorInput(el));
}

// ─── Page Phishing Scan ────────────────────────────────────────────────────

async function scanPageForPhishing() {
  const content = document.body.innerText.slice(0, 4000);
  if (content.length < 80) return;
  try {
    const result = await callAnalyze("phishing", content);
    if ((result.risk_score || 0) > 40) {
      showPhishingAlert(result.risk_score, result.explanation);
      if (result.suspicious_phrases?.length) highlightPhrases(result.suspicious_phrases);
    }
  } catch (e) {
    console.warn("[AuroraShield] Phishing scan failed:", e);
  }
}

// ─── URL Risk Analysis ─────────────────────────────────────────────────────

async function analyzePageUrls() {
  const urls = Array.from(document.querySelectorAll("a[href]"))
    .map(a => a.getAttribute("href"))
    .filter(h => h && h.startsWith("http"))
    .slice(0, 20);
  if (!urls.length) return;
  try {
    const result = await callAnalyze("url", JSON.stringify(urls));
    if ((result.risk_score || 0) > 30) {
      chrome.storage.local.set({
        [`url_risk_${window.location.hostname}`]: {
          riskLevel:   result.risk_level,
          riskScore:   result.risk_score,
          explanation: result.explanation,
          timestamp:   Date.now(),
        },
      });
    }
  } catch (e) {
    console.warn("[AuroraShield] URL analysis failed:", e);
  }
}

// ─── MutationObserver (SPA support) ───────────────────────────────────────

const observer = new MutationObserver(() => findAndMonitorInputs());
observer.observe(document.body, { childList: true, subtree: true });

// ─── Init ──────────────────────────────────────────────────────────────────

function init() {
  findAndMonitorInputs();
  setTimeout(scanPageForPhishing, 2500);
  setTimeout(analyzePageUrls,     4000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

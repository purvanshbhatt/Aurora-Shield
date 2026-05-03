/**
 * AuroraShield Content Script
 * Runs on all URLs. Monitors text inputs, scans page content,
 * and extracts URLs for real-time security analysis.
 *
 * SETUP: Replace API_BASE with your deployed AuroraShield API URL.
 */

const API_BASE = "https://your-replit-app.replit.app/api";

// ─── Helpers ───────────────────────────────────────────────────────────────

function getSiteContext() {
  const h = window.location.hostname;
  if (h.includes("chatgpt.com") || h.includes("openai.com")) return "chatgpt";
  if (h.includes("mail.google.com")) return "gmail";
  if (h.includes("outlook")) return "outlook";
  return h;
}

async function callAnalyze(type, data) {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, data }),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ─── Risk Overlay ──────────────────────────────────────────────────────────

let activeOverlay = null;

function showRiskOverlay(riskScore, category, explanation) {
  if (activeOverlay) activeOverlay.remove();

  const COLORS = {
    safe:              { bg: "#0f2318", border: "#22c55e", text: "#22c55e" },
    prompt_injection:  { bg: "#1a0f0f", border: "#ef4444", text: "#ef4444" },
    phishing:          { bg: "#1a0a00", border: "#f97316", text: "#f97316" },
    suspicious_url:    { bg: "#1a1a00", border: "#eab308", text: "#eab308" },
  };

  const key = category in COLORS ? category : (riskScore > 60 ? "prompt_injection" : "safe");
  const c = COLORS[key];

  const el = document.createElement("div");
  el.id = "aurora-overlay";
  el.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:2147483647;
    background:${c.bg};border:1.5px solid ${c.border};border-radius:10px;
    padding:12px 16px;font-family:'SF Mono','Fira Code',monospace;font-size:12px;
    color:${c.text};min-width:240px;max-width:340px;
    box-shadow:0 4px 32px rgba(0,0,0,0.5);
    animation:aurora-in 0.2s ease-out;
  `;

  el.innerHTML = `
    <style>@keyframes aurora-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}</style>
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <div style="font-size:9px;letter-spacing:.12em;opacity:.6">AURORASHIELD</div>
        <div style="font-size:13px;font-weight:600;margin-top:2px;text-transform:uppercase">${category.replace(/_/g," ")}</div>
      </div>
      <div style="font-size:24px;font-weight:700">${riskScore}<span style="font-size:10px;opacity:.6">%</span></div>
    </div>
    <div style="margin-top:8px;font-size:11px;color:${c.text}bb;border-top:1px solid ${c.border}22;padding-top:8px">${explanation}</div>
    <div onclick="document.getElementById('aurora-overlay').remove()" style="margin-top:8px;font-size:10px;opacity:.4;cursor:pointer;text-align:right">dismiss</div>
  `;

  document.body.appendChild(el);
  activeOverlay = el;

  if (riskScore < 30) setTimeout(() => el.remove(), 3500);
}

// ─── Before-You-Send Banner ────────────────────────────────────────────────

let activeBanner = null;

function showBeforeYouSendWarning(riskScore, explanation, onBlock, onProceed) {
  if (activeBanner) activeBanner.remove();

  const el = document.createElement("div");
  el.id = "aurora-banner";
  el.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:2147483647;
    background:#0d0d0d;border-bottom:2px solid #ef4444;
    padding:12px 20px;font-family:'SF Mono','Fira Code',monospace;
    display:flex;align-items:center;gap:16px;flex-wrap:wrap;
    animation:aurora-banner-in 0.15s ease-out;
  `;

  el.innerHTML = `
    <style>@keyframes aurora-banner-in{from{opacity:0;transform:translateY(-100%)}to{opacity:1;transform:translateY(0)}}</style>
    <div style="color:#ef4444;font-size:12px;font-weight:600;flex:1;min-width:200px">
      AURORASHIELD — Risk Score: ${riskScore}% &nbsp;|&nbsp; ${explanation}
    </div>
    <div style="display:flex;gap:8px">
      <button id="aurora-block" style="background:#ef444422;border:1px solid #ef4444;color:#ef4444;font-family:monospace;font-size:11px;padding:5px 12px;border-radius:5px;cursor:pointer">Block Send</button>
      <button id="aurora-proceed" style="background:transparent;border:1px solid #ffffff22;color:#ffffff55;font-family:monospace;font-size:11px;padding:5px 12px;border-radius:5px;cursor:pointer">Send Anyway</button>
    </div>
  `;

  document.body.prepend(el);
  activeBanner = el;

  el.querySelector("#aurora-block").addEventListener("click", () => {
    el.remove(); activeBanner = null; onBlock?.();
  });
  el.querySelector("#aurora-proceed").addEventListener("click", () => {
    el.remove(); activeBanner = null; onProceed?.();
  });
}

// ─── Phishing Alert Banner ─────────────────────────────────────────────────

function showPhishingAlert(riskScore, explanation) {
  if (document.getElementById("aurora-phishing-banner")) return;

  const el = document.createElement("div");
  el.id = "aurora-phishing-banner";
  el.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:2147483647;
    background:#1a0000;border-bottom:2px solid #f97316;
    padding:10px 20px;font-family:'SF Mono','Fira Code',monospace;
    font-size:12px;color:#f97316;
    display:flex;align-items:center;justify-content:space-between;gap:12px;
  `;

  el.innerHTML = `
    <span>AURORASHIELD PHISHING ALERT — Risk: ${riskScore}% &nbsp;|&nbsp; ${explanation}</span>
    <button onclick="document.getElementById('aurora-phishing-banner').remove()" style="background:transparent;border:1px solid #f9731666;color:#f97316;font-family:monospace;font-size:11px;padding:4px 10px;border-radius:4px;cursor:pointer">dismiss</button>
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
          `<mark style="background:#ef444433;color:#ef4444;border-bottom:1px solid #ef4444;border-radius:2px;padding:0 2px">${m}</mark>`
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

const monitored = new WeakSet();
let pendingAnalysis = null;

function monitorInput(input) {
  if (monitored.has(input)) return;
  monitored.add(input);

  // Analyze on blur (when user leaves the field)
  input.addEventListener("blur", async () => {
    const text = input.value || input.textContent || input.innerText || "";
    if (text.trim().length < 15) return;

    try {
      const result = await callAnalyze("prompt", text);
      showRiskOverlay(result.risk_score, result.category, result.explanation);
    } catch (e) {
      console.warn("[AuroraShield] Prompt analysis failed:", e);
    }
  });

  // Intercept Enter key — "Before You Send" warning for high-risk text
  input.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter" || e.shiftKey) return;
    const text = input.value || input.textContent || input.innerText || "";
    if (text.trim().length < 15) return;

    try {
      const result = await callAnalyze("prompt", text);
      if (result.risk_score > 60) {
        e.preventDefault();
        e.stopImmediatePropagation();
        showBeforeYouSendWarning(result.risk_score, result.explanation, null, null);
      }
    } catch (e) {
      console.warn("[AuroraShield] Pre-send check failed:", e);
    }
  }, true);
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
    if (result.risk_score > 40) {
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
    // Pass as JSON string since unified endpoint expects data: string
    const result = await callAnalyze("url", JSON.stringify(urls));

    if (result.risk_score > 30) {
      // Store risk for popup
      chrome.storage.local.set({
        [`url_risk_${window.location.hostname}`]: {
          riskLevel: result.risk_level,
          riskScore: result.risk_score,
          explanation: result.explanation,
          timestamp: Date.now(),
        },
      });
    }
  } catch (e) {
    console.warn("[AuroraShield] URL analysis failed:", e);
  }
}

// ─── Mutation Observer (SPA support) ──────────────────────────────────────

const observer = new MutationObserver(() => findAndMonitorInputs());
observer.observe(document.body, { childList: true, subtree: true });

// ─── Init ──────────────────────────────────────────────────────────────────

function init() {
  findAndMonitorInputs();
  setTimeout(scanPageForPhishing, 2500);
  setTimeout(analyzePageUrls, 4000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

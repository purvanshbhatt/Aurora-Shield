/**
 * AuroraShield Content Script
 * Monitors text inputs on ChatGPT, Gmail, and Outlook for security threats.
 */

const API_BASE = "https://your-api-host.replit.app/api"; // Replace with your deployed API URL

let currentOverlay = null;
let currentBanner = null;
let analysisTimeout = null;
let lastAnalyzedText = "";

// ─── Site Detection ────────────────────────────────────────────────────────
function getSiteContext() {
  const host = window.location.hostname;
  if (host.includes("chatgpt.com") || host.includes("openai.com")) return "chatgpt";
  if (host.includes("mail.google.com")) return "gmail";
  if (host.includes("outlook")) return "outlook";
  return "unknown";
}

// ─── Risk Badge Overlay ────────────────────────────────────────────────────
function createRiskOverlay(riskLevel, riskScore, patterns) {
  removeOverlay();
  const overlay = document.createElement("div");
  overlay.id = "auroraShield-overlay";

  const colors = {
    safe: { bg: "#0f2318", border: "#22c55e", text: "#22c55e" },
    low: { bg: "#1a1a0f", border: "#eab308", text: "#eab308" },
    medium: { bg: "#1a120f", border: "#f97316", text: "#f97316" },
    high: { bg: "#1a0f0f", border: "#ef4444", text: "#ef4444" },
    critical: { bg: "#1a0000", border: "#dc2626", text: "#ff3333" },
  };

  const c = colors[riskLevel] || colors.safe;
  const scorePercent = Math.round(riskScore * 100);
  const label = riskLevel.toUpperCase();

  overlay.style.cssText = `
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 2147483647;
    background: ${c.bg};
    border: 1.5px solid ${c.border};
    border-radius: 10px;
    padding: 12px 16px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px;
    color: ${c.text};
    min-width: 220px;
    max-width: 320px;
    box-shadow: 0 4px 32px rgba(0,0,0,0.5);
    backdrop-filter: blur(8px);
    animation: aurora-slide-in 0.2s ease-out;
  `;

  const patternsHtml = patterns.length > 0
    ? `<div style="margin-top:8px;border-top:1px solid ${c.border}22;padding-top:8px;font-size:11px;color:${c.text}99">
        ${patterns.slice(0, 3).map(p => `<div>&#9656; ${p}</div>`).join("")}
       </div>`
    : "";

  overlay.innerHTML = `
    <style>
      @keyframes aurora-slide-in {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }
    </style>
    <div style="display:flex;align-items:center;gap:10px;justify-content:space-between">
      <div>
        <div style="font-size:10px;letter-spacing:0.1em;opacity:0.7">AURORASHIELD</div>
        <div style="font-size:13px;font-weight:600;margin-top:2px">${label} RISK</div>
      </div>
      <div style="font-size:22px;font-weight:700">${scorePercent}<span style="font-size:11px;opacity:0.7">%</span></div>
    </div>
    ${patternsHtml}
    <div style="margin-top:8px;font-size:10px;opacity:0.5;cursor:pointer;text-align:right" onclick="document.getElementById('auroraShield-overlay').remove()">dismiss</div>
  `;

  document.body.appendChild(overlay);
  currentOverlay = overlay;

  if (riskLevel === "safe" || riskLevel === "low") {
    setTimeout(() => overlay.remove(), 4000);
  }
}

function removeOverlay() {
  if (currentOverlay) {
    currentOverlay.remove();
    currentOverlay = null;
  }
}

// ─── Before-You-Send Warning ───────────────────────────────────────────────
function showBeforeYouSendWarning(riskLevel, patterns, onProceed, onCancel) {
  if (currentBanner) currentBanner.remove();

  const banner = document.createElement("div");
  banner.id = "auroraShield-banner";

  const isHigh = riskLevel === "high" || riskLevel === "critical";
  const color = isHigh ? "#ef4444" : "#f97316";

  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    background: #0d0d0d;
    border-bottom: 2px solid ${color};
    padding: 14px 20px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
    animation: aurora-banner-in 0.15s ease-out;
  `;

  banner.innerHTML = `
    <style>
      @keyframes aurora-banner-in {
        from { opacity: 0; transform: translateY(-100%); }
        to { opacity: 1; transform: translateY(0); }
      }
    </style>
    <div style="color:${color};font-size:13px;font-weight:600;flex:1;min-width:200px">
      AURORASCHIELD: Prompt injection detected — ${patterns.slice(0, 2).join(", ") || "suspicious pattern"}
    </div>
    <div style="display:flex;gap:8px">
      <button id="aurora-cancel" style="background:${color}22;border:1px solid ${color};color:${color};font-family:monospace;font-size:12px;padding:6px 14px;border-radius:6px;cursor:pointer">
        Block Send
      </button>
      <button id="aurora-proceed" style="background:transparent;border:1px solid #ffffff22;color:#ffffff66;font-family:monospace;font-size:12px;padding:6px 14px;border-radius:6px;cursor:pointer">
        Send Anyway
      </button>
    </div>
  `;

  document.body.prepend(banner);
  currentBanner = banner;

  banner.querySelector("#aurora-cancel").addEventListener("click", () => {
    banner.remove();
    currentBanner = null;
    onCancel?.();
  });

  banner.querySelector("#aurora-proceed").addEventListener("click", () => {
    banner.remove();
    currentBanner = null;
    onProceed?.();
  });
}

// ─── Phishing Banner ───────────────────────────────────────────────────────
function showPhishingBanner(riskLevel, phrases) {
  if (currentBanner) return;
  const banner = document.createElement("div");
  banner.id = "auroraShield-phishing-banner";

  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    background: #1a0000;
    border-bottom: 2px solid #ef4444;
    padding: 12px 20px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px;
    color: #ef4444;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  `;

  banner.innerHTML = `
    <span>AURORASCHIELD ALERT: Phishing content detected on this page — ${phrases.slice(0, 2).join(", ")}</span>
    <button onclick="this.parentElement.remove()" style="background:transparent;border:1px solid #ef444466;color:#ef4444;font-family:monospace;font-size:11px;padding:4px 10px;border-radius:4px;cursor:pointer">dismiss</button>
  `;

  document.body.prepend(banner);
  currentBanner = banner;
}

// ─── Highlight Suspicious Phrases in Emails ────────────────────────────────
function highlightSuspiciousPhrases(phrases) {
  if (!phrases || phrases.length === 0) return;
  const body = document.body;
  const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
  const nodesToProcess = [];

  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (node.parentElement && !["SCRIPT", "STYLE", "HEAD"].includes(node.parentElement.tagName)) {
      nodesToProcess.push(node);
    }
  }

  for (const node of nodesToProcess) {
    let text = node.textContent || "";
    let modified = false;
    for (const phrase of phrases) {
      if (text.toLowerCase().includes(phrase.toLowerCase())) {
        modified = true;
        const regex = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
        text = text.replace(regex, `<mark style="background:#ef444433;color:#ef4444;border-bottom:1px solid #ef4444;border-radius:2px;padding:0 2px">$&</mark>`);
      }
    }
    if (modified) {
      const span = document.createElement("span");
      span.innerHTML = text;
      node.parentNode?.replaceChild(span, node);
    }
  }
}

// ─── URL Extraction & Analysis ─────────────────────────────────────────────
function extractPageUrls() {
  const links = Array.from(document.querySelectorAll("a[href]"));
  const urls = new Set();
  for (const link of links) {
    const href = link.getAttribute("href");
    if (href && href.startsWith("http")) urls.add(href);
  }
  return Array.from(urls).slice(0, 30);
}

async function analyzePageUrls() {
  const urls = extractPageUrls();
  if (urls.length === 0) return;

  try {
    const res = await sendMessage({ type: "ANALYZE_URLS", urls, pageUrl: window.location.href });
    if (res?.riskLevel && res.riskLevel !== "safe") {
      chrome.storage.local.set({
        [`url_risk_${window.location.hostname}`]: {
          riskLevel: res.riskLevel,
          riskScore: res.overallRiskScore,
          timestamp: Date.now(),
        },
      });
    }
  } catch (e) {
    console.warn("[AuroraShield] URL analysis failed:", e);
  }
}

// ─── Background Messaging ──────────────────────────────────────────────────
function sendMessage(msg) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(msg, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    } catch (e) {
      reject(e);
    }
  });
}

// ─── Input Monitoring ──────────────────────────────────────────────────────
function monitorInput(input) {
  const context = getSiteContext();

  const handleInput = () => {
    const text = input.value || input.textContent || input.innerText || "";
    if (text.trim().length < 20 || text === lastAnalyzedText) return;
    lastAnalyzedText = text;

    clearTimeout(analysisTimeout);
    analysisTimeout = setTimeout(async () => {
      try {
        const res = await sendMessage({ type: "ANALYZE_PROMPT", text, context });
        if (res) {
          createRiskOverlay(res.riskLevel, res.riskScore, res.patterns);
        }
      } catch (e) {
        console.warn("[AuroraShield] Prompt analysis failed:", e);
      }
    }, 800);
  };

  const handleBeforeSubmit = async (e) => {
    const text = input.value || input.textContent || input.innerText || "";
    if (text.trim().length < 20) return;

    try {
      const res = await sendMessage({ type: "ANALYZE_PROMPT", text, context });
      if (res && (res.riskLevel === "high" || res.riskLevel === "critical")) {
        e.preventDefault();
        e.stopImmediatePropagation();
        showBeforeYouSendWarning(res.riskLevel, res.patterns, null, null);
        return false;
      }
    } catch (e) {
      console.warn("[AuroraShield] Pre-submit check failed:", e);
    }
  };

  input.addEventListener("input", handleInput);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) handleBeforeSubmit(e);
  });
}

// ─── Scan Page Content for Phishing ───────────────────────────────────────
async function scanPageForPhishing() {
  const content = document.body.innerText.slice(0, 3000);
  if (content.length < 100) return;

  try {
    const res = await sendMessage({
      type: "ANALYZE_PHISHING",
      content,
      url: window.location.href,
    });

    if (res && (res.riskLevel === "high" || res.riskLevel === "critical")) {
      showPhishingBanner(res.riskLevel, res.suspiciousPhrases);
      highlightSuspiciousPhrases(res.suspiciousPhrases);
    }
  } catch (e) {
    console.warn("[AuroraShield] Phishing scan failed:", e);
  }
}

// ─── Input Observer ────────────────────────────────────────────────────────
const monitoredInputs = new WeakSet();

function findAndMonitorInputs() {
  const selectors = [
    "textarea",
    "[contenteditable='true']",
    "[contenteditable='']",
    "input[type='text']:not([type='search'])",
    "[role='textbox']",
  ];

  for (const selector of selectors) {
    document.querySelectorAll(selector).forEach(el => {
      if (!monitoredInputs.has(el)) {
        monitoredInputs.add(el);
        monitorInput(el);
      }
    });
  }
}

const observer = new MutationObserver(() => findAndMonitorInputs());
observer.observe(document.body, { childList: true, subtree: true });

// ─── Initialize ────────────────────────────────────────────────────────────
function init() {
  findAndMonitorInputs();
  setTimeout(scanPageForPhishing, 2000);
  setTimeout(analyzePageUrls, 3000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

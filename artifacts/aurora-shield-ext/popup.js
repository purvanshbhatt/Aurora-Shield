/**
 * AuroraShield Popup — Premium UI
 * Circular gauge, threat breakdown, live feed, action buttons.
 */

const DEFAULT_API_BASE = "https://aurora-shield--PurvanshBhatt.replit.app/api";

// ─── Constants ─────────────────────────────────────────────────────────────
const ARC_CIRCUMFERENCE = 2 * Math.PI * 48; // r=48 → ≈301.6

const THRESHOLDS = {
  green:  { max: 30,  cls: "",        label: "Low Risk",   status: "Active",   statusCls: "" },
  yellow: { max: 70,  cls: "warning", label: "Suspicious", status: "Warning",  statusCls: "warning" },
  red:    { max: 100, cls: "danger",  label: "High Risk",  status: "Threat",   statusCls: "danger" },
};

function tier(score) {
  if (score <= 30) return THRESHOLDS.green;
  if (score <= 70) return THRESHOLDS.yellow;
  return THRESHOLDS.red;
}

function timeAgo(iso) {
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.floor(d / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function clampScore(n) { return Math.max(0, Math.min(100, Math.round(n || 0))); }

// ─── DOM Refs ──────────────────────────────────────────────────────────────
const shell       = document.querySelector(".shell");
const gaugeArc    = document.getElementById("gaugeArc");
const gaugeGlow   = document.getElementById("gaugeGlow");
const gaugeScore  = document.getElementById("gaugeScore");
const gaugeLabel  = document.getElementById("gaugeLabel");
const pulseDot    = document.getElementById("pulseDot");
const statusText  = document.getElementById("statusText");
const scanInd     = document.getElementById("scanIndicator");
const feedList    = document.getElementById("feedList");

const barInject   = document.getElementById("barInject");
const barPhish    = document.getElementById("barPhish");
const barUrl      = document.getElementById("barUrl");
const pctInject   = document.getElementById("pctInject");
const pctPhish    = document.getElementById("pctPhish");
const pctUrl      = document.getElementById("pctUrl");

const btnScan     = document.getElementById("btnScan");
const btnDetails  = document.getElementById("btnDetails");
const btnReport   = document.getElementById("btnReport");
const dashLink    = document.getElementById("dashLink");
const backendUrlInput = document.getElementById("backendUrl");
const useMockInput = document.getElementById("useMock");

// ─── Gauge Update ──────────────────────────────────────────────────────────
function setGauge(score) {
  const pct    = clampScore(score);
  const t      = tier(pct);
  const offset = ARC_CIRCUMFERENCE * (1 - pct / 100);

  gaugeArc.style.strokeDashoffset  = offset;
  gaugeGlow.style.strokeDashoffset = offset;

  gaugeArc.className  = `gauge-arc  ${t.cls}`;
  gaugeGlow.className = `gauge-glow ${t.cls}`;
  gaugeScore.className = `gauge-score ${t.cls}`;

  gaugeScore.textContent = pct;
  gaugeLabel.textContent = pct === 0 ? "Secure" : t.label;

  pulseDot.className  = `pulse-dot ${t.statusCls}`;
  statusText.textContent = t.status;
  statusText.className   = `status-text ${t.statusCls}`;

  shell.className = `shell ${t.cls}`;
}

// ─── Breakdown Bars ────────────────────────────────────────────────────────
function riskColor(score) {
  if (score <= 30) return "var(--green)";
  if (score <= 70) return "var(--yellow)";
  return "var(--red)";
}

function setBar(barEl, pctEl, score) {
  const pct = clampScore(score);
  barEl.style.width      = pct + "%";
  barEl.style.background = riskColor(pct);
  pctEl.textContent      = pct + "%";
  pctEl.style.color      = riskColor(pct);
}

// ─── Feed ──────────────────────────────────────────────────────────────────
const FEED_TYPE_META = {
  prompt_injection: { cls: "inject", badge: "Injection", icon: "!!" },
  phishing:         { cls: "phish",  badge: "Phishing",  icon: "!!"  },
  suspicious_url:   { cls: "url",    badge: "URL Risk",  icon: "!!" },
};

function renderFeed(threats) {
  if (!threats || threats.length === 0) {
    feedList.innerHTML = '<div class="feed-empty">Shield is monitoring this page</div>';
    return;
  }

  feedList.innerHTML = threats.slice(0, 6).map(t => {
    const meta = FEED_TYPE_META[t.type] || { cls: "url", badge: t.type, icon: "!!" };
    return `
      <div class="feed-item">
        <div class="feed-type-dot ${meta.cls}"></div>
        <div class="feed-content">
          <div class="feed-msg">${t.summary || t.context || "Threat detected"}</div>
          <div class="feed-meta">
            <span class="feed-badge ${meta.cls}">${meta.badge}</span>
            <span class="feed-time">${timeAgo(t.detectedAt)}</span>
          </div>
        </div>
      </div>`;
  }).join("");
}

// ─── Scanning State ────────────────────────────────────────────────────────
function setScanningState(active) {
  if (active) {
    scanInd.classList.add("active");
    btnScan.classList.add("scanning");
    btnScan.textContent = "Scanning...";
  } else {
    scanInd.classList.remove("active");
    btnScan.classList.remove("scanning");
    btnScan.innerHTML = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      Scan Page`;
  }
}

// ─── Add to Feed ───────────────────────────────────────────────────────────
function prependFeedItem(type, msg) {
  const empty = feedList.querySelector(".feed-empty");
  if (empty) empty.remove();

  const meta = FEED_TYPE_META[type] || { cls: "url", badge: type };
  const el = document.createElement("div");
  el.className = "feed-item";
  el.innerHTML = `
    <div class="feed-type-dot ${meta.cls}"></div>
    <div class="feed-content">
      <div class="feed-msg">${msg}</div>
      <div class="feed-meta">
        <span class="feed-badge ${meta.cls}">${meta.badge}</span>
        <span class="feed-time">just now</span>
      </div>
    </div>`;
  feedList.prepend(el);

  // Trim to 6 items
  const items = feedList.querySelectorAll(".feed-item");
  if (items.length > 6) items[items.length - 1].remove();
}

// ─── Load Data ─────────────────────────────────────────────────────────────
async function loadPageRisk(tab) {
  if (!tab?.url) return;
  let hostname = "unknown";
  try { hostname = new URL(tab.url).hostname; } catch {}

  chrome.storage.local.get([`url_risk_${hostname}`], result => {
    const risk = Object.values(result)[0];
    if (risk) {
      setGauge(risk.riskScore);
      setBar(barUrl, pctUrl, risk.riskScore);
    } else {
      setGauge(0);
    }
  });
}

async function loadStats() {
  chrome.runtime.sendMessage({ type: "GET_STATS" }, stats => {
    if (!stats || stats.error) return;
    // Derive approximate breakdown scores from stats
    const total = Math.max(1, stats.totalScans);
    const injRate = clampScore((stats.promptInjections / total) * 100 * 3);
    const phRate  = clampScore((stats.phishingDetected / total) * 100 * 3);
    setBar(barInject, pctInject, injRate);
    setBar(barPhish,  pctPhish,  phRate);

    // Update gauge to max threat level
    const maxScore = Math.max(injRate, phRate);
    if (maxScore > 0) setGauge(maxScore);
  });
}

async function loadThreats() {
  chrome.runtime.sendMessage({ type: "GET_RECENT" }, threats => {
    if (!threats || threats.error) { renderFeed([]); return; }
    renderFeed(threats);

    // Update breakdown bars from recent data
    const recent = threats.slice(0, 10);
    const injections = recent.filter(t => t.type === "prompt_injection");
    const phishing   = recent.filter(t => t.type === "phishing");
    const urls       = recent.filter(t => t.type === "suspicious_url");

    const avgScore = arr => arr.length === 0 ? 0
      : Math.round(arr.reduce((s, t) => s + t.riskScore * 100, 0) / arr.length);

    setBar(barInject, pctInject, avgScore(injections));
    setBar(barPhish,  pctPhish,  avgScore(phishing));
    setBar(barUrl,    pctUrl,    avgScore(urls));

    // Overall gauge = highest recent score
    const allScores = recent.map(t => t.riskScore * 100);
    if (allScores.length) setGauge(Math.max(...allScores));
  });
}

// ─── Manual Page Scan ──────────────────────────────────────────────────────
async function runPageScan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  setScanningState(true);

  try {
    // Inject scan via scripting API
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => ({ text: document.body.innerText.slice(0, 4000), url: window.location.href }),
    });

    const { text, url } = results[0]?.result || {};

    chrome.runtime.sendMessage({ type: "ANALYZE_PHISHING", content: text, url }, res => {
      if (res && !res.error) {
        const score = Math.round(res.riskScore * 100);
        setGauge(score);
        setBar(barPhish, pctPhish, score);
        if (score > 20) {
          prependFeedItem("phishing", res.explanation || "Phishing content detected on this page");
        }
      }
    });

    chrome.runtime.sendMessage({ type: "ANALYZE_URLS", urls: [], pageUrl: url }, res => {
      if (res && !res.error) {
        const score = Math.round(res.overallRiskScore * 100);
        setBar(barUrl, pctUrl, score);
        if (score > 20) {
          prependFeedItem("suspicious_url", res.urlResults?.[0]
            ? `Suspicious URL: ${res.urlResults[0].flags.slice(0,2).join(", ")}`
            : "Suspicious URL patterns detected");
        }
      }
      setScanningState(false);
    });

  } catch (err) {
    console.warn("[AuroraShield] Scan failed:", err);
    setScanningState(false);
  }
}

// ─── Report Threat ─────────────────────────────────────────────────────────
function showReportConfirmation() {
  const orig = btnReport.innerHTML;
  btnReport.textContent = "Reported!";
  btnReport.style.background = "#00FF9C18";
  btnReport.style.borderColor = "#00FF9C33";
  btnReport.style.color = "var(--green)";
  setTimeout(() => {
    btnReport.innerHTML = orig;
    btnReport.style = "";
  }, 2000);
}

function loadBackendConfig() {
  chrome.storage.local.get(["backendUrl", "useMock"], items => {
    backendUrlInput.value = (typeof items.backendUrl === "string" && items.backendUrl.trim())
      ? items.backendUrl.trim()
      : DEFAULT_API_BASE;
    useMockInput.checked = !!items.useMock;
  });
}

function saveBackendConfig() {
  chrome.storage.local.set({
    backendUrl: backendUrlInput.value.trim(),
    useMock: useMockInput.checked,
  });
}

// ─── Init ──────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  setGauge(0);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  await Promise.all([loadPageRisk(tab), loadStats(), loadThreats()]);

  btnScan.addEventListener("click", runPageScan);

  btnDetails.addEventListener("click", () => {
    chrome.tabs.create({ url: "https://aurora-shield--PurvanshBhatt.replit.app/threats" });
  });

  btnReport.addEventListener("click", showReportConfirmation);

  backendUrlInput.addEventListener("change", saveBackendConfig);
  useMockInput.addEventListener("change", saveBackendConfig);
  loadBackendConfig();

  dashLink.addEventListener("click", e => {
    e.preventDefault();
    chrome.tabs.create({ url: "https://aurora-shield--PurvanshBhatt.replit.app/" });
  });
});

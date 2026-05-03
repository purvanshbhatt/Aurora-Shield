/**
 * AuroraShield Popup Script
 * Displays current page risk, session stats, and recent threats.
 */

const RISK_COLORS = {
  safe: "#22c55e",
  low: "#eab308",
  medium: "#f97316",
  high: "#ef4444",
  critical: "#ff2020",
};

function formatType(type) {
  return type.replace(/_/g, " ").toUpperCase();
}

function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ─── Update Risk Display ──────────────────────────────────────────────────
function updateRisk(riskLevel, riskScore) {
  const scoreEl = document.getElementById("riskScore");
  const levelEl = document.getElementById("riskLevel");
  const barEl = document.getElementById("riskBarFill");

  const pct = Math.round((riskScore || 0) * 100);
  scoreEl.textContent = pct + "%";
  levelEl.textContent = (riskLevel || "safe").toUpperCase();
  levelEl.className = `risk-level ${riskLevel || "safe"}`;
  scoreEl.style.color = RISK_COLORS[riskLevel] || RISK_COLORS.safe;

  barEl.style.width = pct + "%";
  barEl.style.background = RISK_COLORS[riskLevel] || RISK_COLORS.safe;
}

// ─── Update Stats ─────────────────────────────────────────────────────────
function updateStats(stats) {
  if (!stats) return;
  document.getElementById("totalScans").textContent = stats.totalScans ?? "--";
  document.getElementById("injections").textContent = stats.promptInjections ?? "--";
  document.getElementById("phishing").textContent = stats.phishingDetected ?? "--";
  document.getElementById("suspicious").textContent = stats.suspiciousUrls ?? "--";
}

// ─── Update Threat List ───────────────────────────────────────────────────
function updateThreats(threats) {
  const list = document.getElementById("threatList");

  if (!threats || threats.length === 0) {
    list.innerHTML = '<div class="empty">No threats detected</div>';
    return;
  }

  list.innerHTML = threats.slice(0, 5).map(t => `
    <div class="threat-item">
      <div class="threat-dot ${t.riskLevel}"></div>
      <div class="threat-info">
        <div class="threat-type">${formatType(t.type)}</div>
        <div class="threat-summary">${t.summary || t.context}</div>
      </div>
      <div class="threat-time">${timeAgo(t.detectedAt)}</div>
    </div>
  `).join("");
}

// ─── Load Data ────────────────────────────────────────────────────────────
async function loadData() {
  // Get current tab risk from storage
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    chrome.storage.local.get([`url_risk_${new URL(tab.url || "https://unknown").hostname}`], (result) => {
      const risk = Object.values(result)[0];
      if (risk) {
        updateRisk(risk.riskLevel, risk.riskScore);
      } else {
        updateRisk("safe", 0);
      }
    });
  }

  // Get stats from background
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (stats && !stats.error) updateStats(stats);
  });

  // Get recent threats from background
  chrome.runtime.sendMessage({ type: "GET_RECENT" }, (threats) => {
    if (threats && !threats.error) updateThreats(threats);
    else updateThreats([]);
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadData();

  document.getElementById("dashboardLink").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: "https://your-api-host.replit.app/" }); // Replace with your dashboard URL
  });
});

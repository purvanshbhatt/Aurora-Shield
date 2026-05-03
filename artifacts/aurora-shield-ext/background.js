/**
 * AuroraShield Background Service Worker
 * Handles API calls with caching and tab risk tracking.
 */

const DEFAULT_API_BASE = "https://aurora-shield--PurvanshBhatt.replit.app/api";

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

// ─── In-memory cache ──────────────────────────────────────────────────────
const promptCache = new Map();
const phishingCache = new Map();
const urlCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function hashKey(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return String(h);
}

function getCached(map, key) {
  const entry = map.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL) {
    map.delete(key);
    return null;
  }
  return entry.data;
}

function setCache(map, key, data) {
  map.set(key, { data, timestamp: Date.now() });
  if (map.size > 200) {
    const firstKey = map.keys().next().value;
    map.delete(firstKey);
  }
}

// ─── API Call Helper ──────────────────────────────────────────────────────
async function callApi(endpoint, body) {
  if (runtimeConfig.useMock) {
    return mockResponse(endpoint, body);
  }

  const response = await fetch(`${runtimeConfig.backendUrl}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`API error ${response.status}`);
  return response.json();
}

function mockResponse(endpoint, body) {
  if (endpoint === "/analyze/prompt") {
    return Promise.resolve({
      riskLevel: "high",
      riskScore: 0.78,
      category: "prompt_injection",
      explanation: "Instruction override pattern detected",
      patterns: ["ignore previous", "system prompt", "role override"],
    });
  }

  if (endpoint === "/analyze/phishing") {
    return Promise.resolve({
      riskLevel: "medium",
      riskScore: 0.66,
      category: "phishing",
      explanation: "Credential bait and urgency language detected",
      patterns: ["verify account", "password", "urgent action"],
    });
  }

  if (endpoint === "/analyze/url") {
    return Promise.resolve({
      overallRiskScore: 0.54,
      urlResults: [{ flags: ["typosquatting", "long URL"] }],
    });
  }

  if (endpoint === "/analyze/stats") {
    return Promise.resolve({
      totalScans: 12,
      promptInjections: 4,
      phishingDetected: 3,
      urlRisks: 5,
    });
  }

  if (endpoint === "/analyze/recent") {
    return Promise.resolve([
      { type: "prompt_injection", summary: "Instruction override detected", detectedAt: new Date().toISOString(), riskScore: 0.78 },
      { type: "phishing", summary: "Suspicious credential request", detectedAt: new Date(Date.now() - 8 * 60 * 1000).toISOString(), riskScore: 0.66 },
      { type: "suspicious_url", summary: "Suspicious URL pattern found", detectedAt: new Date(Date.now() - 17 * 60 * 1000).toISOString(), riskScore: 0.54 },
    ]);
  }

  return Promise.resolve({ error: "Unknown mock endpoint" });
}

// ─── Message Handler ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(err => sendResponse({ error: err.message }));
  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  const { type } = message;

  if (type === "ANALYZE_PROMPT") {
    const { text, context } = message;
    const key = hashKey(text.slice(0, 200));
    const cached = getCached(promptCache, key);
    if (cached) return { ...cached, cached: true };

    const result = await callApi("/analyze/prompt", { text, context });
    setCache(promptCache, key, result);

    // Update tab badge
    if (sender.tab?.id) updateTabBadge(sender.tab.id, result.riskLevel);

    return result;
  }

  if (type === "ANALYZE_PHISHING") {
    const { content, url } = message;
    const key = hashKey(content.slice(0, 300));
    const cached = getCached(phishingCache, key);
    if (cached) return { ...cached, cached: true };

    const result = await callApi("/analyze/phishing", { content, url });
    setCache(phishingCache, key, result);
    return result;
  }

  if (type === "ANALYZE_URLS") {
    const { urls, pageUrl } = message;
    const key = hashKey(urls.slice(0, 10).join(","));
    const cached = getCached(urlCache, key);
    if (cached) return { ...cached, cached: true };

    const result = await callApi("/analyze/url", { urls, pageUrl });
    setCache(urlCache, key, result);
    return result;
  }

  if (type === "GET_TAB_RISK") {
    const tabId = sender.tab?.id || message.tabId;
    const risk = tabRiskMap.get(tabId) || { riskLevel: "safe", riskScore: 0 };
    return risk;
  }

  if (type === "GET_STATS") {
    const response = await fetch(`${runtimeConfig.backendUrl}/analyze/stats`);
    return response.json();
  }

  if (type === "GET_RECENT") {
    const response = await fetch(`${runtimeConfig.backendUrl}/analyze/recent`);
    return response.json();
  }

  return { error: "Unknown message type" };
}

// ─── Tab Risk Badge ────────────────────────────────────────────────────────
const tabRiskMap = new Map();

const BADGE_COLORS = {
  safe: "#22c55e",
  low: "#eab308",
  medium: "#f97316",
  high: "#ef4444",
  critical: "#dc2626",
};

const BADGE_LABELS = {
  safe: "OK",
  low: "LOW",
  medium: "MED",
  high: "HIGH",
  critical: "!!!",
};

function updateTabBadge(tabId, riskLevel) {
  tabRiskMap.set(tabId, { riskLevel, timestamp: Date.now() });

  const color = BADGE_COLORS[riskLevel] || BADGE_COLORS.safe;
  const text = riskLevel !== "safe" ? BADGE_LABELS[riskLevel] || riskLevel.slice(0, 3).toUpperCase() : "";

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// Clean up on tab close
chrome.tabs.onRemoved.addListener(tabId => tabRiskMap.delete(tabId));

// Reset badge on navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ tabId, text: "" });
    tabRiskMap.delete(tabId);
  }
});

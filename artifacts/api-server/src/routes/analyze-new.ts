/**
 * Production-grade Analyze Route
 * Uses modular detection engines with deterministic scoring
 */

import { Router } from "express";
import { db } from "@workspace/db";
import { threatEventsTable } from "@workspace/db";
import { desc, eq, count } from "drizzle-orm";

// Import detection engines
import { detectPromptInjection } from "../detectors/promptInjection";
import { detectPhishing } from "../detectors/phishing";
import { analyzeURL, analyzeMultipleURLs } from "../detectors/urlAnalyzer";

// Import utilities
import {
  calculateUnifiedScore,
  getRiskLevel,
  getRecommendation,
} from "../utils/scoring";
import {
  validateAnalysisRequest,
  sanitizeOutput,
  extractURLsFromText,
  checkRateLimit,
} from "../utils/sanitizer";

const router = Router();

// ─── Simple in-memory cache with TTL ──────────────────────────────────────
const CACHE_TTL = 3600000; // 1 hour
const cache = new Map<
  string,
  { data: any; timestamp: number }
>();

function hashKey(str: string): string {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return String(Math.abs(h));
}

function getCachedResult(key: string): any | null {
  const cached = cache.get(key);
  if (!cached) return null;

  if (Date.now() - cached.timestamp > CACHE_TTL) {
    cache.delete(key);
    return null;
  }

  return cached.data;
}

function setCachedResult(key: string, data: any): void {
  cache.set(key, { data, timestamp: Date.now() });

  // Simple cache size management (keep under 1000 entries)
  if (cache.size > 1000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
}

// ─── Security-aware logging ───────────────────────────────────────────────
async function logThreatEvent(
  type: string,
  riskLevel: string,
  riskScore: number,
  summary: string,
  context: string
): Promise<void> {
  try {
    // Do not log actual sensitive content; only metadata
    await db.insert(threatEventsTable).values({
      type,
      riskLevel: riskLevel as any,
      riskScore,
      summary, // Summarized, not full content
      context: context.substring(0, 255), // Truncate context
    });
  } catch (err) {
    // Log database errors but don't expose to client
    console.error("Failed to log threat event:", err);
  }
}

// ─── Main Analysis Endpoint ────────────────────────────────────────────────
router.post("/", async (req, res) => {
  // Rate limiting check (use IP address as identifier)
  const clientIp = req.ip || "unknown";
  if (!checkRateLimit(clientIp, 120)) {
    return res.status(429).json({
      error: "Rate limit exceeded. Maximum 120 requests per minute.",
    });
  }

  // Validate and sanitize input
  const validation = validateAnalysisRequest(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { type, data } = validation.data!;
  const analysisType = type?.toLowerCase() || "prompt";

  // Determine analysis strategy
  if (analysisType === "prompt" || analysisType === "prompt_injection") {
    // ─── PROMPT INJECTION ANALYSIS ─────────────────────────────────────
    const cacheKey = `prompt:${hashKey(data)}`;
    const cached = getCachedResult(cacheKey);

    let promptResult = cached;
    let wasCached = false;

    if (!promptResult) {
      promptResult = detectPromptInjection(data);

      // Log if threat detected
      if (promptResult.risk_score > 30) {
        await logThreatEvent(
          "prompt_injection",
          getRiskLevel(promptResult.risk_score),
          promptResult.risk_score,
          `Detected ${promptResult.signals.length} patterns`,
          "extension"
        );
      }

      setCachedResult(cacheKey, promptResult);
    } else {
      wasCached = true;
    }

    return res.json({
      risk_score: Math.round(promptResult.risk_score),
      category: promptResult.category,
      explanation: promptResult.explanation,
      signals: sanitizeOutput(promptResult.signals),
      confidence: promptResult.confidence,
      cached: wasCached,
    });
  }

  if (analysisType === "phishing") {
    // ─── PHISHING ANALYSIS ────────────────────────────────────────────
    const cacheKey = `phishing:${hashKey(data.substring(0, 500))}`;
    const cached = getCachedResult(cacheKey);

    let phishingResult = cached;
    let wasCached = false;

    if (!phishingResult) {
      phishingResult = detectPhishing(data);

      // Log if threat detected
      if (phishingResult.risk_score > 30) {
        await logThreatEvent(
          "phishing",
          getRiskLevel(phishingResult.risk_score),
          phishingResult.risk_score,
          `Detected ${phishingResult.signals.length} indicators`,
          "extension"
        );
      }

      setCachedResult(cacheKey, phishingResult);
    } else {
      wasCached = true;
    }

    return res.json({
      risk_score: Math.round(phishingResult.risk_score),
      category: phishingResult.category,
      explanation: phishingResult.explanation,
      signals: sanitizeOutput(phishingResult.signals),
      confidence: phishingResult.confidence,
      cached: wasCached,
    });
  }

  if (analysisType === "url") {
    // ─── URL ANALYSIS ─────────────────────────────────────────────────
    // Parse URL list from data (can be JSON array or single URL)
    let urlList: string[] = [];

    try {
      if (data.startsWith("[")) {
        urlList = JSON.parse(data);
      } else {
        urlList = [data];
      }
    } catch {
      urlList = [data];
    }

    // Limit to 50 URLs
    if (urlList.length > 50) {
      return res.status(400).json({
        error: "Maximum 50 URLs per request",
      });
    }

    const cacheKey = `url:${hashKey(data.substring(0, 500))}`;
    const cached = getCachedResult(cacheKey);

    let urlAnalysis = cached;
    let wasCached = false;

    if (!urlAnalysis) {
      urlAnalysis = analyzeMultipleURLs(urlList);

      // Log if threats detected
      if (urlAnalysis.max_risk_score > 30) {
        const threatenedUrls = urlAnalysis.results.filter(
          r => r.risk_score > 50
        ).length;
        await logThreatEvent(
          "suspicious_url",
          getRiskLevel(urlAnalysis.max_risk_score),
          urlAnalysis.max_risk_score,
          `${threatenedUrls} suspicious URL(s)`,
          "extension"
        );
      }

      setCachedResult(cacheKey, urlAnalysis);
    } else {
      wasCached = true;
    }

    return res.json({
      risk_score: Math.round(urlAnalysis.max_risk_score),
      category: urlAnalysis.overall_category,
      results: sanitizeOutput(
        urlAnalysis.results.map(r => ({
          url: r.url,
          risk_score: Math.round(r.risk_score),
          category: r.category,
          signals: r.signals,
          parsed_domain: r.parsed_domain,
          subdomain_depth: r.subdomain_depth,
        }))
      ),
      cached: wasCached,
    });
  }

  return res.status(400).json({
    error: `Unknown analysis type: ${analysisType}`,
  });
});

// ─── Statistics Endpoint ──────────────────────────────────────────────────
router.get("/stats", async (_req, res) => {
  try {
    const [totalRow] = await db
      .select({ count: count() })
      .from(threatEventsTable);

    const [piRow] = await db
      .select({ count: count() })
      .from(threatEventsTable)
      .where(eq(threatEventsTable.type, "prompt_injection"));

    const [phRow] = await db
      .select({ count: count() })
      .from(threatEventsTable)
      .where(eq(threatEventsTable.type, "phishing"));

    const [urlRow] = await db
      .select({ count: count() })
      .from(threatEventsTable)
      .where(eq(threatEventsTable.type, "suspicious_url"));

    const levelCounts = await db
      .select({
        riskLevel: threatEventsTable.riskLevel,
        count: count(),
      })
      .from(threatEventsTable)
      .groupBy(threatEventsTable.riskLevel);

    const threatsByLevel: Record<string, number> = {
      safe: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    for (const row of levelCounts) {
      threatsByLevel[row.riskLevel] = Number(row.count);
    }

    return res.json({
      totalDetections: Number(totalRow.count),
      promptInjections: Number(piRow.count),
      phishingDetected: Number(phRow.count),
      suspiciousUrls: Number(urlRow.count),
      threatsByLevel,
      cacheSize: cache.size,
    });
  } catch (err) {
    console.error("Stats query error:", err);
    return res.status(500).json({ error: "Failed to fetch statistics" });
  }
});

// ─── Recent Events Endpoint ───────────────────────────────────────────────
router.get("/recent", async (_req, res) => {
  try {
    const events = await db
      .select()
      .from(threatEventsTable)
      .orderBy(desc(threatEventsTable.detectedAt))
      .limit(20);

    return res.json(
      events.map(e => ({
        id: e.id,
        type: e.type,
        riskLevel: e.riskLevel,
        riskScore: e.riskScore,
        summary: e.summary,
        context: e.context,
        detectedAt: e.detectedAt.toISOString(),
      }))
    );
  } catch (err) {
    console.error("Recent events query error:", err);
    return res.status(500).json({ error: "Failed to fetch recent events" });
  }
});

// ─── Health Check ─────────────────────────────────────────────────────────
router.get("/health", (_req, res) => {
  return res.json({
    status: "ok",
    version: "2.0.0",
    mode: "production",
    detectors: ["prompt_injection", "phishing", "url_analysis"],
  });
});

export default router;

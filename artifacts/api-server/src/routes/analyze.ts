import { Router } from "express";
import { db } from "@workspace/db";
import { threatEventsTable } from "@workspace/db";
import { desc, eq, count, sql } from "drizzle-orm";
import {
  AnalyzePromptBody,
  AnalyzePhishingBody,
  AnalyzeUrlBody,
} from "@workspace/api-zod";

const router = Router();

// ─── Prompt Injection Detection ────────────────────────────────────────────
const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)/i, label: "Ignore instructions" },
  { pattern: /you\s+are\s+now\s+(a|an)\s+/i, label: "Role override" },
  { pattern: /act\s+as\s+(a|an|if)\s+/i, label: "Act-as jailbreak" },
  { pattern: /disregard\s+(your|all|any)\s+/i, label: "Disregard directive" },
  { pattern: /pretend\s+(you|that|to)\s+/i, label: "Pretend directive" },
  { pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i, label: "Token injection" },
  { pattern: /do\s+not\s+(follow|obey|comply)\s+/i, label: "Compliance bypass" },
  { pattern: /override\s+(safety|filter|restriction|policy)/i, label: "Safety override" },
  { pattern: /reveal\s+(your\s+)?(system\s+)?prompt/i, label: "Prompt extraction" },
  { pattern: /jailbreak|DAN\s+mode|developer\s+mode/i, label: "Known jailbreak" },
  { pattern: /translate\s+everything\s+to|respond\s+only\s+in/i, label: "Output manipulation" },
  { pattern: /what\s+(are|were)\s+your\s+instructions/i, label: "Instruction probe" },
];

function detectPromptInjection(text: string) {
  const matched: string[] = [];
  for (const { pattern, label } of INJECTION_PATTERNS) {
    if (pattern.test(text)) matched.push(label);
  }
  const riskScore = Math.min(1, matched.length * 0.25 + (matched.length > 0 ? 0.1 : 0));
  let riskLevel: "safe" | "low" | "medium" | "high" | "critical";
  if (riskScore === 0) riskLevel = "safe";
  else if (riskScore < 0.3) riskLevel = "low";
  else if (riskScore < 0.5) riskLevel = "medium";
  else if (riskScore < 0.8) riskLevel = "high";
  else riskLevel = "critical";

  const recommendations: Record<string, string> = {
    safe: "No prompt injection patterns detected. Safe to proceed.",
    low: "Minor suspicious patterns found. Review before submission.",
    medium: "Moderate injection risk detected. Exercise caution.",
    high: "High risk of prompt injection. Do not submit to AI systems.",
    critical: "Critical injection attack detected. Block immediately.",
  };

  return { riskScore, riskLevel, patterns: matched, recommendation: recommendations[riskLevel] };
}

// ─── Phishing Detection ────────────────────────────────────────────────────
const PHISHING_PHRASES = [
  "verify your account", "confirm your identity", "update your payment",
  "your account has been suspended", "urgent action required", "click here to verify",
  "your password will expire", "unusual activity detected", "limited time offer",
  "act now", "you have been selected", "claim your reward", "free gift",
  "won a prize", "bank account", "social security", "wire transfer",
  "send money", "gift card", "bitcoin", "cryptocurrency payment",
  "login credentials", "enter your credentials", "reset your password immediately",
];

const PHISHING_INDICATORS = [
  { pattern: /https?:\/\/[a-z0-9-]+\.[a-z]{2,}\.[a-z]{2,}\//i, label: "Subdomain spoofing" },
  { pattern: /paypa1|g00gle|amaz0n|micros0ft|app1e/i, label: "Lookalike domain" },
  { pattern: /\b(account|password|ssn|credit.?card|bank)\b/i, label: "Sensitive data request" },
  { pattern: /click\s+(here|below|this\s+link)/i, label: "Urgency click" },
  { pattern: /expires?\s+in\s+\d+\s+(hour|minute|day)/i, label: "Urgency timer" },
  { pattern: /\$\d{3,}|\d{3,}\s*dollars?/i, label: "Large monetary mention" },
];

function detectPhishing(content: string) {
  const lower = content.toLowerCase();
  const foundPhrases = PHISHING_PHRASES.filter(p => lower.includes(p));
  const foundIndicators: string[] = [];
  for (const { pattern, label } of PHISHING_INDICATORS) {
    if (pattern.test(content)) foundIndicators.push(label);
  }

  const riskScore = Math.min(
    1,
    foundPhrases.length * 0.12 + foundIndicators.length * 0.2
  );
  let riskLevel: "safe" | "low" | "medium" | "high" | "critical";
  if (riskScore === 0) riskLevel = "safe";
  else if (riskScore < 0.25) riskLevel = "low";
  else if (riskScore < 0.5) riskLevel = "medium";
  else if (riskScore < 0.75) riskLevel = "high";
  else riskLevel = "critical";

  return { riskScore, riskLevel, suspiciousPhrases: foundPhrases.slice(0, 10), indicators: foundIndicators };
}

// ─── URL Analysis ──────────────────────────────────────────────────────────
const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, label: "Raw IP address" },
  { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|short\.link/i, label: "URL shortener" },
  { pattern: /[a-z0-9-]{25,}\./i, label: "Long subdomain" },
  { pattern: /paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k/i, label: "Lookalike brand" },
  { pattern: /login|signin|account|verify|secure|update|confirm/i, label: "Phishing keyword" },
  { pattern: /\.xyz$|\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/i, label: "Suspicious TLD" },
  { pattern: /@/, label: "At-sign in URL" },
  { pattern: /%[0-9a-f]{2}/i, label: "URL encoding" },
];

function analyzeUrl(url: string) {
  const flags: string[] = [];
  for (const { pattern, label } of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(url)) flags.push(label);
  }

  let domainLength = 0;
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    domainLength = parsed.hostname.length;
    if (domainLength > 30) flags.push("Long domain name");
  } catch {
    flags.push("Invalid URL format");
  }

  const riskScore = Math.min(1, flags.length * 0.2);
  return { url, riskScore, flags };
}

// ─── Simple in-memory cache ────────────────────────────────────────────────
const promptCache = new Map<string, ReturnType<typeof detectPromptInjection>>();
const phishingCache = new Map<string, ReturnType<typeof detectPhishing>>();
const urlCache = new Map<string, ReturnType<typeof analyzeUrl>>();

function hashKey(str: string) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return String(h);
}

// ─── Routes ────────────────────────────────────────────────────────────────
router.post("/prompt", async (req, res) => {
  const parse = AnalyzePromptBody.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid request body" });

  const { text, context } = parse.data;
  const key = hashKey(text);
  let result: ReturnType<typeof detectPromptInjection>;
  let cached = false;

  if (promptCache.has(key)) {
    result = promptCache.get(key)!;
    cached = true;
  } else {
    result = detectPromptInjection(text);
    promptCache.set(key, result);
    if (promptCache.size > 500) promptCache.delete(promptCache.keys().next().value!);

    if (result.riskLevel !== "safe") {
      await db.insert(threatEventsTable).values({
        type: "prompt_injection",
        riskLevel: result.riskLevel,
        riskScore: result.riskScore,
        summary: result.patterns.length > 0
          ? `Detected: ${result.patterns.slice(0, 3).join(", ")}`
          : "Prompt injection attempt",
        context: context ?? "unknown",
      });
    }
  }

  return res.json({ ...result, cached });
});

router.post("/phishing", async (req, res) => {
  const parse = AnalyzePhishingBody.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid request body" });

  const { content, url } = parse.data;
  const key = hashKey(content.slice(0, 500));
  let result: ReturnType<typeof detectPhishing>;
  let cached = false;

  if (phishingCache.has(key)) {
    result = phishingCache.get(key)!;
    cached = true;
  } else {
    result = detectPhishing(content);
    phishingCache.set(key, result);
    if (phishingCache.size > 500) phishingCache.delete(phishingCache.keys().next().value!);

    if (result.riskLevel !== "safe") {
      await db.insert(threatEventsTable).values({
        type: "phishing",
        riskLevel: result.riskLevel,
        riskScore: result.riskScore,
        summary: result.suspiciousPhrases.length > 0
          ? `Phrases: ${result.suspiciousPhrases.slice(0, 3).join(", ")}`
          : "Phishing content detected",
        context: url ?? "unknown",
      });
    }
  }

  return res.json({ ...result, cached });
});

router.post("/url", async (req, res) => {
  const parse = AnalyzeUrlBody.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid request body" });

  const { urls, pageUrl } = parse.data;
  const urlResults = urls.map(u => {
    const key = hashKey(u);
    if (urlCache.has(key)) return { ...urlCache.get(key)!, _cached: true };
    const r = analyzeUrl(u);
    urlCache.set(key, r);
    if (urlCache.size > 1000) urlCache.delete(urlCache.keys().next().value!);
    return r;
  });

  const overallRiskScore = urlResults.length > 0
    ? Math.max(...urlResults.map(r => r.riskScore))
    : 0;

  let riskLevel: "safe" | "low" | "medium" | "high" | "critical";
  if (overallRiskScore === 0) riskLevel = "safe";
  else if (overallRiskScore < 0.25) riskLevel = "low";
  else if (overallRiskScore < 0.5) riskLevel = "medium";
  else if (overallRiskScore < 0.75) riskLevel = "high";
  else riskLevel = "critical";

  const highRisk = urlResults.filter(r => r.riskScore > 0.3);
  if (highRisk.length > 0 && !urlResults.every(r => (r as any)._cached)) {
    await db.insert(threatEventsTable).values({
      type: "suspicious_url",
      riskLevel,
      riskScore: overallRiskScore,
      summary: `${highRisk.length} suspicious URL(s) detected`,
      context: pageUrl ?? "unknown",
    });
  }

  const cleanResults = urlResults.map(({ url, riskScore, flags }) => ({ url, riskScore, flags }));
  const cached = urlResults.some((r: any) => r._cached);

  return res.json({ overallRiskScore, riskLevel, urlResults: cleanResults, cached });
});

router.get("/stats", async (_req, res) => {
  const [totalRow] = await db.select({ count: count() }).from(threatEventsTable);
  const [piRow] = await db.select({ count: count() }).from(threatEventsTable)
    .where(eq(threatEventsTable.type, "prompt_injection"));
  const [phRow] = await db.select({ count: count() }).from(threatEventsTable)
    .where(eq(threatEventsTable.type, "phishing"));
  const [urlRow] = await db.select({ count: count() }).from(threatEventsTable)
    .where(eq(threatEventsTable.type, "suspicious_url"));

  const levelCounts = await db.select({
    riskLevel: threatEventsTable.riskLevel,
    count: count(),
  }).from(threatEventsTable).groupBy(threatEventsTable.riskLevel);

  const threatsByLevel = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const row of levelCounts) {
    threatsByLevel[row.riskLevel] = Number(row.count);
  }

  return res.json({
    totalScans: Number(totalRow.count) + promptCache.size + phishingCache.size + urlCache.size,
    promptInjections: Number(piRow.count),
    phishingDetected: Number(phRow.count),
    suspiciousUrls: Number(urlRow.count),
    threatsByLevel,
  });
});

router.get("/recent", async (_req, res) => {
  const events = await db.select().from(threatEventsTable)
    .orderBy(desc(threatEventsTable.detectedAt))
    .limit(20);

  return res.json(events.map(e => ({
    id: e.id,
    type: e.type,
    riskLevel: e.riskLevel,
    riskScore: e.riskScore,
    summary: e.summary,
    context: e.context,
    detectedAt: e.detectedAt.toISOString(),
  })));
});

// ─── Unified /analyze endpoint (extension-compatible format) ───────────────
// Accepts: { type: "prompt" | "phishing" | "url", data: string }
// Returns: { risk_score: 0-100, category: string, explanation: string }
router.post("/", async (req, res) => {
  const { type, data } = req.body as { type?: string; data?: string };

  if (!data || typeof data !== "string") {
    return res.status(400).json({ error: "Missing required field: data (string)" });
  }

  const analysisType = type ?? "prompt";

  if (analysisType === "prompt" || analysisType === "prompt_injection") {
    const key = hashKey(data);
    let result: ReturnType<typeof detectPromptInjection>;
    let wasCached = false;

    if (promptCache.has(key)) {
      result = promptCache.get(key)!;
      wasCached = true;
    } else {
      result = detectPromptInjection(data);
      promptCache.set(key, result);
      if (promptCache.size > 500) promptCache.delete(promptCache.keys().next().value!);

      if (result.riskLevel !== "safe") {
        await db.insert(threatEventsTable).values({
          type: "prompt_injection",
          riskLevel: result.riskLevel,
          riskScore: result.riskScore,
          summary: result.patterns.length > 0
            ? `Detected: ${result.patterns.slice(0, 3).join(", ")}`
            : "Prompt injection attempt",
          context: "extension",
        });
      }
    }

    const riskScore = Math.round(result.riskScore * 100);
    const categories: Record<string, string> = {
      safe: "safe",
      low: "prompt_injection",
      medium: "prompt_injection",
      high: "prompt_injection",
      critical: "prompt_injection",
    };

    return res.json({
      risk_score: riskScore,
      category: categories[result.riskLevel] ?? "prompt_injection",
      explanation: result.recommendation,
      patterns: result.patterns,
      risk_level: result.riskLevel,
      cached: wasCached,
    });
  }

  if (analysisType === "phishing") {
    const key = hashKey(data.slice(0, 500));
    let result: ReturnType<typeof detectPhishing>;
    let wasCached = false;

    if (phishingCache.has(key)) {
      result = phishingCache.get(key)!;
      wasCached = true;
    } else {
      result = detectPhishing(data);
      phishingCache.set(key, result);
      if (phishingCache.size > 500) phishingCache.delete(phishingCache.keys().next().value!);

      if (result.riskLevel !== "safe") {
        await db.insert(threatEventsTable).values({
          type: "phishing",
          riskLevel: result.riskLevel,
          riskScore: result.riskScore,
          summary: result.suspiciousPhrases.length > 0
            ? `Phrases: ${result.suspiciousPhrases.slice(0, 3).join(", ")}`
            : "Phishing content detected",
          context: "extension",
        });
      }
    }

    const riskScore = Math.round(result.riskScore * 100);
    const explanation = result.suspiciousPhrases.length > 0
      ? `Phishing indicators: ${result.suspiciousPhrases.slice(0, 3).join(", ")}`
      : result.indicators.length > 0
        ? `Detected: ${result.indicators.slice(0, 3).join(", ")}`
        : "No phishing indicators found.";

    return res.json({
      risk_score: riskScore,
      category: result.riskLevel === "safe" ? "safe" : "phishing",
      explanation,
      suspicious_phrases: result.suspiciousPhrases,
      indicators: result.indicators,
      risk_level: result.riskLevel,
      cached: wasCached,
    });
  }

  if (analysisType === "url") {
    const urlList = data.startsWith("[")
      ? (JSON.parse(data) as string[])
      : [data];

    const urlResults = urlList.map(u => {
      const key = hashKey(u);
      if (urlCache.has(key)) return { ...urlCache.get(key)!, _cached: true };
      const r = analyzeUrl(u);
      urlCache.set(key, r);
      if (urlCache.size > 1000) urlCache.delete(urlCache.keys().next().value!);
      return r;
    });

    const overallScore = urlResults.length > 0
      ? Math.max(...urlResults.map(r => r.riskScore))
      : 0;

    let riskLevel: "safe" | "low" | "medium" | "high" | "critical";
    if (overallScore === 0) riskLevel = "safe";
    else if (overallScore < 0.25) riskLevel = "low";
    else if (overallScore < 0.5) riskLevel = "medium";
    else if (overallScore < 0.75) riskLevel = "high";
    else riskLevel = "critical";

    const highRisk = urlResults.filter(r => r.riskScore > 0.3);
    if (highRisk.length > 0 && !urlResults.every(r => (r as any)._cached)) {
      await db.insert(threatEventsTable).values({
        type: "suspicious_url",
        riskLevel,
        riskScore: overallScore,
        summary: `${highRisk.length} suspicious URL(s) detected`,
        context: "extension",
      });
    }

    const topFlags = urlResults.flatMap(r => r.flags).slice(0, 3);
    const explanation = topFlags.length > 0
      ? `Suspicious patterns: ${topFlags.join(", ")}`
      : "No suspicious URL patterns found.";

    return res.json({
      risk_score: Math.round(overallScore * 100),
      category: riskLevel === "safe" ? "safe" : "suspicious_url",
      explanation,
      url_results: urlResults.map(({ url, riskScore, flags }) => ({ url, riskScore, flags })),
      risk_level: riskLevel,
    });
  }

  return res.status(400).json({ error: `Unknown analysis type: ${analysisType}. Use "prompt", "phishing", or "url".` });
});

export default router;

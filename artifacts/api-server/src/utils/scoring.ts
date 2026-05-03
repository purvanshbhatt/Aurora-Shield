/**
 * Unified Deterministic Scoring Model
 * Combines multiple threat signals into a single risk score (0-100)
 */

export interface ThreatSignals {
  promptInjectionScore: number;
  phishingScore: number;
  urlScore: number;
  signalCount: number;
}

export interface UnifiedRiskScore {
  risk_score: number;
  category: "safe" | "threat";
  primary_threat: "prompt_injection" | "phishing" | "suspicious_url" | "none";
  signals: string[];
  confidence: number;
}

interface ScoringWeights {
  promptInjection: number;
  phishing: number;
  url: number;
}

const DEFAULT_WEIGHTS: ScoringWeights = {
  promptInjection: 0.4, // 40% weight
  phishing: 0.35,       // 35% weight
  url: 0.25,            // 25% weight
};

/**
 * Normalize individual detector scores (0-100) to weighted contribution
 */
export function calculateUnifiedScore(
  promptInjectionScore: number,
  phishingScore: number,
  urlScore: number,
  weights: ScoringWeights = DEFAULT_WEIGHTS
): UnifiedRiskScore {
  // Normalize scores to 0-1 range
  const normPi = promptInjectionScore / 100;
  const normPhish = phishingScore / 100;
  const normUrl = urlScore / 100;

  // Weighted sum
  const weightedSum =
    normPi * weights.promptInjection +
    normPhish * weights.phishing +
    normUrl * weights.url;

  // Scale back to 0-100
  const unifiedScore = Math.round(weightedSum * 100);

  // Determine primary threat and signals
  const scores = [
    { type: "prompt_injection", score: promptInjectionScore },
    { type: "phishing", score: phishingScore },
    { type: "suspicious_url", score: urlScore },
  ];

  const primaryThreat = scores.reduce((max, current) =>
    current.score > max.score ? current : max
  );

  const signals: string[] = [];
  if (promptInjectionScore > 30) signals.push("prompt_injection_detected");
  if (phishingScore > 30) signals.push("phishing_detected");
  if (urlScore > 30) signals.push("suspicious_url_detected");

  // Confidence: higher when signals align or concentration is strong
  const nonZeroScores = [promptInjectionScore, phishingScore, urlScore].filter(
    s => s > 0
  ).length;
  let confidence = 0.7;
  if (nonZeroScores === 0) confidence = 0.95; // High confidence in "safe"
  if (nonZeroScores >= 2) confidence = Math.min(0.95, 0.7 + nonZeroScores * 0.1);

  return {
    risk_score: unifiedScore,
    category: unifiedScore > 50 ? "threat" : "safe",
    primary_threat: (primaryThreat.type as any) || "none",
    signals,
    confidence,
  };
}

/**
 * Determine risk severity level based on score
 */
export function getRiskLevel(
  riskScore: number
): "safe" | "low" | "medium" | "high" | "critical" {
  if (riskScore === 0) return "safe";
  if (riskScore < 25) return "low";
  if (riskScore < 50) return "medium";
  if (riskScore < 75) return "high";
  return "critical";
}

/**
 * Get recommendation based on risk level
 */
export function getRecommendation(riskLevel: string): string {
  const recommendations: Record<string, string> = {
    safe: "Content appears safe. Proceed normally.",
    low: "Minor suspicious indicators detected. Exercise light caution.",
    medium: "Moderate risk indicators present. Review carefully before proceeding.",
    high: "High risk indicators detected. Do not proceed without verification.",
    critical: "Critical threat detected. Do not engage with this content.",
  };
  return recommendations[riskLevel] || "Unable to determine risk level.";
}

/**
 * Format a human-readable threat report
 */
export function formatThreatReport(
  score: UnifiedRiskScore,
  detailedSignals?: Record<string, any>
): string {
  const level = getRiskLevel(score.risk_score);
  const recommendation = getRecommendation(level);

  let report = `Risk Score: ${score.risk_score}/100 (${level.toUpperCase()})\n`;
  report += `Category: ${score.primary_threat.replace(/_/g, " ").toUpperCase()}\n`;

  if (score.signals.length > 0) {
    report += `Detected Signals: ${score.signals.join(", ")}\n`;
  }

  report += `Confidence: ${(score.confidence * 100).toFixed(0)}%\n`;
  report += `Recommendation: ${recommendation}`;

  return report;
}

/**
 * Production-grade Phishing Detection
 * Detects: credential harvesting, urgent language, deception patterns, social engineering
 */

interface PhishingSignal {
  category: "credential_request" | "urgency" | "deception" | "social_engineering" | "suspicious_content";
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  count: number;
}

interface PhishingResult {
  signals: PhishingSignal[];
  risk_score: number;
  category: "safe" | "phishing";
  explanation: string;
  confidence: number;
}

// Credential harvesting indicators
const CREDENTIAL_PATTERNS = [
  {
    pattern: /(?:verify|confirm|validate|update|reset)\s+(?:your\s+)?(password|credentials?|account|identity|username)/i,
    category: "credential_request" as const,
    severity: "critical" as const,
    name: "Password/credential request",
  },
  {
    pattern: /(enter|provide|submit|input).*?(password|pin|security\s+code|2fa|totp)/i,
    category: "credential_request" as const,
    severity: "critical" as const,
    name: "Credential input solicitation",
  },
  {
    pattern: /(social\s+)?security\s+(number|ssn)|credit\s+card|card\s+number|cvv/i,
    category: "credential_request" as const,
    severity: "critical" as const,
    name: "Sensitive personal data request",
  },
  {
    pattern: /bank\s+account|routing\s+number|swift|iban/i,
    category: "credential_request" as const,
    severity: "critical" as const,
    name: "Banking credential request",
  },
];

// Urgency and pressure tactics
const URGENCY_PATTERNS = [
  {
    pattern: /urgent\s+action\s+required/i,
    category: "urgency" as const,
    severity: "high" as const,
    name: "Urgent action demand",
  },
  {
    pattern: /act\s+now|immediate(ly)?|immediately|within\s+(?:24\s+)?hours?/i,
    category: "urgency" as const,
    severity: "high" as const,
    name: "Time pressure tactic",
  },
  {
    pattern: /limited\s+time\s+offer|expires?\s+(?:in|on)\s+/i,
    category: "urgency" as const,
    severity: "medium" as const,
    name: "Expiration deadline",
  },
  {
    pattern: /(?:your\s+)?account.*?(?:suspend|lock|close|deactivate|disabled)/i,
    category: "urgency" as const,
    severity: "high" as const,
    name: "Account suspension threat",
  },
  {
    pattern: /unusual\s+activity|suspicious\s+(?:access|login)|unrecognized\s+(?:device|location)/i,
    category: "urgency" as const,
    severity: "high" as const,
    name: "Suspicious activity alert",
  },
];

// Deception and impersonation
const DECEPTION_PATTERNS = [
  {
    pattern: /(?:verify|confirm)\s+(?:your\s+)?(?:account|identity)/i,
    category: "deception" as const,
    severity: "high" as const,
    name: "Account verification deception",
  },
  {
    pattern: /(?:click|tap)\s+(?:here|below|link|button).*?(?:verify|confirm|authenticate)/i,
    category: "deception" as const,
    severity: "high" as const,
    name: "Deceptive link/button",
  },
  {
    pattern: /confirm\s+(?:your\s+)?payment|update.*?payment\s+method/i,
    category: "deception" as const,
    severity: "high" as const,
    name: "Payment verification deception",
  },
];

// Social engineering
const SOCIAL_ENGINEERING_PATTERNS = [
  {
    pattern: /you\s+(?:have\s+)?(?:won|earned|claim).*?(?:prize|reward|gift|refund)/i,
    category: "social_engineering" as const,
    severity: "high" as const,
    name: "Prize/reward scam",
  },
  {
    pattern: /you\s+(?:have\s+)?been\s+selected|congratulations|lucky\s+winner/i,
    category: "social_engineering" as const,
    severity: "high" as const,
    name: "Selection scam",
  },
  {
    pattern: /(?:refund|compensation|settlement)\s+(?:awaiting|pending|owed|due)/i,
    category: "social_engineering" as const,
    severity: "medium" as const,
    name: "Refund/compensation scam",
  },
  {
    pattern: /claim\s+(?:your|free).*?(?:gift|voucher|coupon|credit)/i,
    category: "social_engineering" as const,
    severity: "medium" as const,
    name: "Free offer scam",
  },
  {
    pattern: /(?:inheritance|lottery|bank)\s+(?:notification|transfer|deposit)/i,
    category: "social_engineering" as const,
    severity: "high" as const,
    name: "Money transfer scam",
  },
];

// Suspicious content
const SUSPICIOUS_CONTENT_PATTERNS = [
  {
    pattern: /(?:wire|transfer|send)\s+(?:money|funds|payment|bitcoin|cryptocurrency)/i,
    category: "suspicious_content" as const,
    severity: "critical" as const,
    name: "Money transfer request",
  },
  {
    pattern: /(?:buy|purchase|invest)\s+(?:bitcoin|cryptocurrency|gift\s+card|itunes)/i,
    category: "suspicious_content" as const,
    severity: "high" as const,
    name: "Suspicious purchase request",
  },
  {
    pattern: /for\s+(?:free|no\s+cost|zero\s+charge)/i,
    category: "suspicious_content" as const,
    severity: "low" as const,
    name: "Free offer",
  },
];

interface PhishingPatternConfig {
  pattern: RegExp;
  category: PhishingSignal["category"];
  severity: PhishingSignal["severity"];
  name: string;
}

const allPatterns: PhishingPatternConfig[] = [
  ...CREDENTIAL_PATTERNS,
  ...URGENCY_PATTERNS,
  ...DECEPTION_PATTERNS,
  ...SOCIAL_ENGINEERING_PATTERNS,
  ...SUSPICIOUS_CONTENT_PATTERNS,
];

function detectPhishingPatterns(text: string): PhishingSignal[] {
  const signals: Map<string, PhishingSignal> = new Map();

  for (const { pattern, category, severity, name } of allPatterns) {
    const matches = text.match(pattern);
    if (matches) {
      const key = `${category}:${name}`;
      if (!signals.has(key)) {
        signals.set(key, {
          category,
          name,
          severity,
          count: 0,
        });
      }

      signals.get(key)!.count += matches.length;
    }
  }

  return Array.from(signals.values());
}

function calculatePhishingScore(signals: PhishingSignal[]): number {
  const severityWeights: Record<string, number> = {
    low: 10,
    medium: 25,
    high: 50,
    critical: 100,
  };

  let score = 0;
  const categoryMultipliers: Record<PhishingSignal["category"], number> = {
    credential_request: 2.0,
    urgency: 1.5,
    social_engineering: 1.8,
    deception: 1.6,
    suspicious_content: 1.3,
  };

  for (const signal of signals) {
    const baseScore = severityWeights[signal.severity];
    const multiplier = categoryMultipliers[signal.category];
    score += (baseScore * multiplier) / 100;
  }

  return Math.min(100, score);
}

function assessPhishingConfidence(signals: PhishingSignal[], score: number): number {
  if (signals.length === 0) return 1.0;
  
  const criticalSignals = signals.filter(s => s.severity === "critical");
  const credentialSignals = signals.filter(s => s.category === "credential_request");

  if (criticalSignals.length > 0 || credentialSignals.length > 0) {
    return 0.95;
  }

  if (signals.length >= 3) return 0.85;
  if (signals.length === 2) return 0.75;
  return 0.6;
}

export function detectPhishing(text: string): PhishingResult {
  if (!text || text.trim().length === 0) {
    return {
      signals: [],
      risk_score: 0,
      category: "safe",
      explanation: "Input is empty or whitespace only.",
      confidence: 1.0,
    };
  }

  const signals = detectPhishingPatterns(text);
  const riskScore = calculatePhishingScore(signals);
  const confidence = assessPhishingConfidence(signals, riskScore);

  if (signals.length === 0) {
    return {
      signals: [],
      risk_score: 0,
      category: "safe",
      explanation: "No phishing indicators detected. Content appears legitimate.",
      confidence: 1.0,
    };
  }

  const credentialSignals = signals.filter(s => s.category === "credential_request");
  const urgencySignals = signals.filter(s => s.category === "urgency");

  let explanation = `Detected ${signals.length} phishing indicator(s): `;
  if (credentialSignals.length > 0) {
    explanation += `${credentialSignals.map(s => s.name).join(", ")} [CRITICAL]. `;
  }
  if (urgencySignals.length > 0) {
    explanation += `${urgencySignals.map(s => s.name).join(", ")} [HIGH]. `;
  }
  explanation += "Be cautious and verify sender authenticity.";

  return {
    signals,
    risk_score: riskScore,
    category: "phishing",
    explanation,
    confidence,
  };
}

/**
 * Production-grade Prompt Injection Detection
 * Detects: instruction overrides, role-play attacks, prompt extraction, jailbreaks
 */

interface DetectionSignal {
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  count: number;
  examples: string[];
}

interface PromptInjectionResult {
  signals: DetectionSignal[];
  risk_score: number;
  category: "safe" | "prompt_injection";
  explanation: string;
  confidence: number;
}

// Categorized patterns with severity levels
const INSTRUCTION_OVERRIDE_PATTERNS = [
  {
    pattern: /ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context|rules)/i,
    severity: "critical" as const,
    name: "Ignore instructions directive",
  },
  {
    pattern: /disregard\s+(your|all|any)\s+(instructions?|rules|guidelines|policy)/i,
    severity: "critical" as const,
    name: "Disregard directive",
  },
  {
    pattern: /forget\s+(everything|all)\s+(previous|before|above)/i,
    severity: "high" as const,
    name: "Forget previous context",
  },
  {
    pattern: /no\s+longer\s+follow/i,
    severity: "high" as const,
    name: "No longer follow rules",
  },
];

const ROLE_PLAY_JAILBREAK_PATTERNS = [
  {
    pattern: /you\s+are\s+now\s+(a|an|the)\s+(?!an\s+ai|a\s+language|a\s+helpful)/i,
    severity: "high" as const,
    name: "Role override attempt",
  },
  {
    pattern: /act\s+as\s+(if\s+)?(?!an\s+ai|a\s+helpful|a\s+responsible)/i,
    severity: "high" as const,
    name: "Act-as jailbreak",
  },
  {
    pattern: /pretend\s+(you|that|to)\s+(?!know|understand|have)/i,
    severity: "medium" as const,
    name: "Pretend directive",
  },
  {
    pattern: /imagine\s+you\s+are/i,
    severity: "medium" as const,
    name: "Imagination directive",
  },
  {
    pattern: /(DAN\s+mode|developer\s+mode|god\s+mode|unrestricted\s+mode)/i,
    severity: "critical" as const,
    name: "Known jailbreak pattern",
  },
];

const PROMPT_EXTRACTION_PATTERNS = [
  {
    pattern: /reveal\s+(your\s+)?(system\s+)?prompt/i,
    severity: "critical" as const,
    name: "System prompt extraction",
  },
  {
    pattern: /what\s+(are|were)\s+your\s+(original|system|hidden|secret)\s+instructions?/i,
    severity: "high" as const,
    name: "Instruction probe",
  },
  {
    pattern: /show\s+me\s+the\s+(prompt|instructions?|original\s+message)/i,
    severity: "high" as const,
    name: "Prompt display request",
  },
  {
    pattern: /echo\s+(the\s+)?prompt/i,
    severity: "high" as const,
    name: "Prompt echo request",
  },
];

const TOKEN_INJECTION_PATTERNS = [
  {
    pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>/i,
    severity: "critical" as const,
    name: "Model token injection",
  },
  {
    pattern: /{{.*?}}|{%.*?%}|<%.*?%>/,
    severity: "high" as const,
    name: "Template injection syntax",
  },
];

const SAFETY_BYPASS_PATTERNS = [
  {
    pattern: /override\s+(safety|filter|restriction|policy|safeguard|ethical\s+guideline)/i,
    severity: "critical" as const,
    name: "Safety override request",
  },
  {
    pattern: /disable\s+(content\s+)?filter/i,
    severity: "high" as const,
    name: "Filter disable request",
  },
  {
    pattern: /ignore\s+(ethical|safety|usage|policy)\s+guideline/i,
    severity: "high" as const,
    name: "Guideline bypass",
  },
  {
    pattern: /do\s+not\s+(follow|obey|comply|check)\s+(?!this\s+rule)/i,
    severity: "medium" as const,
    name: "Compliance bypass",
  },
];

const OUTPUT_MANIPULATION_PATTERNS = [
  {
    pattern: /respond\s+(only\s+)?(in\s+)?code|return\s+(only\s+)?code/i,
    severity: "medium" as const,
    name: "Output format manipulation",
  },
  {
    pattern: /translate\s+everything\s+to/i,
    severity: "low" as const,
    name: "Translation directive",
  },
  {
    pattern: /use\s+(only\s+)?rot13|base64|cipher/i,
    severity: "medium" as const,
    name: "Encoding directive",
  },
];

interface PatternConfig {
  pattern: RegExp;
  severity: "low" | "medium" | "high" | "critical";
  name: string;
}

const allPatterns: PatternConfig[] = [
  ...INSTRUCTION_OVERRIDE_PATTERNS,
  ...ROLE_PLAY_JAILBREAK_PATTERNS,
  ...PROMPT_EXTRACTION_PATTERNS,
  ...TOKEN_INJECTION_PATTERNS,
  ...SAFETY_BYPASS_PATTERNS,
  ...OUTPUT_MANIPULATION_PATTERNS,
];

function detectPatterns(text: string): DetectionSignal[] {
  const signals: Map<string, DetectionSignal> = new Map();

  for (const { pattern, severity, name } of allPatterns) {
    const matches = text.match(pattern);
    if (matches) {
      if (!signals.has(name)) {
        signals.set(name, {
          name,
          severity,
          count: 0,
          examples: [],
        });
      }

      const signal = signals.get(name)!;
      signal.count += matches.length;
      // Store first few examples (redacted for privacy)
      if (signal.examples.length < 2) {
        signal.examples.push(matches[0].substring(0, 50));
      }
    }
  }

  return Array.from(signals.values());
}

function calculateSeverityScore(signals: DetectionSignal[]): number {
  const severityWeights: Record<string, number> = {
    low: 0.1,
    medium: 0.3,
    high: 0.6,
    critical: 1.0,
  };

  let totalScore = 0;
  for (const signal of signals) {
    totalScore += severityWeights[signal.severity] * Math.log(signal.count + 1);
  }

  // Cap at 100
  return Math.min(100, totalScore);
}

function assessConfidence(signals: DetectionSignal[], riskScore: number): number {
  if (signals.length === 0) return 1.0; // High confidence in "safe"
  if (signals.length >= 3) return 0.95; // Multiple signals = high confidence
  if (signals.some(s => s.severity === "critical")) return 0.9;
  if (signals.some(s => s.severity === "high")) return 0.8;
  return 0.6; // Lower confidence for low/medium signals
}

export function detectPromptInjection(text: string): PromptInjectionResult {
  // Early exit for empty input
  if (!text || text.trim().length === 0) {
    return {
      signals: [],
      risk_score: 0,
      category: "safe",
      explanation: "Input is empty or whitespace only.",
      confidence: 1.0,
    };
  }

  const signals = detectPatterns(text);
  const riskScore = calculateSeverityScore(signals);
  const confidence = assessConfidence(signals, riskScore);

  if (signals.length === 0) {
    return {
      signals: [],
      risk_score: 0,
      category: "safe",
      explanation: "No prompt injection patterns detected. Safe to proceed.",
      confidence: 1.0,
    };
  }

  const criticalSignals = signals.filter(s => s.severity === "critical");
  const highSignals = signals.filter(s => s.severity === "high");

  let explanation = `Detected ${signals.length} injection pattern(s): `;
  if (criticalSignals.length > 0) {
    explanation += `${criticalSignals.map(s => s.name).join(", ")} [CRITICAL]. `;
  }
  if (highSignals.length > 0) {
    explanation += `${highSignals.map(s => s.name).join(", ")} [HIGH]. `;
  }
  explanation += "Do not submit to AI systems.";

  return {
    signals,
    risk_score: riskScore,
    category: "prompt_injection",
    explanation,
    confidence,
  };
}

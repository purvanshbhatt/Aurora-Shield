/**
 * Production-grade URL Analysis Engine
 * Detects: typosquatting, IP-based URLs, suspicious TLDs, encoding tricks, domain analysis
 */

interface URLSignal {
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

interface URLAnalysisResult {
  url: string;
  signals: URLSignal[];
  risk_score: number;
  category: "safe" | "suspicious";
  explanation: string;
  confidence: number;
  parsed_domain?: string;
  subdomain_depth?: number;
  entropy_score?: number;
}

// Common suspicious TLDs used in phishing/malware
const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", // Free TLDs
  "xyz", "download", "stream", "review",
  "webcam", "work", "trade", "racing",
  "click", "date", "faith", "win",
]);

// Common brand names for typosquatting
const COMMON_BRANDS = new Map([
  ["google", ["gogle", "goggle", "gogle", "g00gle", "goog1e"]],
  ["paypal", ["paypa1", "paypa|", "paypa7", "paypai"]],
  ["amazon", ["amaz0n", "amazno", "amaozn"]],
  ["apple", ["app1e", "aple", "appl3"]],
  ["facebook", ["faceb00k", "faceb0ok", "facebook"]],
  ["microsoft", ["m1crosoft", "microso7t"]],
  ["bank", ["b4nk", "bank"]],
  ["paypa1", ["paypal"]],
]);

function calculateEntropy(domain: string): number {
  const chars = new Set(domain.split(""));
  const uniqueChars = chars.size;
  const domainLength = domain.length;
  
  // Entropy-like score: high char diversity relative to length = suspicious
  const entropy = (uniqueChars / domainLength) * 100;
  
  // Penalize for numbers and special chars (more common in malicious domains)
  const numberCount = (domain.match(/\d/g) || []).length;
  const specialCount = (domain.match(/[-_]/g) || []).length;
  
  return Math.min(100, entropy + (numberCount * 5) + (specialCount * 3));
}

function checkTyposquatting(domain: string): URLSignal | null {
  const domainLower = domain.toLowerCase();
  
  for (const [brand, typos] of COMMON_BRANDS) {
    for (const typo of typos) {
      if (domainLower.includes(typo) && domainLower !== brand) {
        return {
          name: "Possible typosquatting",
          severity: "high",
          description: `Domain resembles '${brand}' but has suspicious variations`,
        };
      }
    }
  }
  
  return null;
}

function analyzeSubdomains(hostname: string): { depth: number; suspicious: boolean } {
  const parts = hostname.split(".");
  const depth = parts.length;
  
  // More than 3 subdomains is suspicious
  const isSuspicious = depth > 3;
  
  return { depth, suspicious: isSuspicious };
}

function detectIPAddress(hostname: string): URLSignal | null {
  // IPv4 pattern
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    const octets = hostname.split(".").map(Number);
    
    // Check for private IP ranges
    if (octets[0] === 192 || octets[0] === 172 || octets[0] === 10) {
      return {
        name: "Private IP address",
        severity: "medium",
        description: "Domain uses private/internal IP address",
      };
    }
    
    return {
      name: "Raw IP address",
      severity: "high",
      description: "Domain uses raw IPv4 address instead of hostname",
    };
  }
  
  // IPv6 pattern (simplified)
  if (hostname.includes(":") && /^[a-f0-9:]+$/.test(hostname)) {
    return {
      name: "IPv6 address",
      severity: "medium",
      description: "Domain uses IPv6 address",
    };
  }
  
  return null;
}

function detectURLEncoding(url: string): URLSignal | null {
  if (/%[0-9a-f]{2}/i.test(url)) {
    return {
      name: "URL encoded characters",
      severity: "high",
      description: "Domain contains URL-encoded characters (obfuscation)",
    };
  }
  return null;
}

function detectPunycodeAttacks(hostname: string): URLSignal | null {
  if (hostname.startsWith("xn--")) {
    return {
      name: "Punycode domain",
      severity: "medium",
      description: "Domain uses Punycode encoding (may hide Unicode characters)",
    };
  }
  return null;
}

function detectURLShortener(url: string): URLSignal | null {
  const shortenerPatterns = [
    /bit\.ly|tinyurl|t\.co|goo\.gl|short\.link|ow\.ly|adf\.ly|clickbait/i,
  ];
  
  for (const pattern of shortenerPatterns) {
    if (pattern.test(url)) {
      return {
        name: "URL shortener detected",
        severity: "medium",
        description: "Shortened URL hides true destination",
      };
    }
  }
  
  return null;
}

function detectAtSymbol(url: string): URLSignal | null {
  // Check for @ symbol in authority section (before /)
  const authMatch = url.match(/^https?:\/\/([^\/]+)/);
  if (authMatch && authMatch[1].includes("@")) {
    return {
      name: "@ symbol in URL",
      severity: "high",
      description: "URL contains @ symbol (may hide actual domain)",
    };
  }
  return null;
}

function checkSuspiciousTLD(hostname: string): URLSignal | null {
  const parts = hostname.split(".");
  const tld = parts[parts.length - 1].toLowerCase();
  
  if (SUSPICIOUS_TLDS.has(tld)) {
    return {
      name: "Suspicious TLD",
      severity: "medium",
      description: `Domain uses suspicious TLD: .${tld}`,
    };
  }
  
  return null;
}

function detectPortHiding(url: string): URLSignal | null {
  // Unusual ports that might hide phishing
  const suspiciousPorts = [8080, 8888, 3000, 5000, 9090];
  
  for (const port of suspiciousPorts) {
    if (url.includes(`:${port}`)) {
      return {
        name: "Non-standard port",
        severity: "low",
        description: `Uses non-standard port ${port}`,
      };
    }
  }
  
  return null;
}

export function analyzeURL(urlString: string): URLAnalysisResult {
  const signals: URLSignal[] = [];
  
  // Validate URL format
  let parsed: URL;
  try {
    parsed = new URL(urlString.startsWith("http") ? urlString : `https://${urlString}`);
  } catch {
    return {
      url: urlString,
      signals: [{
        name: "Invalid URL format",
        severity: "high",
        description: "URL is malformed or cannot be parsed",
      }],
      risk_score: 60,
      category: "suspicious",
      explanation: "Invalid URL format detected. Could not analyze for security threats.",
      confidence: 0.9,
    };
  }

  const hostname = parsed.hostname || "";
  const protocol = parsed.protocol;

  // Protocol checks
  if (protocol !== "http:" && protocol !== "https:") {
    signals.push({
      name: "Non-HTTP protocol",
      severity: "medium",
      description: `Uses ${protocol.slice(0, -1)} protocol`,
    });
  }

  if (protocol === "http:") {
    signals.push({
      name: "Unencrypted connection",
      severity: "medium",
      description: "HTTP (unencrypted) instead of HTTPS",
    });
  }

  // IP address check
  const ipSignal = detectIPAddress(hostname);
  if (ipSignal) signals.push(ipSignal);

  // URL encoding check
  const encodingSignal = detectURLEncoding(urlString);
  if (encodingSignal) signals.push(encodingSignal);

  // Punycode check
  const punycodeSignal = detectPunycodeAttacks(hostname);
  if (punycodeSignal) signals.push(punycodeSignal);

  // URL shortener check
  const shortenerSignal = detectURLShortener(urlString);
  if (shortenerSignal) signals.push(shortenerSignal);

  // @ symbol check
  const atSymbolSignal = detectAtSymbol(urlString);
  if (atSymbolSignal) signals.push(atSymbolSignal);

  // Suspicious TLD check
  const tldSignal = checkSuspiciousTLD(hostname);
  if (tldSignal) signals.push(tldSignal);

  // Port hiding check
  const portSignal = detectPortHiding(urlString);
  if (portSignal) signals.push(portSignal);

  // Typosquatting check
  const typosquattingSignal = checkTyposquatting(hostname);
  if (typosquattingSignal) signals.push(typosquattingSignal);

  // Subdomain analysis
  const subdomainAnalysis = analyzeSubdomains(hostname);
  if (subdomainAnalysis.suspicious) {
    signals.push({
      name: "Excessive subdomains",
      severity: "low",
      description: `Domain has ${subdomainAnalysis.depth} levels (typical: 2-3)`,
    });
  }

  // Calculate entropy
  const entropyScore = calculateEntropy(hostname);
  if (entropyScore > 70) {
    signals.push({
      name: "High domain entropy",
      severity: "low",
      description: "Domain has unusual character distribution",
    });
  }

  // Calculate risk score
  const severityWeights: Record<string, number> = {
    low: 5,
    medium: 20,
    high: 40,
    critical: 100,
  };

  let riskScore = 0;
  for (const signal of signals) {
    riskScore += severityWeights[signal.severity];
  }
  riskScore = Math.min(100, riskScore);

  // Determine confidence
  let confidence = 0.7;
  if (signals.length === 0) confidence = 0.95;
  else if (signals.some(s => s.severity === "critical")) confidence = 0.95;
  else if (signals.some(s => s.severity === "high")) confidence = 0.85;
  else confidence = 0.7;

  const explanation = signals.length === 0
    ? "URL appears legitimate based on analysis."
    : `Detected ${signals.length} potential issue(s): ${signals.map(s => s.name).join(", ")}`;

  return {
    url: urlString,
    signals,
    risk_score: riskScore,
    category: signals.length === 0 ? "safe" : "suspicious",
    explanation,
    confidence,
    parsed_domain: hostname,
    subdomain_depth: subdomainAnalysis.depth,
    entropy_score: entropyScore,
  };
}

export function analyzeMultipleURLs(urls: string[]): {
  results: URLAnalysisResult[];
  max_risk_score: number;
  overall_category: "safe" | "suspicious";
} {
  const results = urls.map(url => analyzeURL(url));
  const maxRiskScore = Math.max(...results.map(r => r.risk_score), 0);
  const overallCategory = maxRiskScore > 50 ? "suspicious" : "safe";

  return {
    results,
    max_risk_score: maxRiskScore,
    overall_category: overallCategory,
  };
}

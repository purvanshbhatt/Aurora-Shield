/**
 * Security-focused Input Sanitizer
 * Prevents injection attacks and validates input format
 */

const MAX_INPUT_LENGTH = 10000; // 10KB limit
const MAX_URLS_PER_REQUEST = 50;

export interface SanitizationResult {
  isValid: boolean;
  sanitized: string;
  error?: string;
}

/**
 * Remove or escape potentially dangerous characters
 * Does NOT remove analysis-critical characters (for detection patterns)
 */
export function sanitizeAnalysisInput(input: string): SanitizationResult {
  if (!input || typeof input !== "string") {
    return {
      isValid: false,
      sanitized: "",
      error: "Input must be a non-empty string",
    };
  }

  const trimmed = input.trim();

  // Check length
  if (trimmed.length === 0) {
    return {
      isValid: false,
      sanitized: "",
      error: "Input cannot be empty or whitespace only",
    };
  }

  if (trimmed.length > MAX_INPUT_LENGTH) {
    return {
      isValid: false,
      sanitized: "",
      error: `Input exceeds maximum length of ${MAX_INPUT_LENGTH} characters`,
    };
  }

  // Null byte check (common injection vector)
  if (trimmed.includes("\0")) {
    return {
      isValid: false,
      sanitized: "",
      error: "Input contains null bytes",
    };
  }

  // Check for excessive control characters (except newlines and tabs which are normal)
  const controlCharCount = (trimmed.match(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g) || []).length;
  if (controlCharCount > 5) {
    return {
      isValid: false,
      sanitized: "",
      error: "Input contains excessive control characters",
    };
  }

  // Return sanitized (trimmed) version
  return {
    isValid: true,
    sanitized: trimmed,
  };
}

/**
 * Validate and sanitize URLs
 */
export function sanitizeURL(url: string): SanitizationResult {
  if (!url || typeof url !== "string") {
    return {
      isValid: false,
      sanitized: "",
      error: "URL must be a non-empty string",
    };
  }

  const trimmed = url.trim();

  if (trimmed.length === 0) {
    return {
      isValid: false,
      sanitized: "",
      error: "URL cannot be empty",
    };
  }

  if (trimmed.length > 2048) {
    return {
      isValid: false,
      sanitized: "",
      error: "URL exceeds maximum length of 2048 characters",
    };
  }

  // Null byte check
  if (trimmed.includes("\0")) {
    return {
      isValid: false,
      sanitized: "",
      error: "URL contains null bytes",
    };
  }

  // Try to parse as URL (basic validation)
  try {
    const urlObj = new URL(trimmed.startsWith("http") ? trimmed : `https://${trimmed}`);
    
    // Ensure only http/https
    if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") {
      return {
        isValid: false,
        sanitized: "",
        error: `URL uses unsupported protocol: ${urlObj.protocol}`,
      };
    }

    return {
      isValid: true,
      sanitized: trimmed,
    };
  } catch (e) {
    return {
      isValid: false,
      sanitized: "",
      error: "URL format is invalid or cannot be parsed",
    };
  }
}

/**
 * Validate URL array
 */
export function sanitizeURLArray(urls: any): SanitizationResult {
  if (!Array.isArray(urls)) {
    return {
      isValid: false,
      sanitized: "",
      error: "URLs must be an array",
    };
  }

  if (urls.length === 0) {
    return {
      isValid: false,
      sanitized: "",
      error: "URLs array cannot be empty",
    };
  }

  if (urls.length > MAX_URLS_PER_REQUEST) {
    return {
      isValid: false,
      sanitized: "",
      error: `Cannot analyze more than ${MAX_URLS_PER_REQUEST} URLs per request`,
    };
  }

  const sanitized: string[] = [];

  for (const url of urls) {
    const result = sanitizeURL(url);
    if (!result.isValid) {
      return {
        isValid: false,
        sanitized: "",
        error: `Invalid URL in array: ${result.error}`,
      };
    }
    sanitized.push(result.sanitized);
  }

  return {
    isValid: true,
    sanitized: JSON.stringify(sanitized),
  };
}

/**
 * Validate analysis request body
 */
export interface AnalysisRequestBody {
  type?: string;
  data: string;
  urls?: string[];
}

export function validateAnalysisRequest(
  body: any
): { valid: boolean; error?: string; data?: AnalysisRequestBody } {
  if (!body || typeof body !== "object") {
    return { valid: false, error: "Request body must be a JSON object" };
  }

  if (!body.data || typeof body.data !== "string") {
    return { valid: false, error: "Missing required field: data (string)" };
  }

  // Sanitize data field
  const dataResult = sanitizeAnalysisInput(body.data);
  if (!dataResult.isValid) {
    return { valid: false, error: dataResult.error };
  }

  // Validate type if present
  const analysisType = body.type ?? "prompt";
  const validTypes = ["prompt", "prompt_injection", "phishing", "url"];
  if (!validTypes.includes(analysisType.toLowerCase())) {
    return {
      valid: false,
      error: `Invalid type: ${analysisType}. Must be one of: ${validTypes.join(", ")}`,
    };
  }

  return {
    valid: true,
    data: {
      type: analysisType,
      data: dataResult.sanitized,
      urls: body.urls,
    },
  };
}

/**
 * Extract URLs from text safely
 */
export function extractURLsFromText(text: string, maxUrls: number = 20): string[] {
  // Simple URL regex (not exhaustive but safe)
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
  const matches = text.match(urlRegex) || [];

  // Deduplicate and limit
  const unique = Array.from(new Set(matches));
  return unique.slice(0, maxUrls);
}

/**
 * Sanitize output to prevent XSS in responses
 */
export function sanitizeOutput(value: any): any {
  if (typeof value === "string") {
    // Escape HTML special characters
    return value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");
  }

  if (Array.isArray(value)) {
    return value.map(sanitizeOutput);
  }

  if (typeof value === "object" && value !== null) {
    const sanitized: Record<string, any> = {};
    for (const [key, val] of Object.entries(value)) {
      sanitized[key] = sanitizeOutput(val);
    }
    return sanitized;
  }

  return value;
}

/**
 * Rate limiting check (simple token bucket)
 */
const requestBuckets = new Map<string, { tokens: number; lastRefill: number }>();

export function checkRateLimit(
  identifier: string,
  tokensPerMinute: number = 60
): boolean {
  const now = Date.now();
  const bucket = requestBuckets.get(identifier) || { tokens: tokensPerMinute, lastRefill: now };

  // Refill tokens based on time elapsed
  const timePassed = (now - bucket.lastRefill) / 1000 / 60; // Minutes
  bucket.tokens = Math.min(tokensPerMinute, bucket.tokens + timePassed * tokensPerMinute);
  bucket.lastRefill = now;

  if (bucket.tokens < 1) {
    requestBuckets.set(identifier, bucket);
    return false; // Rate limited
  }

  bucket.tokens -= 1;
  requestBuckets.set(identifier, bucket);
  return true; // Allowed
}

/**
 * Clean up expired rate limit buckets (call periodically)
 */
export function cleanupRateLimitBuckets(maxAge: number = 3600000): void {
  // Max age: 1 hour
  const now = Date.now();
  for (const [key, bucket] of requestBuckets) {
    if (now - bucket.lastRefill > maxAge) {
      requestBuckets.delete(key);
    }
  }
}

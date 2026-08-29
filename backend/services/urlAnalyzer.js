/**
 * PhishGuard URL Analyzer Service (Phase 2)
 * Performs pure static textual analysis and feature extraction on URLs.
 * NOTE: Does NOT visit, render, or make any network requests.
 */

const {
  SUSPICIOUS_KEYWORDS,
  SUSPICIOUS_TLDS,
  BRAND_PROFILES
} = require('../config/threatSignals');

const {
  normalizeDomainString,
  calculateSimilarity,
  isIpAddress,
  extractDomainComponents,
  parseUrlSafely,
  detectObfuscation
} = require('../utils/urlUtils');

/**
 * Analyze a URL string as pure text and extract structural and threat signal features
 * @param {string} rawUrl - The input URL to analyze
 * @returns {object} Structured feature extraction and signal flags
 */
function analyzeUrl(rawUrl) {
  // Safe textual parsing
  const parsed = parseUrlSafely(rawUrl);

  if (!parsed.valid) {
    return {
      valid: false,
      error: parsed.error,
      flags: [parsed.error || 'Invalid or malformed URL input']
    };
  }

  const flags = [];
  const normalizedUrl = parsed.rawUrl;
  const hostname = parsed.hostname || '';
  const pathname = parsed.pathname || '';
  const search = parsed.search || '';

  // 1. Basic structural lengths and metrics
  const urlLength = normalizedUrl.length;
  const hostnameLength = hostname.length;
  const pathLength = pathname.length;
  const queryLength = search.length;

  // 2. Character frequencies
  const dotCount = (normalizedUrl.match(/\./g) || []).length;
  const hyphenCount = (normalizedUrl.match(/-/g) || []).length;
  
  // Special characters: non-alphanumeric and not standard URL structural chars (/ : . ? & = #)
  const specialCharsMatch = normalizedUrl.match(/[@_~!$%*+=^`{}|[\]\\;<>]/g) || [];
  const specialCharacterCount = specialCharsMatch.length;

  // 3. Authority & Hostname analysis
  const hasAtSymbol = parsed.hasAtSymbol || normalizedUrl.includes('@');
  const ipHost = isIpAddress(hostname);
  const domainInfo = extractDomainComponents(hostname);
  const { domain, subdomainCount, tld } = domainInfo;

  if (hasAtSymbol) {
    flags.push("URL contains '@' userinfo delimiter (common phishing obfuscation vector)");
  }

  if (ipHost) {
    flags.push(`IP address used as hostname (${hostname}) instead of domain name`);
  }

  // 4. Protocol & Security features
  const https = parsed.https;
  const protocol = parsed.protocol || (parsed.normalizedProtocol ? parsed.normalizedProtocol : '');
  
  if (!https && protocol === 'http:') {
    flags.push('Unencrypted HTTP protocol in use');
  }

  // 5. Suspicious TLD check
  const isSuspiciousTld = SUSPICIOUS_TLDS.some(stld => 
    tld.toLowerCase() === stld.toLowerCase() || hostname.toLowerCase().endsWith(stld.toLowerCase())
  );
  if (isSuspiciousTld) {
    flags.push(`Suspicious / high-abuse top-level domain detected: ${tld}`);
  }

  // 6. Excessive Subdomains check (> 2 subdomains)
  const excessiveSubdomains = subdomainCount >= 3;
  if (excessiveSubdomains) {
    flags.push(`Excessive subdomain levels detected (${subdomainCount} subdomains)`);
  }

  // 7. Obfuscation & Encoding check
  const obfuscationData = detectObfuscation(normalizedUrl, hostname, pathname);
  const hasEncoding = obfuscationData.hasEncoding;
  const obfuscation = obfuscationData.obfuscation;
  
  if (obfuscationData.indicators.length > 0) {
    obfuscationData.indicators.forEach(ind => flags.push(ind));
  }

  // 8. Suspicious Keywords Extraction
  const foundKeywords = new Set();
  const lowerUrl = normalizedUrl.toLowerCase();
  
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    // Check if keyword exists as whole word or token separated by delimiters
    const regex = new RegExp(`(^|[._/\\-?=&@#])${keyword}([._/\\-?=&@#]|$)`, 'i');
    if (regex.test(lowerUrl) || lowerUrl.includes(keyword)) {
      foundKeywords.add(keyword);
    }
  }

  const suspiciousKeywords = Array.from(foundKeywords);
  if (suspiciousKeywords.length > 0) {
    suspiciousKeywords.slice(0, 5).forEach(kw => {
      flags.push(`Suspicious / credential-related keyword found: ${kw}`);
    });
  }

  // 9. Lookalike & Brand Impersonation Detection
  const lookalikeResult = detectLookalikeDomain(hostname, domain, domainInfo.subdomains);
  if (lookalikeResult.detected) {
    flags.push(`Lookalike domain detected: targeting brand '${lookalikeResult.matchedBrand}' (similarity: ${(lookalikeResult.similarity * 100).toFixed(1)}%)`);
  }

  // 10. URL Length warning (> 120 chars)
  if (urlLength > 120) {
    flags.push(`Abnormally long URL length (${urlLength} characters)`);
  }

  return {
    valid: true,
    protocol: parsed.normalizedProtocol || protocol,
    https,
    hostname,
    domain,
    subdomainCount,
    urlLength,
    hostnameLength,
    pathLength,
    queryLength,
    dotCount,
    hyphenCount,
    specialCharacterCount,
    hasAtSymbol,
    isIpAddress: ipHost,
    hasEncoding,
    suspiciousKeywords,
    suspiciousTld: isSuspiciousTld,
    excessiveSubdomains,
    obfuscation,
    lookalike: lookalikeResult,
    flags
  };
}

/**
 * Intelligent Lookalike and Typosquatting Detection
 * Checks if the hostname attempts to spoof a known brand without being the legitimate brand domain.
 */
function detectLookalikeDomain(hostname, rootDomain, subdomains) {
  if (!hostname || !rootDomain) {
    return { detected: false, matchedBrand: null, similarity: 0 };
  }

  const lowerHost = hostname.toLowerCase();
  const lowerDomain = rootDomain.toLowerCase();

  // Extract the root domain name without its TLD (e.g., "paypa1-login" from "paypa1-login.xyz")
  const domainParts = lowerDomain.split('.');
  const domainLabel = domainParts[0] || '';
  const normalizedDomainLabel = normalizeDomainString(domainLabel);

  for (const profile of BRAND_PROFILES) {
    const brand = profile.brand;
    const isLegit = profile.legitDomains.some(legit => 
      lowerDomain === legit || lowerDomain.endsWith(`.${legit}`)
    );

    // If it's the verified legitimate domain for this brand, it is NOT a lookalike
    if (isLegit) {
      continue;
    }

    // 1. Check exact brand pattern matches in domain label
    for (const pattern of profile.patterns) {
      const normPattern = normalizeDomainString(pattern);
      if (domainLabel.includes(pattern) || normalizedDomainLabel.includes(normPattern)) {
        return {
          detected: true,
          matchedBrand: brand,
          similarity: 1.0
        };
      }
    }

    // 2. Check string similarity against brand name
    // Direct similarity
    const directSim = calculateSimilarity(domainLabel, brand);
    if (directSim >= 0.75 && domainLabel.length >= brand.length - 1) {
      return {
        detected: true,
        matchedBrand: brand,
        similarity: directSim
      };
    }

    // Normalized similarity (after homoglyph/leetspeak translation)
    const normSim = calculateSimilarity(normalizedDomainLabel, brand);
    if (normSim >= 0.80 && normalizedDomainLabel.length >= brand.length - 1) {
      return {
        detected: true,
        matchedBrand: brand,
        similarity: normSim
      };
    }

    // 3. Check for hyphenated brand spoofing in root domain (e.g. "paypal-security.com", "microsoft-login.net")
    if (domainLabel.includes('-')) {
      const tokens = domainLabel.split('-');
      for (const token of tokens) {
        const normToken = normalizeDomainString(token);
        if (normToken === brand || calculateSimilarity(normToken, brand) >= 0.85) {
          return {
            detected: true,
            matchedBrand: brand,
            similarity: calculateSimilarity(normToken, brand)
          };
        }
      }
    }

    // 4. Check for subdomain deceptive brand placement (e.g., "paypal.com.attacker.xyz")
    if (subdomains && subdomains.length > 0) {
      for (const sub of subdomains) {
        const normSub = normalizeDomainString(sub);
        if (normSub === brand && !isLegit) {
          return {
            detected: true,
            matchedBrand: brand,
            similarity: 0.95
          };
        }
      }
    }
  }

  return {
    detected: false,
    matchedBrand: null,
    similarity: 0
  };
}

module.exports = {
  analyzeUrl,
  detectLookalikeDomain
};

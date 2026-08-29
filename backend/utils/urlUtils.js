/**
 * URL Utilities for PhishGuard URL Analysis
 * Pure static textual analysis and feature extraction algorithms
 */

const { URL } = require('url');

// Common multi-part ccTLDs to correctly extract registered domains
const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.in', 'net.in', 'org.in', 'gen.in',
  'com.br', 'net.br', 'org.br',
  'co.jp', 'ne.jp', 'or.jp',
  'co.nz', 'net.nz', 'org.nz',
  'co.za', 'org.za',
  'gc.ca', 'com.mx'
]);

/**
 * Character mapping for leetspeak and visual homoglyphs
 */
const LEET_MAP = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  '$': 's',
  '!': 'i',
  '|': 'l',
  'vv': 'w',
  'rn': 'm',
  'cl': 'd'
};

/**
 * Normalize a domain string by replacing leetspeak / homoglyphs
 * and removing non-alphanumeric separators.
 */
function normalizeDomainString(str) {
  if (!str) return '';
  let lower = str.toLowerCase();
  
  // Replace multi-char homoglyphs first
  lower = lower.replace(/vv/g, 'w').replace(/rn/g, 'm').replace(/cl/g, 'd');
  
  let normalized = '';
  for (let i = 0; i < lower.length; i++) {
    const char = lower[i];
    if (LEET_MAP[char]) {
      normalized += LEET_MAP[char];
    } else if (/[a-z0-9]/.test(char)) {
      normalized += char;
    }
  }
  return normalized;
}

/**
 * Calculate Levenshtein Distance between two strings
 */
function levenshteinDistance(a, b) {
  if (!a || !b) return (a || b || '').length;
  const matrix = Array.from({ length: a.length + 1 }, () => 
    new Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,       // deletion
        matrix[i][j - 1] + 1,       // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return matrix[a.length][b.length];
}

/**
 * Calculate normalized similarity ratio between 0 and 1
 */
function calculateSimilarity(str1, str2) {
  if (str1 === str2) return 1.0;
  const maxLength = Math.max(str1.length, str2.length);
  if (maxLength === 0) return 1.0;
  const distance = levenshteinDistance(str1, str2);
  return Math.max(0, 1 - distance / maxLength);
}

/**
 * Check if a hostname is an IPv4 address (standard, hex, octal, or dword)
 */
function isIpAddress(hostname) {
  if (!hostname) return false;
  
  // Standard IPv4: 4 octets between 0-255
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = hostname.match(ipv4Regex);
  if (match) {
    const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
    return octets.every(oct => oct >= 0 && oct <= 255);
  }

  // Hexadecimal / Octal IP format (e.g. 0x7f000001 or 0x7f.0x0.0x0.0x1)
  const hexIpRegex = /^(0x[0-9a-f]{1,8})(\.(0x[0-9a-f]{1,8})){0,3}$/i;
  if (hexIpRegex.test(hostname)) return true;

  // Single DWORD decimal integer IP (e.g. 2130706433)
  if (/^\d{8,10}$/.test(hostname)) {
    const num = Number(hostname);
    if (!isNaN(num) && num > 0 && num <= 4294967295) return true;
  }

  return false;
}

/**
 * Extract registered domain and subdomain components from a hostname
 */
function extractDomainComponents(hostname) {
  if (!hostname) {
    return { domain: '', subdomains: [], subdomainCount: 0, tld: '' };
  }

  // If hostname is an IP address, domain is the IP itself
  if (isIpAddress(hostname)) {
    return {
      domain: hostname,
      subdomains: [],
      subdomainCount: 0,
      tld: ''
    };
  }

  const parts = hostname.toLowerCase().split('.').filter(Boolean);
  if (parts.length === 0) {
    return { domain: '', subdomains: [], subdomainCount: 0, tld: '' };
  }

  if (parts.length === 1) {
    return { domain: parts[0], subdomains: [], subdomainCount: 0, tld: '' };
  }

  // Check for known 2-part ccTLDs (e.g. co.uk, com.au, co.in)
  if (parts.length >= 3) {
    const twoPartTld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (MULTI_PART_TLDS.has(twoPartTld)) {
      const root = `${parts[parts.length - 3]}.${twoPartTld}`;
      const subdomains = parts.slice(0, parts.length - 3);
      return {
        domain: root,
        subdomains,
        subdomainCount: subdomains.length,
        tld: `.${twoPartTld}`
      };
    }
  }

  // Standard single TLD (e.g. example.com, secure.google.co)
  const root = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  const subdomains = parts.slice(0, parts.length - 2);
  const tld = `.${parts[parts.length - 1]}`;

  return {
    domain: root,
    subdomains,
    subdomainCount: subdomains.length,
    tld
  };
}

/**
 * Safely parse a raw URL string without executing network operations
 */
function parseUrlSafely(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    return { valid: false, error: 'Empty or invalid URL input' };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: 'URL cannot be blank' };
  }

  // Check for dangerous non-HTTP/HTTPS protocols
  const unsupportedSchemeMatch = trimmed.match(/^([a-zA-Z0-9+.-]+):/);
  if (unsupportedSchemeMatch) {
    const scheme = unsupportedSchemeMatch[1].toLowerCase();
    if (!['http', 'https'].includes(scheme)) {
      return {
        valid: false,
        error: `Unsupported protocol '${scheme}:'`,
        protocol: `${scheme}:`
      };
    }
  }

  let parseableUrl = trimmed;
  let missingProtocol = false;

  // Auto-prepend http:// if protocol is omitted (e.g., "example.com/login")
  if (!/^https?:\/\//i.test(trimmed)) {
    parseableUrl = `http://${trimmed}`;
    missingProtocol = true;
  }

  try {
    const parsed = new URL(parseableUrl);
    
    // Check if the URL contained an @ symbol in authority (userinfo phishing vector)
    const hasAtSymbol = trimmed.includes('@');

    return {
      valid: true,
      rawUrl: trimmed,
      protocol: missingProtocol ? '' : parsed.protocol,
      normalizedProtocol: parsed.protocol,
      https: parsed.protocol === 'https:',
      hostname: parsed.hostname,
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      username: parsed.username,
      password: parsed.password,
      hasAtSymbol
    };
  } catch (err) {
    return {
      valid: false,
      error: `Malformed URL structure: ${err.message}`
    };
  }
}

/**
 * Detect obfuscation and encoding anomalies
 */
function detectObfuscation(rawUrl, parsedHostname, parsedPathname) {
  let hasEncoding = false;
  let obfuscation = false;
  const indicators = [];

  // Percent-encoding check
  const percentMatches = rawUrl.match(/%[0-9a-fA-F]{2}/g) || [];
  if (percentMatches.length > 0) {
    hasEncoding = true;
    if (percentMatches.length >= 3) {
      obfuscation = true;
      indicators.push(`Excessive percent-encoding (${percentMatches.length} encoded sequences)`);
    }
  }

  // Double encoding check (e.g. %2520 or %252e)
  if (/%25[0-9a-fA-F]{2}/i.test(rawUrl)) {
    obfuscation = true;
    hasEncoding = true;
    indicators.push('Double URL encoding detected (%25xx)');
  }

  // Encoded dot/slash representations (e.g. %2e, %2f, %5c)
  if (/%2e|%2f|%5c/i.test(rawUrl)) {
    obfuscation = true;
    indicators.push('Path/delimiter obfuscation via encoded dots or slashes (%2e/%2f)');
  }

  // Punycode / Internationalized domain homograph (xn--)
  if (parsedHostname && parsedHostname.startsWith('xn--')) {
    obfuscation = true;
    indicators.push('Punycode / Internationalized domain (IDN) detected');
  }

  // Hexadecimal representation in hostname (e.g., 0x7f...)
  if (parsedHostname && /0x[0-9a-f]/i.test(parsedHostname)) {
    obfuscation = true;
    indicators.push('Hexadecimal-encoded hostname format');
  }

  return {
    hasEncoding,
    obfuscation,
    indicators
  };
}

module.exports = {
  LEET_MAP,
  normalizeDomainString,
  levenshteinDistance,
  calculateSimilarity,
  isIpAddress,
  extractDomainComponents,
  parseUrlSafely,
  detectObfuscation
};

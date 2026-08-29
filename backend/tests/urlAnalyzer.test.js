const { describe, it } = require('node:test');
const assert = require('node:assert');
const { analyzeUrl, detectLookalikeDomain } = require('../services/urlAnalyzer');
const {
  isIpAddress,
  levenshteinDistance,
  calculateSimilarity,
  normalizeDomainString,
  extractDomainComponents,
  parseUrlSafely
} = require('../utils/urlUtils');

describe('PhishGuard URL Analyzer Test Suite (Phase 2)', () => {

  // Test Case 1: https://www.google.com
  it('1. Legitimate search engine URL (https://www.google.com)', () => {
    const result = analyzeUrl('https://www.google.com');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.protocol, 'https:');
    assert.strictEqual(result.https, true);
    assert.strictEqual(result.hostname, 'www.google.com');
    assert.strictEqual(result.domain, 'google.com');
    assert.strictEqual(result.subdomainCount, 1);
    assert.strictEqual(result.isIpAddress, false);
    assert.strictEqual(result.hasAtSymbol, false);
    assert.strictEqual(result.suspiciousTld, false);
    assert.strictEqual(result.lookalike.detected, false); // Must NOT flag legitimate Google
  });

  // Test Case 2: https://example.com
  it('2. Standard clean URL (https://example.com)', () => {
    const result = analyzeUrl('https://example.com');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.https, true);
    assert.strictEqual(result.hostname, 'example.com');
    assert.strictEqual(result.domain, 'example.com');
    assert.strictEqual(result.subdomainCount, 0);
    assert.strictEqual(result.dotCount, 1);
    assert.strictEqual(result.isIpAddress, false);
    assert.strictEqual(result.lookalike.detected, false);
    assert.strictEqual(result.flags.length, 0);
  });

  // Test Case 3: http://192.168.1.10/login
  it('3. IP address hostname with unencrypted HTTP (http://192.168.1.10/login)', () => {
    const result = analyzeUrl('http://192.168.1.10/login');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.isIpAddress, true);
    assert.strictEqual(result.https, false);
    assert.strictEqual(result.hostname, '192.168.1.10');
    assert.ok(result.suspiciousKeywords.includes('login'));
    assert.ok(result.flags.some(f => f.includes('IP address used as hostname')));
    assert.ok(result.flags.some(f => f.includes('Unencrypted HTTP')));
  });

  // Test Case 4: https://paypa1-login.xyz/verify
  it('4. Phishing URL with lookalike domain and suspicious TLD (https://paypa1-login.xyz/verify)', () => {
    const result = analyzeUrl('https://paypa1-login.xyz/verify');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.suspiciousTld, true);
    assert.strictEqual(result.lookalike.detected, true);
    assert.strictEqual(result.lookalike.matchedBrand, 'paypal');
    assert.ok(result.suspiciousKeywords.includes('login'));
    assert.ok(result.suspiciousKeywords.includes('verify'));
    assert.ok(result.flags.some(f => f.includes('Lookalike domain detected: targeting brand \'paypal\'')));
    assert.ok(result.flags.some(f => f.includes('Suspicious / high-abuse top-level domain')));
  });

  // Test Case 5: https://micros0ft-example.com/login
  it('5. Typosquatting / homoglyph domain (https://micros0ft-example.com/login)', () => {
    const result = analyzeUrl('https://micros0ft-example.com/login');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.lookalike.detected, true);
    assert.strictEqual(result.lookalike.matchedBrand, 'microsoft');
    assert.ok(result.suspiciousKeywords.includes('login'));
    assert.ok(result.flags.some(f => f.includes('Lookalike domain detected: targeting brand \'microsoft\'')));
  });

  // Test Case 6: Malformed URL
  it('6. Malformed and invalid URL handling', () => {
    const malformed1 = analyzeUrl('http://:invalid::domain:80');
    assert.strictEqual(malformed1.valid, false);
    assert.ok(malformed1.flags.length > 0);

    const emptyUrl = analyzeUrl('');
    assert.strictEqual(emptyUrl.valid, false);

    const nullUrl = analyzeUrl(null);
    assert.strictEqual(nullUrl.valid, false);

    const javascriptUrl = analyzeUrl('javascript:alert(1)');
    assert.strictEqual(javascriptUrl.valid, false);
    assert.ok(javascriptUrl.error.includes('Unsupported protocol'));
  });

  // Test Case 7: URL containing @ userinfo symbol
  it('7. URL containing @ delimiter symbol (https://legit.com@evil.com/login)', () => {
    const result = analyzeUrl('https://legit.com@evil.com/login');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.hasAtSymbol, true);
    assert.strictEqual(result.hostname, 'evil.com');
    assert.ok(result.flags.some(f => f.includes("URL contains '@' userinfo delimiter")));
  });

  // Test Case 8: URL containing encoded characters / obfuscation
  it('8. Heavily percent-encoded and obfuscated URL', () => {
    const result = analyzeUrl('http://example.com/%73%65%63%75%72%65/%6c%6f%67%69%6e');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.hasEncoding, true);
    assert.strictEqual(result.obfuscation, true);
    assert.ok(result.flags.some(f => f.includes('Excessive percent-encoding')));
  });

  // Test Case 9: URL with excessive subdomains
  it('9. Excessive subdomains count (https://a.b.c.d.e.malicious-domain.com/update)', () => {
    const result = analyzeUrl('https://a.b.c.d.e.malicious-domain.com/update');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.excessiveSubdomains, true);
    assert.strictEqual(result.subdomainCount, 5);
    assert.strictEqual(result.domain, 'malicious-domain.com');
    assert.ok(result.flags.some(f => f.includes('Excessive subdomain levels detected')));
  });

  // Test Case 10: Normal legitimate URL containing "login" (False positive prevention)
  it('10. Legitimate brand login page - False Positive Prevention (https://accounts.google.com/signin/v2/identifier)', () => {
    const result = analyzeUrl('https://accounts.google.com/signin/v2/identifier');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.domain, 'google.com');
    assert.strictEqual(result.lookalike.detected, false); // CRITICAL: Google's real domain must NOT be marked lookalike
    assert.strictEqual(result.suspiciousTld, false);
    assert.strictEqual(result.isIpAddress, false);
    assert.ok(result.suspiciousKeywords.includes('signin'));
  });

  // Bonus Edge Cases
  it('11. Legitimate GitHub login URL (https://github.com/login)', () => {
    const result = analyzeUrl('https://github.com/login');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.domain, 'github.com');
    assert.strictEqual(result.lookalike.detected, false);
    assert.ok(result.suspiciousKeywords.includes('login'));
  });

  it('12. URL without protocol scheme (example.com/secure/login)', () => {
    const result = analyzeUrl('example.com/secure/login');
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.hostname, 'example.com');
    assert.strictEqual(result.domain, 'example.com');
    assert.ok(result.suspiciousKeywords.includes('secure'));
    assert.ok(result.suspiciousKeywords.includes('login'));
  });
});

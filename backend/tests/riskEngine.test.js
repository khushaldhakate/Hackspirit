const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { analyzeUrl } = require('../services/urlAnalyzer');
const { analyzeMessage } = require('../services/messageAnalyzer');
const {
  evaluateRisk,
  determineRiskLevel,
  determineThreatCategory,
  evaluateUrlSignals,
  evaluateMessageSignals,
  evaluateRedirectSignals,
  evaluateMLSignals
} = require('../services/riskEngine');
const { CATEGORY_CAPS } = require('../config/riskWeights');

describe('PhishGuard Risk Engine Test Suite (Phase 6)', () => {

  // TEST 1 — Completely normal URL / message
  it('TEST 1 — Completely normal URL and message produces LOW risk with no suspicious evidence', () => {
    const urlAnalysis = analyzeUrl('https://example.com');
    const messageAnalysis = analyzeMessage('Hey, let us meet for lunch at 12:30 PM tomorrow.');
    const mlAnalysis = { prediction: 'benign', probability: 0.99 };
    const redirectAnalysis = {
      redirectDetected: false,
      redirectCount: 0,
      chain: [],
      finalUrl: 'https://example.com',
      finalDomain: 'example.com',
      blocked: false,
      error: null
    };

    const result = evaluateRisk({ urlAnalysis, messageAnalysis, redirectAnalysis, mlAnalysis });

    assert.strictEqual(result.riskLevel, 'LOW');
    assert.strictEqual(result.riskScore, 0);
    assert.strictEqual(result.threatCategory, 'benign');
    assert.strictEqual(result.evidence.length, 0);
    assert.strictEqual(result.scoreBreakdown.url, 0);
    assert.strictEqual(result.scoreBreakdown.message, 0);
    assert.strictEqual(result.scoreBreakdown.redirect, 0);
    assert.strictEqual(result.scoreBreakdown.ml, 0);
  });

  // TEST 2 — Suspicious URL
  it('TEST 2 — Suspicious URL evidence contributes to score', () => {
    const urlAnalysis = analyzeUrl('https://paypa1-security-update.xyz/login/verify');
    const result = evaluateRisk({ urlAnalysis });

    assert.ok(result.scoreBreakdown.url > 0, 'URL score should contribute');
    assert.ok(result.riskScore > 0, 'Total risk score should be > 0');
    assert.ok(result.evidence.some(e => e.category === 'url'));
    assert.ok(result.evidence.some(e => e.signal === 'lookalike_domain'));
  });

  // TEST 3 — Urgent credential phishing message
  it('TEST 3 — Urgent credential phishing message contributes significantly and detects social engineering', () => {
    const messageAnalysis = analyzeMessage(
      'URGENT! Your account will be suspended today. Verify your password and OTP immediately to prevent permanent deletion.'
    );
    const result = evaluateRisk({ messageAnalysis });

    assert.ok(result.scoreBreakdown.message >= 20, `Message score should be >= 20, got ${result.scoreBreakdown.message}`);
    assert.strictEqual(result.threatCategory, 'credential_theft');
    assert.ok(result.evidence.some(e => e.signal === 'otp_request' || e.signal === 'password_request'));
    assert.ok(result.evidence.some(e => e.signal === 'threat_language'));
    assert.ok(result.evidence.some(e => e.signal === 'urgency_language'));
  });

  // TEST 4 — Suspicious redirect chain
  it('TEST 4 — Suspicious redirect chain contribution appears in score', () => {
    const redirectAnalysis = {
      redirectDetected: true,
      redirectCount: 3,
      chain: [
        { from: 'http://source-tracker.com/click', statusCode: 302, to: 'http://bridge-hop.net/jump' },
        { from: 'http://bridge-hop.net/jump', statusCode: 301, to: 'http://deceptive-landing.org/welcome' }
      ],
      finalUrl: 'http://deceptive-landing.org/welcome',
      finalDomain: 'deceptive-landing.org',
      blocked: false,
      error: null
    };

    const result = evaluateRisk({ redirectAnalysis });

    assert.ok(result.scoreBreakdown.redirect > 0, 'Redirect contribution must be > 0');
    assert.ok(result.evidence.some(e => e.category === 'redirect'));
    assert.ok(result.evidence.some(e => e.signal === 'multiple_redirects'));
    assert.ok(result.evidence.some(e => e.signal === 'suspicious_final_domain'));
  });

  // TEST 5 — High ML phishing probability
  it('TEST 5 — Higher ML phishing probability produces proportionally higher contribution', () => {
    const mlLow = { prediction: 'phishing', probability: 0.50 };
    const mlHigh = { prediction: 'phishing', probability: 0.95 };

    const resultLow = evaluateRisk({ mlAnalysis: mlLow });
    const resultHigh = evaluateRisk({ mlAnalysis: mlHigh });

    assert.ok(resultLow.scoreBreakdown.ml > 0);
    assert.ok(resultHigh.scoreBreakdown.ml > resultLow.scoreBreakdown.ml,
      `High ML (${resultHigh.scoreBreakdown.ml}) must exceed low ML (${resultLow.scoreBreakdown.ml})`);
    assert.strictEqual(resultHigh.scoreBreakdown.ml, Math.round(CATEGORY_CAPS.ml * 0.95));
  });

  // TEST 6 — Low ML probability + strong independent evidence
  it('TEST 6 — Low ML probability with strong independent evidence still elevates final risk', () => {
    // ML claims benign with 99% confidence
    const mlAnalysis = { prediction: 'benign', probability: 0.99 };
    // Strong URL + redirect evidence
    const urlAnalysis = analyzeUrl('http://192.168.1.10@paypa1-security.xyz/verify');
    const redirectAnalysis = {
      blocked: true,
      reason: 'Destination IP in prohibited private range (192.168.1.10)',
      chain: [],
      finalUrl: 'http://192.168.1.10'
    };

    const result = evaluateRisk({ urlAnalysis, redirectAnalysis, mlAnalysis });

    assert.strictEqual(result.scoreBreakdown.ml, 0, 'Benign ML should contribute 0');
    assert.ok(result.riskScore >= 35, `Risk score should be elevated (got ${result.riskScore}) despite benign ML`);
    assert.ok(['MEDIUM', 'HIGH', 'CRITICAL'].includes(result.riskLevel));
  });

  // TEST 7 — High ML probability + weak other evidence
  it('TEST 7 — High ML probability with weak other evidence is elevated but not automatically 100', () => {
    const mlAnalysis = { prediction: 'phishing', probability: 0.95 };
    const urlAnalysis = analyzeUrl('https://example.com'); // benign URL

    const result = evaluateRisk({ urlAnalysis, mlAnalysis });

    assert.ok(result.riskScore > 0, 'Risk score must be elevated');
    assert.strictEqual(result.scoreBreakdown.url, 0);
    assert.strictEqual(result.scoreBreakdown.ml, Math.round(CATEGORY_CAPS.ml * 0.95));
    assert.strictEqual(result.riskScore, result.scoreBreakdown.ml);
    assert.ok(result.riskScore <= 35, `Score should be strictly capped at ML contribution, got ${result.riskScore}`);
    assert.notStrictEqual(result.riskScore, 100, 'Score must NOT automatically be 100');
  });

  // TEST 8 — All strong indicators
  it('TEST 8 — All strong indicators produce critical risk without exceeding 100', () => {
    const urlAnalysis = analyzeUrl('http://192.168.1.10@paypa1-account.xyz/login/verify?token=123');
    const messageAnalysis = analyzeMessage(
      'CRITICAL: Your account is suspended. Enter your password and OTP immediately to avoid legal action.'
    );
    const redirectAnalysis = {
      blocked: true,
      redirectCount: 3,
      reason: 'Destination blocked due to SSRF hazard'
    };
    const mlAnalysis = {
      prediction: 'phishing',
      probability: 0.98
    };

    const result = evaluateRisk({ urlAnalysis, messageAnalysis, redirectAnalysis, mlAnalysis });

    assert.ok(result.riskScore >= 81, `Expected CRITICAL score (>=81), got ${result.riskScore}`);
    assert.strictEqual(result.riskLevel, 'CRITICAL');
    assert.ok(result.riskScore <= 100, `Score must never exceed 100, got ${result.riskScore}`);
    assert.ok(result.scoreBreakdown.url <= CATEGORY_CAPS.url);
    assert.ok(result.scoreBreakdown.message <= CATEGORY_CAPS.message);
    assert.ok(result.scoreBreakdown.redirect <= CATEGORY_CAPS.redirect);
    assert.ok(result.scoreBreakdown.ml <= CATEGORY_CAPS.ml);
  });

  // TEST 9 — Missing optional message
  it('TEST 9 — URL-only analysis works when optional message is omitted', () => {
    const urlAnalysis = analyzeUrl('https://paypa1-login.xyz/verify');
    const mlAnalysis = { prediction: 'phishing', probability: 0.88 };

    const result = evaluateRisk({ urlAnalysis, mlAnalysis });

    assert.ok(result.riskScore > 0);
    assert.strictEqual(result.scoreBreakdown.message, 0);
    assert.ok(result.scoreBreakdown.url > 0);
    assert.ok(result.scoreBreakdown.ml > 0);
  });

  // TEST 10 — Missing optional URL
  it('TEST 10 — Message-only analysis works when optional URL is omitted', () => {
    const messageAnalysis = analyzeMessage('Your bank debit card is locked! Reply with your PIN immediately.');

    const result = evaluateRisk({ messageAnalysis });

    assert.ok(result.riskScore > 0);
    assert.strictEqual(result.scoreBreakdown.url, 0);
    assert.strictEqual(result.scoreBreakdown.redirect, 0);
    assert.strictEqual(result.scoreBreakdown.ml, 0);
    assert.ok(result.scoreBreakdown.message > 0);
    assert.strictEqual(result.threatCategory, 'credential_theft');
  });

  // TEST 11 — Evidence transparency
  it('TEST 11 — Every score contribution has signal, category, points, and reason', () => {
    const urlAnalysis = analyzeUrl('https://paypa1-login.xyz/verify');
    const messageAnalysis = analyzeMessage('Urgent: Your account is suspended, provide your password');
    const mlAnalysis = { prediction: 'phishing', probability: 0.85 };

    const result = evaluateRisk({ urlAnalysis, messageAnalysis, mlAnalysis });

    assert.ok(result.evidence.length >= 3);
    for (const item of result.evidence) {
      assert.strictEqual(typeof item.signal, 'string', 'signal must be a string');
      assert.ok(item.signal.length > 0);
      assert.ok(['url', 'message', 'redirect', 'ml'].includes(item.category), `Invalid category: ${item.category}`);
      assert.strictEqual(typeof item.points, 'number', 'points must be a number');
      assert.ok(item.points > 0, `points must be > 0, got ${item.points}`);
      assert.strictEqual(typeof item.reason, 'string', 'reason must be a string');
      assert.ok(item.reason.length > 0);
    }
  });

  // TEST 12 — Determinism
  it('TEST 12 — Identical analyzer inputs produce identical Risk Engine outputs', () => {
    const inputs = {
      urlAnalysis: analyzeUrl('https://paypa1-update.xyz/login'),
      messageAnalysis: analyzeMessage('Urgent notice: Verify OTP to prevent account suspension.'),
      redirectAnalysis: { redirectDetected: true, redirectCount: 2, finalDomain: 'paypa1-update.xyz' },
      mlAnalysis: { prediction: 'phishing', probability: 0.91 }
    };

    const run1 = evaluateRisk(inputs);
    const run2 = evaluateRisk(inputs);

    assert.deepStrictEqual(run1, run2, 'Consecutive runs with identical inputs must be identical');
  });

  // Additional test: Correlation de-duplication between URL and message verification keywords
  it('13. Cross-signal correlation applies dampening to avoid double-counting verification intent', () => {
    const urlWithVerify = analyzeUrl('https://example.com/verify');
    const messageWithVerify = analyzeMessage('Urgent: verify your account now');

    const combinedResult = evaluateRisk({ urlAnalysis: urlWithVerify, messageAnalysis: messageWithVerify });
    const verifyEvidence = combinedResult.evidence.find(e => e.signal === 'verification_request');

    assert.ok(verifyEvidence, 'Verification request evidence should exist');
    assert.ok(verifyEvidence.points < 6, 'Verification points should be dampened due to correlation');
    assert.ok(verifyEvidence.reason.includes('dampened to avoid double-counting'));
  });

  // Additional test: Malware threat category classification
  it('14. ML malware prediction sets primary threat category to malware', () => {
    const mlAnalysis = { prediction: 'malware', probability: 0.92 };
    const result = evaluateRisk({ mlAnalysis });

    assert.strictEqual(result.threatCategory, 'malware');
    assert.strictEqual(result.confidence, 'high');
  });

  // HTTP API Integration Tests
  describe('HTTP API /api/analyze/risk Integration', () => {
    let server;
    let baseUrl;

    before(() => {
      process.env.NODE_ENV = 'test';
      const app = require('../server');
      server = app.listen(0);
      baseUrl = `http://127.0.0.1:${server.address().port}`;
    });

    after(() => {
      if (server) {
        server.close();
      }
    });

    it('15. POST /api/analyze/risk endpoint returns 400 when neither url nor message is provided', async () => {
      const res = await fetch(`${baseUrl}/api/analyze/risk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      assert.strictEqual(res.status, 400);
      const json = await res.json();
      assert.strictEqual(json.success, false);
    });

    it('16. POST /api/analyze/risk endpoint successfully evaluates message-only request', async () => {
      const res = await fetch(`${baseUrl}/api/analyze/risk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'URGENT! Your account will be suspended today. Verify your password immediately.'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.strictEqual(typeof json.riskScore, 'number');
      assert.ok(json.riskScore > 0);
      assert.ok(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(json.riskLevel));
      assert.strictEqual(json.threatCategory, 'credential_theft');
      assert.ok(json.scoreBreakdown);
      assert.ok(Array.isArray(json.evidence));
      assert.ok(Array.isArray(json.summary));
    });

    it('17. POST /api/analyze/risk endpoint successfully evaluates URL-only request with real ML inference', async () => {
      const res = await fetch(`${baseUrl}/api/analyze/risk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.strictEqual(typeof json.riskScore, 'number');
      // The pretrained ML model classifies example.com as phishing (~35 pts), producing MEDIUM risk without other signals
      assert.ok(json.riskScore <= 35, `Score should be bounded to ML contribution (got ${json.riskScore})`);
      assert.strictEqual(json.scoreBreakdown.message, 0);
      assert.ok(json.ml !== undefined);
      assert.ok(json.ml.prediction);
    });
  });
});

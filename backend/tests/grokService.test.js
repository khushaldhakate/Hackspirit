const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const {
  generateSecurityExplanation,
  sanitizeEvidenceForGrok,
  validateExplanationSchema
} = require('../services/grokService');
const { evaluateRisk } = require('../services/riskEngine');
const { analyzeUrl } = require('../services/urlAnalyzer');
const { analyzeMessage } = require('../services/messageAnalyzer');

const MOCK_API_KEY = 'xai-test-secret-key-abcdef123456';

/**
 * Helper to build a successful mock Grok response
 */
function createMockFetch(responseContent, options = {}) {
  const status = options.status || 200;
  const ok = status >= 200 && status < 300;

  return async (url, fetchOptions) => {
    // Record options for assertions
    createMockFetch.lastCall = { url, fetchOptions };

    if (options.delay) {
      await new Promise(resolve => setTimeout(resolve, options.delay));
    }

    if (options.networkError) {
      throw new Error(options.networkError);
    }

    if (options.abort) {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      throw abortErr;
    }

    return {
      ok,
      status,
      text: async () => typeof responseContent === 'string' ? responseContent : JSON.stringify(responseContent),
      json: async () => ({
        choices: [
          {
            message: {
              content: typeof responseContent === 'string' ? responseContent : JSON.stringify(responseContent)
            }
          }
        ]
      })
    };
  };
}

describe('PhishGuard Grok AI Explainability Test Suite (Phase 7)', () => {

  const sampleHighRiskResult = {
    riskScore: 92,
    riskLevel: 'CRITICAL',
    threatCategory: 'credential_theft',
    confidence: 'high',
    ml: {
      prediction: 'phishing',
      probability: 0.96
    },
    scoreBreakdown: {
      url: 25,
      message: 25,
      redirect: 15,
      ml: 34
    },
    evidence: [
      {
        signal: 'lookalike_domain',
        category: 'url',
        points: 20,
        reason: "Domain resembles trusted brand 'paypal' (impersonation vector)"
      },
      {
        signal: 'otp_request',
        category: 'message',
        points: 14,
        reason: 'Solicitation of one-time password (OTP) detected'
      }
    ]
  };

  const sampleLowRiskResult = {
    riskScore: 0,
    riskLevel: 'LOW',
    threatCategory: 'benign',
    confidence: 'high',
    ml: {
      prediction: 'benign',
      probability: 0.99
    },
    scoreBreakdown: {
      url: 0,
      message: 0,
      redirect: 0,
      ml: 0
    },
    evidence: []
  };

  // TEST 1 — Successful Grok explanation
  it('TEST 1 — Successful Grok explanation parses and returns structured data', async () => {
    const mockContent = {
      title: 'High-Risk Phishing and Credential Harvesting Alert',
      explanation: 'PhishGuard detected lookalike domain spoofing and an urgent request for your one-time password.',
      attackIntent: 'Credential theft',
      keyFindings: [
        'Domain spoofing targeting PayPal brand',
        'Direct solicitation of sensitive OTP code'
      ],
      recommendedActions: [
        'Do not interact with the link',
        'Never share OTP or passwords'
      ],
      disclaimer: 'This explanation is based on the security evidence detected by PhishGuard.'
    };

    const fetchFn = createMockFetch(mockContent);
    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'success');
    assert.ok(result.explanation);
    assert.strictEqual(result.explanation.title, mockContent.title);
    assert.strictEqual(result.explanation.attackIntent, 'Credential theft');
    assert.strictEqual(result.explanation.keyFindings.length, 2);
    assert.strictEqual(result.explanation.recommendedActions.length, 2);
  });

  // TEST 2 — High-risk phishing explanation
  it('TEST 2 — High-risk phishing explanation provides clear indicators and safe directives', async () => {
    const mockContent = {
      title: 'Deceptive Phishing Link Detected',
      explanation: 'The link imitates a known banking platform to trick users into revealing login information.',
      attackIntent: 'Account takeover through phishing',
      keyFindings: [
        'Deceptive lookalike domain detected',
        'Machine learning model flagged phishing patterns with 96% confidence'
      ],
      recommendedActions: [
        'Close the message immediately',
        'Report the message as phishing'
      ],
      disclaimer: 'This explanation is based on the security evidence detected by PhishGuard.'
    };

    const fetchFn = createMockFetch(mockContent);
    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'success');
    assert.ok(result.explanation.explanation.includes('imitates a known banking platform'));
    assert.ok(result.explanation.recommendedActions.length >= 2);
  });

  // TEST 3 — Low-risk explanation
  it('TEST 3 — Low-risk explanation confirms benign status without alarming warnings', async () => {
    const mockContent = {
      title: 'Legitimate Request (Benign)',
      explanation: 'No security threats, credential requests, or deceptive patterns were identified.',
      attackIntent: 'Benign communication',
      keyFindings: [
        'Clean URL domain structure',
        'No social engineering triggers found'
      ],
      recommendedActions: [
        'No security action required',
        'Proceed normally'
      ],
      disclaimer: 'This explanation is based on the security evidence detected by PhishGuard.'
    };

    const fetchFn = createMockFetch(mockContent);
    const result = await generateSecurityExplanation(sampleLowRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'success');
    assert.strictEqual(result.explanation.attackIntent, 'Benign communication');
    assert.ok(result.explanation.recommendedActions.includes('Proceed normally'));
  });

  // TEST 4 — Credential theft explanation
  it('TEST 4 — Credential theft explanation accurately highlights authentication risks', async () => {
    const credRisk = {
      ...sampleHighRiskResult,
      threatCategory: 'credential_theft'
    };

    const mockContent = {
      title: 'Urgent Credential Solicitation Attempt',
      explanation: 'The request coerces the recipient into disclosing sensitive passwords or OTP authentication tokens.',
      attackIntent: 'Credential theft',
      keyFindings: [
        'Direct request for one-time verification password'
      ],
      recommendedActions: [
        'Do not share your OTP with anyone',
        'Legitimate companies will never request your OTP via text'
      ],
      disclaimer: 'This explanation is based on the security evidence detected by PhishGuard.'
    };

    const fetchFn = createMockFetch(mockContent);
    const result = await generateSecurityExplanation(credRisk, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'success');
    assert.strictEqual(result.explanation.attackIntent, 'Credential theft');
    assert.ok(result.explanation.recommendedActions.some(a => a.includes('OTP')));
  });

  // TEST 5 — Malware explanation
  it('TEST 5 — Malware threat explanation highlights payload execution hazards', async () => {
    const malwareRisk = {
      riskScore: 78,
      riskLevel: 'HIGH',
      threatCategory: 'malware',
      confidence: 'high',
      ml: { prediction: 'malware', probability: 0.92 },
      evidence: [
        { signal: 'ml_malware', category: 'ml', points: 32, reason: 'Model classified URL as malware' }
      ]
    };

    const mockContent = {
      title: 'Malicious Software Distribution Hazard',
      explanation: 'The referenced web destination is strongly associated with malicious software payloads.',
      attackIntent: 'Malware delivery and infection',
      keyFindings: [
        'URL classification model identified active malware distribution signature'
      ],
      recommendedActions: [
        'Do not navigate to or download any files from the link',
        'Run an endpoint antivirus scan if the link was previously accessed'
      ],
      disclaimer: 'This explanation is based on the security evidence detected by PhishGuard.'
    };

    const fetchFn = createMockFetch(mockContent);
    const result = await generateSecurityExplanation(malwareRisk, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'success');
    assert.strictEqual(result.explanation.attackIntent, 'Malware delivery and infection');
    assert.ok(result.explanation.keyFindings.some(f => f.includes('malware')));
  });

  // TEST 6 — Evidence-grounded response and data sanitization
  it('TEST 6 — Sanitization ensures only structured evidence is sent, filtering raw inputs and secrets', () => {
    const uncleanedInput = {
      riskScore: 85,
      riskLevel: 'HIGH',
      threatCategory: 'phishing',
      rawSecretToken: 'SUPER_SECRET_TOKEN_DO_NOT_SEND',
      userPassword: 'plaintext_password_123',
      evidence: [
        { signal: 'lookalike_domain', category: 'url', points: 20, reason: 'Lookalike domain' }
      ]
    };

    const sanitized = sanitizeEvidenceForGrok(uncleanedInput);

    assert.strictEqual(sanitized.riskScore, 85);
    assert.strictEqual(sanitized.riskLevel, 'HIGH');
    assert.strictEqual(sanitized.rawSecretToken, undefined, 'rawSecretToken must be stripped');
    assert.strictEqual(sanitized.userPassword, undefined, 'userPassword must be stripped');
    assert.strictEqual(sanitized.evidence.length, 1);
  });

  // TEST 7 — Invalid Grok JSON
  it('TEST 7 — Invalid or non-JSON Grok response returns aiStatus "invalid_response" safely', async () => {
    const invalidJsonString = 'I cannot fulfill this request. Here is plain text instead of JSON.';
    const fetchFn = createMockFetch(invalidJsonString);

    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'invalid_response');
    assert.strictEqual(result.explanation, null);
    assert.ok(result.error);
  });

  // TEST 8 — Missing required schema fields
  it('TEST 8 — Response missing required schema fields is rejected with "invalid_response"', async () => {
    // Missing 'explanation' and 'recommendedActions'
    const incompleteContent = {
      title: 'Alert',
      attackIntent: 'Phishing',
      keyFindings: ['Some finding']
    };

    const fetchFn = createMockFetch(incompleteContent);
    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'invalid_response');
    assert.strictEqual(result.explanation, null);
    assert.ok(result.error.includes('required schema'));
  });

  // TEST 9 — Grok timeout
  it('TEST 9 — Grok timeout is handled gracefully returning aiStatus "unavailable"', async () => {
    const fetchFn = createMockFetch({}, { abort: true });

    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY,
      timeoutMs: 50
    });

    assert.strictEqual(result.aiStatus, 'unavailable');
    assert.strictEqual(result.explanation, null);
    assert.ok(result.error.includes('timed out'));
  });

  // TEST 10 — Invalid API key (HTTP 401)
  it('TEST 10 — Invalid API key (HTTP 401) returns aiStatus "unavailable" without crashing', async () => {
    const fetchFn = createMockFetch({ error: 'Unauthorized' }, { status: 401 });

    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: 'invalid-key'
    });

    assert.strictEqual(result.aiStatus, 'unavailable');
    assert.strictEqual(result.explanation, null);
    assert.ok(result.error.includes('authentication failed'));
  });

  // TEST 11 — Rate-limit failure (HTTP 429)
  it('TEST 11 — Rate-limit failure (HTTP 429) returns aiStatus "unavailable" gracefully', async () => {
    const fetchFn = createMockFetch({ error: 'Rate limit reached' }, { status: 429 });

    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'unavailable');
    assert.strictEqual(result.explanation, null);
    assert.ok(result.error.includes('rate limit'));
  });

  // TEST 12 — Grok unavailable (network failure)
  it('TEST 12 — Network failure / ECONNREFUSED returns aiStatus "unavailable"', async () => {
    const fetchFn = createMockFetch({}, { networkError: 'connect ECONNREFUSED 127.0.0.1:443' });

    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: MOCK_API_KEY
    });

    assert.strictEqual(result.aiStatus, 'unavailable');
    assert.strictEqual(result.explanation, null);
    assert.ok(result.error.includes('Network error'));
  });

  // TEST 13 — Risk Engine still works when Grok fails
  it('TEST 13 — Risk Engine evaluation succeeds even if Grok is completely unavailable', () => {
    const urlAnalysis = analyzeUrl('https://paypa1-security.xyz/verify');
    const messageAnalysis = analyzeMessage('Urgent: account suspended today. Verify OTP now.');

    const riskAssessment = evaluateRisk({ urlAnalysis, messageAnalysis });

    // Risk Engine must function 100% autonomously without Grok
    assert.ok(riskAssessment.riskScore > 0);
    assert.ok(['MEDIUM', 'HIGH', 'CRITICAL'].includes(riskAssessment.riskLevel));
    assert.strictEqual(riskAssessment.threatCategory, 'credential_theft');
    assert.ok(riskAssessment.scoreBreakdown.url > 0);
    assert.ok(riskAssessment.scoreBreakdown.message > 0);
  });

  // TEST 14 — API key is never leaked in the response or explanation
  it('TEST 14 — API key is never present in explanation object or response output', async () => {
    const mockContent = {
      title: 'Phishing Attempt',
      explanation: 'Analysis detected credential phishing indicators.',
      attackIntent: 'Credential theft',
      keyFindings: ['Lookalike domain detected'],
      recommendedActions: ['Do not enter credentials'],
      disclaimer: 'This explanation is based on the security evidence detected by PhishGuard.'
    };

    const secretKey = 'super-secret-production-key-999888';
    const fetchFn = createMockFetch(mockContent);
    const result = await generateSecurityExplanation(sampleHighRiskResult, {
      fetchFn,
      apiKey: secretKey
    });

    const serialized = JSON.stringify(result);
    assert.strictEqual(serialized.includes(secretKey), false, 'API key must never appear in output');
  });

  // HTTP API Integration Tests
  describe('HTTP API Endpoints Integration', () => {
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

    it('15. POST /api/analyze/explain accepts risk result and returns formatted response', async () => {
      const res = await fetch(`${baseUrl}/api/analyze/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sampleHighRiskResult)
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.ok(json.risk);
      assert.strictEqual(json.risk.riskScore, 92);
      assert.strictEqual(json.risk.riskLevel, 'CRITICAL');
      assert.ok(['success', 'unavailable', 'invalid_response'].includes(json.aiStatus));
    });

    it('16. POST /api/analyze/explain returns 400 when empty body is provided', async () => {
      const res = await fetch(`${baseUrl}/api/analyze/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      assert.strictEqual(res.status, 400);
      const json = await res.json();
      assert.strictEqual(json.success, false);
    });

    it('17. POST /api/analyze combined pipeline executes full chain', async () => {
      const res = await fetch(`${baseUrl}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'URGENT! Your account will be suspended today. Verify your password immediately.'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.ok(json.risk);
      assert.ok(json.risk.riskScore > 0);
      assert.strictEqual(json.risk.threatCategory, 'credential_theft');
      assert.ok(['success', 'unavailable', 'invalid_response'].includes(json.aiStatus));
    });
  });
});

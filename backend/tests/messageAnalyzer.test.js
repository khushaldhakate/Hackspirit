const { describe, it } = require('node:test');
const assert = require('node:assert');
const { analyzeMessage, extractUrls } = require('../services/messageAnalyzer');

describe('PhishGuard Message Analyzer Test Suite (Phase 3)', () => {

  // TEST 1 — Normal message
  it('TEST 1 — Normal benign message ("Hey, are we meeting at 5 PM?")', () => {
    const result = analyzeMessage('Hey, are we meeting at 5 PM?');
    assert.strictEqual(result.urgency.detected, false);
    assert.strictEqual(result.threat.detected, false);
    assert.strictEqual(result.credentialRequest.detected, false);
    assert.strictEqual(result.passwordRequest, false);
    assert.strictEqual(result.otpRequest, false);
    assert.strictEqual(result.pinRequest, false);
    assert.strictEqual(result.paymentRequest, false);
    assert.strictEqual(result.verificationRequest.detected, false);
    assert.strictEqual(result.callToAction.detected, false);
    assert.strictEqual(result.socialEngineering.detected, false);
    assert.strictEqual(result.extractedUrls.length, 0);
    assert.strictEqual(result.flags.length, 0);
  });

  // TEST 2 — Phishing-style message
  it('TEST 2 — Phishing-style urgent message with threat and credential request', () => {
    const text = 'URGENT! Your account will be suspended today. Verify your password immediately.';
    const result = analyzeMessage(text);

    assert.strictEqual(result.urgency.detected, true);
    assert.ok(result.urgency.evidence.some(e => /urgent/i.test(e)));
    assert.ok(result.urgency.evidence.some(e => /immediately/i.test(e)));

    assert.strictEqual(result.threat.detected, true);
    assert.ok(result.threat.evidence.some(e => /account will be suspended/i.test(e)));

    assert.strictEqual(result.credentialRequest.detected, true);
    assert.strictEqual(result.passwordRequest, true);
    assert.strictEqual(result.socialEngineering.detected, true);
    assert.ok(result.socialEngineering.reasons.length >= 2);
    assert.ok(result.flags.includes('Urgency language detected'));
    assert.ok(result.flags.includes('Account threat detected'));
    assert.ok(result.flags.includes('Credential request detected'));
  });

  // TEST 3 — OTP scam
  it('TEST 3 — OTP / Bank account verification scam', () => {
    const text = 'Your bank account requires verification. Send the OTP to confirm your identity.';
    const result = analyzeMessage(text);

    assert.strictEqual(result.otpRequest, true);
    assert.strictEqual(result.credentialRequest.detected, true);
    assert.strictEqual(result.verificationRequest.detected, true);
    assert.ok(result.verificationRequest.evidence.some(e => /requires verification/i.test(e)));
    assert.ok(result.flags.includes('One-time password (OTP) request detected'));
    assert.ok(result.flags.includes('Verification request detected'));
  });

  // TEST 4 — Payment scam
  it('TEST 4 — Payment scam with urgent threat', () => {
    const text = 'Your payment failed. Pay immediately to avoid account suspension.';
    const result = analyzeMessage(text);

    assert.strictEqual(result.paymentRequest, true);
    assert.strictEqual(result.urgency.detected, true);
    assert.strictEqual(result.threat.detected, true);
    assert.strictEqual(result.socialEngineering.detected, true);
    assert.ok(result.socialEngineering.reasons.some(r => r.includes('Payment')));
    assert.ok(result.flags.includes('Payment demand detected'));
  });

  // TEST 5 — Message containing URL
  it('TEST 5 — Message containing embedded URL (URL must NOT be visited)', () => {
    const text = 'Verify your account here:\nhttps://example.com/login';
    const result = analyzeMessage(text);

    assert.strictEqual(result.extractedUrls.length, 1);
    assert.strictEqual(result.extractedUrls[0], 'https://example.com/login');
    assert.strictEqual(result.verificationRequest.detected, true);
    assert.ok(result.flags.some(f => f.includes('Contains 1 embedded URL(s)')));
  });

  // TEST 6 — False-positive test
  it('TEST 6 — Legitimate workplace message containing "login" and "verify" (False Positive Prevention)', () => {
    const text = 'Please verify the login issue with the IT team tomorrow.';
    const result = analyzeMessage(text);

    // Must NOT be classified as social engineering or threat
    assert.strictEqual(result.socialEngineering.detected, false);
    assert.strictEqual(result.urgency.detected, false);
    assert.strictEqual(result.threat.detected, false);
    assert.strictEqual(result.passwordRequest, false);
    assert.strictEqual(result.otpRequest, false);
    assert.strictEqual(result.pinRequest, false);
    assert.strictEqual(result.paymentRequest, false);
  });

  // Additional Edge Cases
  it('7. PIN request detection', () => {
    const text = 'Enter your 4-digit ATM PIN now to unlock your debit card.';
    const result = analyzeMessage(text);
    assert.strictEqual(result.pinRequest, true);
    assert.strictEqual(result.credentialRequest.detected, true);
  });

  it('8. Multiple URLs extraction with trailing punctuation cleaning', () => {
    const text = 'Check these portals: https://site1.org/update, and https://site2.com/test.';
    const urls = extractUrls(text);
    assert.strictEqual(urls.length, 2);
    assert.strictEqual(urls[0], 'https://site1.org/update');
    assert.strictEqual(urls[1], 'https://site2.com/test');
  });

  it('9. Empty and invalid input handling', () => {
    const emptyResult = analyzeMessage('');
    assert.strictEqual(emptyResult.valid, false);

    const nullResult = analyzeMessage(null);
    assert.strictEqual(nullResult.valid, false);
  });
});

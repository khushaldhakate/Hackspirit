/**
 * PhishGuard Message Analyzer Service (Phase 3)
 * Analyzes SMS, email, WhatsApp, and text messages for social-engineering,
 * threat signals, credential requests, and embedded URLs.
 * NOTE: Pure textual analysis — does NOT visit URLs, call LLMs, or execute code.
 */

const {
  URGENCY_PATTERNS,
  THREAT_PATTERNS,
  CREDENTIAL_PATTERNS,
  PAYMENT_PATTERNS,
  VERIFICATION_PATTERNS,
  CALL_TO_ACTION_PATTERNS,
  AUTHORITY_PATTERNS
} = require('../config/messageSignals');

/**
 * Extract all HTTP/HTTPS URLs from raw text using static regex
 * @param {string} text 
 * @returns {string[]} Array of extracted URLs
 */
function extractUrls(text) {
  if (!text || typeof text !== 'string') return [];
  
  // Static regex matching web URLs
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
  const matches = text.match(urlRegex) || [];
  
  // Clean trailing punctuation attached from surrounding sentence syntax
  return matches.map(url => url.replace(/[.,;:!?)}\]]+$/, ''));
}

/**
 * Helper to match regex patterns against text and collect human-readable evidence
 */
function matchPatterns(text, patterns) {
  const evidence = new Set();
  for (const { pattern, label } of patterns) {
    const match = text.match(pattern);
    if (match) {
      evidence.add(match[0]);
    }
  }
  return Array.from(evidence);
}

/**
 * Analyze a message text for phishing indicators and social engineering tactics
 * @param {string} text - Raw message text
 * @returns {object} Structured signal analysis
 */
function analyzeMessage(text) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return {
      valid: false,
      error: 'Message text is required and must be a non-empty string',
      flags: ['Empty or missing message input']
    };
  }

  const rawText = text.trim();

  // 1. Urgency Detection
  const urgencyEvidence = matchPatterns(rawText, URGENCY_PATTERNS);
  const urgency = {
    detected: urgencyEvidence.length > 0,
    evidence: urgencyEvidence
  };

  // 2. Threat Detection
  const threatEvidence = matchPatterns(rawText, THREAT_PATTERNS);
  const threat = {
    detected: threatEvidence.length > 0,
    evidence: threatEvidence
  };

  // 3. Credential Detection
  const passwordEvidence = matchPatterns(rawText, CREDENTIAL_PATTERNS.password);
  const otpEvidence = matchPatterns(rawText, CREDENTIAL_PATTERNS.otp);
  const pinEvidence = matchPatterns(rawText, CREDENTIAL_PATTERNS.pin);
  const generalCredEvidence = matchPatterns(rawText, CREDENTIAL_PATTERNS.general);

  const passwordRequest = passwordEvidence.length > 0;
  const otpRequest = otpEvidence.length > 0;
  const pinRequest = pinEvidence.length > 0;
  
  const allCredEvidence = [
    ...passwordEvidence,
    ...otpEvidence,
    ...pinEvidence,
    ...generalCredEvidence
  ];

  const credentialRequest = {
    detected: allCredEvidence.length > 0,
    evidence: allCredEvidence
  };

  // 4. Payment Detection
  const paymentEvidence = matchPatterns(rawText, PAYMENT_PATTERNS);
  const paymentRequest = paymentEvidence.length > 0;

  // 5. Verification Request Detection
  const verificationEvidence = matchPatterns(rawText, VERIFICATION_PATTERNS);
  const verificationRequest = {
    detected: verificationEvidence.length > 0,
    evidence: verificationEvidence
  };

  // 6. Call-To-Action Detection
  const ctaEvidence = matchPatterns(rawText, CALL_TO_ACTION_PATTERNS);
  const callToAction = {
    detected: ctaEvidence.length > 0,
    evidence: ctaEvidence
  };

  // 7. Authority Detection
  const authorityEvidence = matchPatterns(rawText, AUTHORITY_PATTERNS);
  const authorityDetected = authorityEvidence.length > 0;

  // 8. URL Extraction (Pure static, never executed)
  const extractedUrls = extractUrls(rawText);

  // 9. Social Engineering Indicator Synthesis
  const socialEngineeringReasons = [];

  if (urgency.detected && threat.detected) {
    socialEngineeringReasons.push('Urgency combined with account threat');
  }
  if (credentialRequest.detected && urgency.detected) {
    socialEngineeringReasons.push('Credential request combined with urgency');
  }
  if (threat.detected && credentialRequest.detected) {
    socialEngineeringReasons.push('Account threat combined with credential request');
  }
  if (paymentRequest && urgency.detected) {
    socialEngineeringReasons.push('Payment request combined with artificial urgency');
  }
  if (paymentRequest && threat.detected) {
    socialEngineeringReasons.push('Payment demand combined with threat of suspension');
  }
  if (authorityDetected && credentialRequest.detected) {
    socialEngineeringReasons.push('Authority impersonation combined with credential request');
  }
  if (otpRequest && verificationRequest.detected) {
    socialEngineeringReasons.push('Solicitation of one-time password (OTP) disguised as verification');
  }

  const socialEngineering = {
    detected: socialEngineeringReasons.length > 0,
    reasons: socialEngineeringReasons
  };

  // 10. Human-Readable Evidence Flags
  const flags = [];
  if (urgency.detected) flags.push('Urgency language detected');
  if (threat.detected) flags.push('Account threat detected');
  if (credentialRequest.detected) flags.push('Credential request detected');
  if (passwordRequest) flags.push('Password request detected');
  if (otpRequest) flags.push('One-time password (OTP) request detected');
  if (pinRequest) flags.push('PIN request detected');
  if (paymentRequest) flags.push('Payment demand detected');
  if (verificationRequest.detected) flags.push('Verification request detected');
  if (callToAction.detected) flags.push('Call-to-action detected');
  if (socialEngineering.detected) flags.push('Social engineering tactics detected');
  if (extractedUrls.length > 0) flags.push(`Contains ${extractedUrls.length} embedded URL(s)`);

  return {
    text: rawText,
    urgency,
    threat,
    credentialRequest,
    passwordRequest,
    otpRequest,
    pinRequest,
    paymentRequest,
    verificationRequest,
    callToAction,
    socialEngineering,
    extractedUrls,
    flags
  };
}

module.exports = {
  analyzeMessage,
  extractUrls
};

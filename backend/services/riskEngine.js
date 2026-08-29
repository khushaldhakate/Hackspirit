/**
 * PhishGuard Risk Engine Service (Phase 6)
 * Synthesizes evidence from URL Analyzer, Message Analyzer, Redirect Analyzer,
 * and the pretrained ML service into a deterministic, explainable risk score (0-100).
 * 
 * NOTE: Pure in-memory evidence evaluation. Does NOT make network requests,
 * call LLMs, or execute code.
 */

const {
  CATEGORY_CAPS,
  RISK_THRESHOLDS,
  SIGNAL_WEIGHTS,
  CORRELATION_RULES
} = require('../config/riskWeights');

/**
 * Determine risk level category based on normalized score (0-100)
 * @param {number} score 
 * @returns {string} LOW | MEDIUM | HIGH | CRITICAL
 */
function determineRiskLevel(score) {
  if (score <= RISK_THRESHOLDS.LOW.max) return RISK_THRESHOLDS.LOW.label;
  if (score <= RISK_THRESHOLDS.MEDIUM.max) return RISK_THRESHOLDS.MEDIUM.label;
  if (score <= RISK_THRESHOLDS.HIGH.max) return RISK_THRESHOLDS.HIGH.label;
  return RISK_THRESHOLDS.CRITICAL.label;
}

/**
 * Extract and score URL evidence items
 * @param {object} urlAnalysis - Output from analyzeUrl()
 * @returns {{ evidence: Array, rawPoints: number, cappedPoints: number }}
 */
function evaluateUrlSignals(urlAnalysis) {
  const evidence = [];
  if (!urlAnalysis || !urlAnalysis.valid) {
    return { evidence, rawPoints: 0, cappedPoints: 0 };
  }

  const weights = SIGNAL_WEIGHTS.url;
  let rawPoints = 0;

  // 1. Lookalike domain impersonation
  if (urlAnalysis.lookalike && urlAnalysis.lookalike.detected) {
    const brand = urlAnalysis.lookalike.matchedBrand || 'known brand';
    const pts = weights.lookalike_domain.points;
    rawPoints += pts;
    evidence.push({
      signal: 'lookalike_domain',
      category: 'url',
      points: pts,
      reason: `Domain resembles trusted brand '${brand}' (impersonation vector)`
    });
  }

  // 2. IP address host
  if (urlAnalysis.isIpAddress) {
    const pts = weights.ip_address_host.points;
    rawPoints += pts;
    evidence.push({
      signal: 'ip_address_host',
      category: 'url',
      points: pts,
      reason: weights.ip_address_host.reason
    });
  }

  // 3. Suspicious / high-abuse TLD
  if (urlAnalysis.suspiciousTld) {
    const pts = weights.suspicious_tld.points;
    rawPoints += pts;
    evidence.push({
      signal: 'suspicious_tld',
      category: 'url',
      points: pts,
      reason: weights.suspicious_tld.reason
    });
  }

  // 4. '@' symbol userinfo delimiter
  if (urlAnalysis.hasAtSymbol) {
    const pts = weights.at_symbol_obfuscation.points;
    rawPoints += pts;
    evidence.push({
      signal: 'at_symbol_obfuscation',
      category: 'url',
      points: pts,
      reason: weights.at_symbol_obfuscation.reason
    });
  }

  // 5. Excessive subdomains
  if (urlAnalysis.excessiveSubdomains) {
    const pts = weights.excessive_subdomains.points;
    rawPoints += pts;
    evidence.push({
      signal: 'excessive_subdomains',
      category: 'url',
      points: pts,
      reason: weights.excessive_subdomains.reason
    });
  }

  // 6. Obfuscation & encoding
  if (urlAnalysis.obfuscation || urlAnalysis.hasEncoding) {
    const pts = weights.obfuscated_encoding.points;
    rawPoints += pts;
    evidence.push({
      signal: 'obfuscated_encoding',
      category: 'url',
      points: pts,
      reason: weights.obfuscated_encoding.reason
    });
  }

  // 7. Suspicious keywords
  if (Array.isArray(urlAnalysis.suspiciousKeywords) && urlAnalysis.suspiciousKeywords.length > 0) {
    const kwCount = urlAnalysis.suspiciousKeywords.length;
    const pts = Math.min(kwCount * weights.suspicious_keyword.points, weights.suspicious_keyword.maxPoints);
    rawPoints += pts;
    evidence.push({
      signal: 'suspicious_keywords',
      category: 'url',
      points: pts,
      reason: `Suspicious keywords found: ${urlAnalysis.suspiciousKeywords.slice(0, 4).join(', ')}`
    });
  }

  // 8. Abnormal URL length (> 120 chars)
  if (urlAnalysis.urlLength > 120) {
    const pts = weights.excessive_length.points;
    rawPoints += pts;
    evidence.push({
      signal: 'excessive_length',
      category: 'url',
      points: pts,
      reason: weights.excessive_length.reason
    });
  }

  // 9. Special character concentration (>= 4 non-standard chars)
  if (urlAnalysis.specialCharacterCount >= 4) {
    const pts = weights.suspicious_special_chars.points;
    rawPoints += pts;
    evidence.push({
      signal: 'suspicious_special_chars',
      category: 'url',
      points: pts,
      reason: weights.suspicious_special_chars.reason
    });
  }

  // 10. Unencrypted HTTP
  if (urlAnalysis.protocol === 'http:' && !urlAnalysis.https) {
    const pts = weights.unencrypted_http.points;
    rawPoints += pts;
    evidence.push({
      signal: 'unencrypted_http',
      category: 'url',
      points: pts,
      reason: weights.unencrypted_http.reason
    });
  }

  const cappedPoints = Math.min(rawPoints, CATEGORY_CAPS.url);
  return { evidence, rawPoints, cappedPoints };
}

/**
 * Extract and score Message evidence items with anti-double-counting logic
 * @param {object} messageAnalysis - Output from analyzeMessage()
 * @param {object} urlAnalysis - Output from analyzeUrl() for cross-signal correlation
 * @returns {{ evidence: Array, rawPoints: number, cappedPoints: number }}
 */
function evaluateMessageSignals(messageAnalysis, urlAnalysis) {
  const evidence = [];
  if (!messageAnalysis || !messageAnalysis.text) {
    return { evidence, rawPoints: 0, cappedPoints: 0 };
  }

  const weights = SIGNAL_WEIGHTS.message;
  let rawPoints = 0;

  // Track if a specific credential signal is already accounted for
  let specificCredentialDetected = false;

  // 1. Specific Credential Solicitation: OTP
  if (messageAnalysis.otpRequest) {
    specificCredentialDetected = true;
    const pts = weights.otp_request.points;
    rawPoints += pts;
    evidence.push({
      signal: 'otp_request',
      category: 'message',
      points: pts,
      reason: weights.otp_request.reason
    });
  }

  // 2. Specific Credential Solicitation: Password
  if (messageAnalysis.passwordRequest) {
    specificCredentialDetected = true;
    const pts = weights.password_request.points;
    rawPoints += pts;
    evidence.push({
      signal: 'password_request',
      category: 'message',
      points: pts,
      reason: weights.password_request.reason
    });
  }

  // 3. Specific Credential Solicitation: PIN
  if (messageAnalysis.pinRequest) {
    specificCredentialDetected = true;
    const pts = weights.pin_request.points;
    rawPoints += pts;
    evidence.push({
      signal: 'pin_request',
      category: 'message',
      points: pts,
      reason: weights.pin_request.reason
    });
  }

  // 4. General Credential Request (Avoid double-counting if specific credential already scored)
  if (messageAnalysis.credentialRequest && messageAnalysis.credentialRequest.detected && !specificCredentialDetected) {
    const pts = weights.general_credential_request.points;
    rawPoints += pts;
    evidence.push({
      signal: 'credential_request',
      category: 'message',
      points: pts,
      reason: weights.general_credential_request.reason
    });
  }

  // 5. Threat Language
  if (messageAnalysis.threat && messageAnalysis.threat.detected) {
    const pts = weights.threat.points;
    rawPoints += pts;
    evidence.push({
      signal: 'threat_language',
      category: 'message',
      points: pts,
      reason: weights.threat.reason
    });
  }

  // 6. Urgency Language
  if (messageAnalysis.urgency && messageAnalysis.urgency.detected) {
    const pts = weights.urgency.points;
    rawPoints += pts;
    evidence.push({
      signal: 'urgency_language',
      category: 'message',
      points: pts,
      reason: weights.urgency.reason
    });
  }

  // 7. Payment / Financial Demand
  if (messageAnalysis.paymentRequest) {
    const pts = weights.payment_request.points;
    rawPoints += pts;
    evidence.push({
      signal: 'payment_demand',
      category: 'message',
      points: pts,
      reason: weights.payment_request.reason
    });
  }

  // 8. Verification Request (with cross-correlation check against URL keywords)
  if (messageAnalysis.verificationRequest && messageAnalysis.verificationRequest.detected) {
    let pts = weights.verification_request.points;
    let reason = weights.verification_request.reason;

    // Cross-correlation deduplication:
    // If URL already triggered verification keywords, apply discount factor to avoid double-counting
    const urlHasVerifyKeyword = urlAnalysis && Array.isArray(urlAnalysis.suspiciousKeywords) &&
      urlAnalysis.suspiciousKeywords.some(kw => ['verify', 'verification', 'login', 'account'].includes(kw.toLowerCase()));

    if (urlHasVerifyKeyword) {
      pts = Math.round(pts * CORRELATION_RULES.crossVerificationDiscount);
      reason += ' (dampened to avoid double-counting with URL verification keyword)';
    }

    rawPoints += pts;
    evidence.push({
      signal: 'verification_request',
      category: 'message',
      points: pts,
      reason
    });
  }

  // 9. Call To Action
  if (messageAnalysis.callToAction && messageAnalysis.callToAction.detected) {
    const pts = weights.call_to_action.points;
    rawPoints += pts;
    evidence.push({
      signal: 'call_to_action',
      category: 'message',
      points: pts,
      reason: weights.call_to_action.reason
    });
  }

  // 10. Social Engineering Combination
  if (messageAnalysis.socialEngineering && messageAnalysis.socialEngineering.detected) {
    const pts = weights.social_engineering_combo.points;
    rawPoints += pts;
    const reasonsStr = messageAnalysis.socialEngineering.reasons
      ? messageAnalysis.socialEngineering.reasons.join('; ')
      : weights.social_engineering_combo.reason;
    evidence.push({
      signal: 'social_engineering_combination',
      category: 'message',
      points: pts,
      reason: `Social engineering synthesis: ${reasonsStr}`
    });
  }

  const cappedPoints = Math.min(rawPoints, CATEGORY_CAPS.message);
  return { evidence, rawPoints, cappedPoints };
}

/**
 * Extract and score Redirect chain evidence items
 * @param {object} redirectAnalysis - Output from analyzeRedirect()
 * @returns {{ evidence: Array, rawPoints: number, cappedPoints: number }}
 */
function evaluateRedirectSignals(redirectAnalysis) {
  const evidence = [];
  if (!redirectAnalysis) {
    return { evidence, rawPoints: 0, cappedPoints: 0 };
  }

  const weights = SIGNAL_WEIGHTS.redirect;
  let rawPoints = 0;

  // 1. Blocked Destination (SSRF / prohibited IP)
  if (redirectAnalysis.blocked) {
    const pts = weights.blocked_destination.points;
    rawPoints += pts;
    evidence.push({
      signal: 'blocked_unsafe_destination',
      category: 'redirect',
      points: pts,
      reason: redirectAnalysis.reason || weights.blocked_destination.reason
    });
  }

  // 2. Redirect Loop
  if (redirectAnalysis.error === 'REDIRECT_LOOP_DETECTED') {
    const pts = weights.redirect_loop.points;
    rawPoints += pts;
    evidence.push({
      signal: 'redirect_loop',
      category: 'redirect',
      points: pts,
      reason: weights.redirect_loop.reason
    });
  }

  // 3. Redirect Limit Exceeded
  if (redirectAnalysis.error === 'REDIRECT_LIMIT_EXCEEDED') {
    const pts = weights.redirect_limit_exceeded.points;
    rawPoints += pts;
    evidence.push({
      signal: 'redirect_limit_exceeded',
      category: 'redirect',
      points: pts,
      reason: weights.redirect_limit_exceeded.reason
    });
  }

  // 4. Multiple Redirects (>= 2 hops)
  if (redirectAnalysis.redirectCount >= 2 && !redirectAnalysis.blocked) {
    const pts = weights.multiple_redirects.points;
    rawPoints += pts;
    evidence.push({
      signal: 'multiple_redirects',
      category: 'redirect',
      points: pts,
      reason: `Chain of ${redirectAnalysis.redirectCount} redirects detected`
    });
  } else if (redirectAnalysis.redirectCount === 1 && !redirectAnalysis.blocked) {
    // 5. Single Redirect
    const pts = weights.single_redirect.points;
    rawPoints += pts;
    evidence.push({
      signal: 'single_redirect',
      category: 'redirect',
      points: pts,
      reason: weights.single_redirect.reason
    });
  }

  // 6. Suspicious Final Domain
  if (redirectAnalysis.finalDomain && redirectAnalysis.chain && redirectAnalysis.chain.length > 0) {
    // Check if initial domain navigated to a disparate final domain
    try {
      const initialHost = new URL(redirectAnalysis.chain[0].from).hostname;
      const finalHost = new URL(redirectAnalysis.finalUrl).hostname;
      if (initialHost && finalHost && initialHost !== finalHost) {
        const pts = weights.suspicious_final_domain.points;
        rawPoints += pts;
        evidence.push({
          signal: 'suspicious_final_domain',
          category: 'redirect',
          points: pts,
          reason: `Redirect chain landed on disparate destination host: ${finalHost} (from ${initialHost})`
        });
      }
    } catch (_) {}
  }

  const cappedPoints = Math.min(rawPoints, CATEGORY_CAPS.redirect);
  return { evidence, rawPoints, cappedPoints };
}

/**
 * Score pretrained ML model output transparently
 * @param {object} mlAnalysis - Output from analyzeUrlWithML()
 * @returns {{ evidence: Array, points: number, mlSummary: object|null }}
 */
function evaluateMLSignals(mlAnalysis) {
  const evidence = [];
  if (!mlAnalysis) {
    return { evidence, points: 0, mlSummary: null };
  }

  // Handle both raw object or { success: true, analysis: { ... } } wrapper
  const analysis = mlAnalysis.analysis ? mlAnalysis.analysis : mlAnalysis;
  const prediction = (analysis.prediction || '').toLowerCase();
  const probability = typeof analysis.probability === 'number' ? analysis.probability : 0;
  const modelName = analysis.model || 'urlbert-tiny-v4-malicious-url-classifier';

  if (!prediction) {
    return { evidence, points: 0, mlSummary: null };
  }

  const mlConfig = SIGNAL_WEIGHTS.ml;
  const multiplier = mlConfig.classMultipliers[prediction] !== undefined
    ? mlConfig.classMultipliers[prediction]
    : 0.0;

  // ML contribution = maxPoints (35) * classMultiplier * probability
  const points = Math.min(CATEGORY_CAPS.ml, Math.round(mlConfig.maxPoints * multiplier * probability));

  if (points > 0) {
    evidence.push({
      signal: `ml_${prediction}`,
      category: 'ml',
      points,
      reason: `Pretrained model (${modelName}) classified URL as '${prediction}' with ${(probability * 100).toFixed(1)}% probability`
    });
  }

  return {
    evidence,
    points,
    mlSummary: {
      prediction,
      probability
    }
  };
}

/**
 * Determine the primary threat category and confidence from accumulated evidence
 * @param {object} params
 * @returns {{ threatCategory: string, confidence: string }}
 */
function determineThreatCategory({
  riskScore,
  urlAnalysis,
  messageAnalysis,
  redirectAnalysis,
  mlAnalysis
}) {
  // 1. Clear Benign case
  if (riskScore <= 15) {
    return {
      threatCategory: 'benign',
      confidence: riskScore === 0 ? 'high' : 'medium'
    };
  }

  // Check ML classification
  const analysis = mlAnalysis && mlAnalysis.analysis ? mlAnalysis.analysis : mlAnalysis;
  const mlPrediction = analysis && analysis.prediction ? analysis.prediction.toLowerCase() : null;
  const mlProb = analysis && typeof analysis.probability === 'number' ? analysis.probability : 0;

  // 2. Credential Theft (highest severity pattern in social engineering & phishing)
  const isCredentialTheft = messageAnalysis && (
    messageAnalysis.otpRequest ||
    messageAnalysis.passwordRequest ||
    messageAnalysis.pinRequest ||
    (messageAnalysis.credentialRequest && messageAnalysis.credentialRequest.detected)
  );

  const isLookalikeWithCreds = urlAnalysis && urlAnalysis.lookalike && urlAnalysis.lookalike.detected &&
    (urlAnalysis.suspiciousKeywords || []).some(k => ['login', 'signin', 'verify', 'account'].includes(k));

  if (isCredentialTheft || isLookalikeWithCreds) {
    const highConfidence = isCredentialTheft && (messageAnalysis.urgency?.detected || messageAnalysis.threat?.detected);
    return {
      threatCategory: 'credential_theft',
      confidence: highConfidence ? 'high' : 'medium'
    };
  }

  // 3. Malware (from ML model or dangerous download indicator)
  if (mlPrediction === 'malware' && mlProb >= 0.5) {
    return {
      threatCategory: 'malware',
      confidence: mlProb >= 0.8 ? 'high' : 'medium'
    };
  }

  // 4. Defacement (from ML model)
  if (mlPrediction === 'defacement' && mlProb >= 0.5) {
    return {
      threatCategory: 'defacement',
      confidence: mlProb >= 0.8 ? 'high' : 'medium'
    };
  }

  // 5. Phishing (ML predicted phishing, or lookalike domain, or deceptive redirect)
  const isLookalike = urlAnalysis && urlAnalysis.lookalike && urlAnalysis.lookalike.detected;
  const isMlPhishing = mlPrediction === 'phishing' && mlProb >= 0.5;

  if (isMlPhishing || isLookalike) {
    const highConfidence = (isMlPhishing && mlProb >= 0.8) || (isLookalike && isMlPhishing);
    return {
      threatCategory: 'phishing',
      confidence: highConfidence ? 'high' : 'medium'
    };
  }

  // 6. Social Engineering (Message has urgency, threat, or payment extortion without specific credential theft)
  if (messageAnalysis && (messageAnalysis.socialEngineering?.detected || messageAnalysis.paymentRequest)) {
    return {
      threatCategory: 'social_engineering',
      confidence: 'medium'
    };
  }

  // 7. Suspicious URL (Structural anomalies: IP host, suspicious TLD, excessive subdomains, obfuscation)
  if (urlAnalysis && (urlAnalysis.isIpAddress || urlAnalysis.suspiciousTld || urlAnalysis.excessiveSubdomains || urlAnalysis.obfuscation)) {
    return {
      threatCategory: 'suspicious_url',
      confidence: 'medium'
    };
  }

  // 8. SSRF / Unsafe Destination blocked
  if (redirectAnalysis && redirectAnalysis.blocked) {
    return {
      threatCategory: 'suspicious_url',
      confidence: 'high'
    };
  }

  // Default fallback for ambiguous cases
  if (riskScore <= 30) {
    return {
      threatCategory: 'benign',
      confidence: 'low'
    };
  }

  return {
    threatCategory: 'unknown',
    confidence: 'low'
  };
}

/**
 * Generate human-readable summary bullets explaining the risk assessment
 * @param {Array} evidence 
 * @param {string} riskLevel 
 * @param {string} threatCategory 
 * @returns {string[]}
 */
function generateSummary(evidence, riskLevel, threatCategory) {
  if (!evidence || evidence.length === 0) {
    return ['No suspicious signals or threat indicators detected. Request evaluated as benign.'];
  }

  const summaries = [];

  // Group by category to generate clear narrative points
  const urlSignals = evidence.filter(e => e.category === 'url');
  const msgSignals = evidence.filter(e => e.category === 'message');
  const redirSignals = evidence.filter(e => e.category === 'redirect');
  const mlSignals = evidence.filter(e => e.category === 'ml');

  if (urlSignals.length > 0) {
    const topUrl = urlSignals.sort((a, b) => b.points - a.points)[0];
    summaries.push(`URL structure: ${topUrl.reason}`);
  }

  if (msgSignals.length > 0) {
    const topMsg = msgSignals.sort((a, b) => b.points - a.points)[0];
    summaries.push(`Message content: ${topMsg.reason}`);
  }

  if (redirSignals.length > 0) {
    const topRedir = redirSignals.sort((a, b) => b.points - a.points)[0];
    summaries.push(`Redirect analysis: ${topRedir.reason}`);
  }

  if (mlSignals.length > 0) {
    summaries.push(`Machine learning: ${mlSignals[0].reason}`);
  }

  summaries.push(`Final risk determination: ${riskLevel} risk with primary threat category '${threatCategory}'.`);

  return summaries;
}

/**
 * Master Risk Engine Evaluation
 * Fuses evidence from all analyzer layers into a normalized, explainable risk assessment.
 * 
 * @param {object} params
 * @param {object} [params.urlAnalysis] - Analysis result from urlAnalyzer.js
 * @param {object} [params.messageAnalysis] - Analysis result from messageAnalyzer.js
 * @param {object} [params.redirectAnalysis] - Analysis result from redirectAnalyzer.js
 * @param {object} [params.mlAnalysis] - Analysis result from mlService.js
 * @returns {object} Final explainable risk assessment
 */
function evaluateRisk({
  urlAnalysis = null,
  messageAnalysis = null,
  redirectAnalysis = null,
  mlAnalysis = null
} = {}) {
  // 1. Evaluate individual signal groups
  const urlResult = evaluateUrlSignals(urlAnalysis);
  const msgResult = evaluateMessageSignals(messageAnalysis, urlAnalysis);
  const redirResult = evaluateRedirectSignals(redirectAnalysis);
  const mlResult = evaluateMLSignals(mlAnalysis);

  // 2. Aggregate score breakdown with group maximum caps enforced
  const scoreBreakdown = {
    url: urlResult.cappedPoints,
    message: msgResult.cappedPoints,
    redirect: redirResult.cappedPoints,
    ml: mlResult.points
  };

  // 3. Compute normalized total risk score: strictly bounded to [0, 100]
  const rawTotal = scoreBreakdown.url + scoreBreakdown.message + scoreBreakdown.redirect + scoreBreakdown.ml;
  const riskScore = Math.min(100, Math.max(0, Math.round(rawTotal)));

  // 4. Determine risk level from thresholds
  const riskLevel = determineRiskLevel(riskScore);

  // 5. Consolidate evidence list
  const evidence = [
    ...urlResult.evidence,
    ...msgResult.evidence,
    ...redirResult.evidence,
    ...mlResult.evidence
  ];

  // 6. Determine primary threat category & confidence
  const { threatCategory, confidence } = determineThreatCategory({
    riskScore,
    urlAnalysis,
    messageAnalysis,
    redirectAnalysis,
    mlAnalysis
  });

  // 7. Generate explainable summary
  const summary = generateSummary(evidence, riskLevel, threatCategory);

  return {
    riskScore,
    riskLevel,
    threatCategory,
    confidence,
    ml: mlResult.mlSummary,
    scoreBreakdown,
    evidence,
    summary
  };
}

module.exports = {
  determineRiskLevel,
  evaluateUrlSignals,
  evaluateMessageSignals,
  evaluateRedirectSignals,
  evaluateMLSignals,
  determineThreatCategory,
  evaluateRisk
};

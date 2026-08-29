/**
 * PhishGuard Risk Engine Configuration (Phase 6)
 * Centralized, configurable weights, category maximums, and risk thresholds.
 * Total maximum score across all evidence groups is strictly capped at 100.
 */

// Maximum point budgets for evidence groups (Total: 100)
const CATEGORY_CAPS = {
  url: 25,
  message: 25,
  redirect: 15,
  ml: 35
};

// Risk Level Classification Thresholds
const RISK_THRESHOLDS = {
  LOW: { min: 0, max: 30, label: 'LOW' },
  MEDIUM: { min: 31, max: 60, label: 'MEDIUM' },
  HIGH: { min: 61, max: 80, label: 'HIGH' },
  CRITICAL: { min: 81, max: 100, label: 'CRITICAL' }
};

// Evidence Signal Weights
const SIGNAL_WEIGHTS = {
  url: {
    lookalike_domain: { points: 20, reason: 'Domain resembles a known or trusted brand (impersonation vector)' },
    ip_address_host: { points: 15, reason: 'Hostname is a raw IP address instead of a domain name' },
    suspicious_tld: { points: 10, reason: 'Top-level domain has known high abuse and malicious activity history' },
    at_symbol_obfuscation: { points: 12, reason: 'URL contains "@" userinfo delimiter commonly used in phishing camouflage' },
    excessive_subdomains: { points: 8, reason: 'Excessive subdomain depth often used to disguise deceptive hostnames' },
    obfuscated_encoding: { points: 10, reason: 'URL uses excessive percent-encoding or multi-encoding obfuscation' },
    suspicious_keyword: { points: 4, maxPoints: 12, reason: 'Credential or account security keywords found in URL path or query' },
    excessive_length: { points: 5, reason: 'Abnormally long URL length typical of tracking and token payloads' },
    suspicious_special_chars: { points: 4, reason: 'High concentration of suspicious non-standard symbols' },
    unencrypted_http: { points: 5, reason: 'Unencrypted HTTP protocol transmitting sensitive context' }
  },

  message: {
    otp_request: { points: 14, reason: 'Solicitation of one-time password (OTP) detected' },
    password_request: { points: 12, reason: 'Direct password or login credential solicitation detected' },
    pin_request: { points: 12, reason: 'Solicitation of secret PIN code detected' },
    general_credential_request: { points: 10, reason: 'General credential or account details requested' },
    threat: { points: 8, reason: 'Coercive account termination, suspension, or penalty threat detected' },
    urgency: { points: 6, reason: 'Artificial urgency or strict deadline pressure tactics detected' },
    payment_request: { points: 12, reason: 'Payment, fund transfer, or financial compensation demand detected' },
    verification_request: { points: 6, reason: 'Security or identity verification demand detected' },
    call_to_action: { points: 4, reason: 'Actionable directive urging immediate interaction detected' },
    social_engineering_combo: { points: 10, reason: 'Synergistic social engineering combination detected (e.g. urgency + threat + credential demand)' }
  },

  redirect: {
    blocked_destination: { points: 15, reason: 'Redirect attempts to access blocked, private, or prohibited network destination (SSRF hazard)' },
    redirect_loop: { points: 12, reason: 'Circular redirect loop detected' },
    redirect_limit_exceeded: { points: 10, reason: 'Excessive redirect chain exceeding safe hop limit (5 hops)' },
    suspicious_final_domain: { points: 10, reason: 'Redirect navigates to a disparate or suspicious final domain' },
    multiple_redirects: { points: 7, reason: 'Multiple intermediate redirect hops detected' },
    single_redirect: { points: 3, reason: 'Single redirect hop detected' }
  },

  ml: {
    maxPoints: 35,
    classMultipliers: {
      phishing: 1.0,    // max 35 * probability
      malware: 1.0,     // max 35 * probability
      defacement: 0.8,  // max 28 * probability
      benign: 0.0       // 0 points
    }
  }
};

// Correlation discount / deduplication rules
const CORRELATION_RULES = {
  // Discount factor applied when URL and Message signals redundantly report verification/credentials
  crossVerificationDiscount: 0.5
};

module.exports = {
  CATEGORY_CAPS,
  RISK_THRESHOLDS,
  SIGNAL_WEIGHTS,
  CORRELATION_RULES
};

/**
 * Message Threat Signals Configuration for PhishGuard (Phase 3)
 * Transparent and maintainable regex patterns and keyword definitions
 */

const URGENCY_PATTERNS = [
  { pattern: /\b(urgent|urgently)\b/i, label: 'urgent' },
  { pattern: /\b(immediately|right away|at once)\b/i, label: 'immediately' },
  { pattern: /\bact now\b/i, label: 'act now' },
  { pattern: /\b(within \d{1,2}\s*(hours?|hrs?|mins?|minutes?))\b/i, label: 'time-bound deadline' },
  { pattern: /\b(last warning|final warning|final notice)\b/i, label: 'final warning' },
  { pattern: /\b(immediately verify|verify immediately)\b/i, label: 'immediately verify' },
  { pattern: /\b(suspended today|blocked today|expires? today)\b/i, label: 'today deadline' },
  { pattern: /\b(time-sensitive|critical update|immediate action required)\b/i, label: 'action required immediately' }
];

const THREAT_PATTERNS = [
  { pattern: /\baccount will be (suspended|blocked|closed|terminated|disabled|locked)\b/i, label: 'account will be suspended' },
  { pattern: /\b(avoid account suspension|avoid being blocked|prevent suspension)\b/i, label: 'avoid account suspension' },
  { pattern: /\b(legal action|law enforcement|police action|court order)\b/i, label: 'legal action' },
  { pattern: /\b(security alert|unauthorized activity|suspicious login attempt)\b/i, label: 'security alert' },
  { pattern: /\b(access (will be |has been )?(revoked|restricted))\b/i, label: 'access restricted' },
  { pattern: /\b(permanently (deleted|closed|banned))\b/i, label: 'permanently deleted' }
];

const CREDENTIAL_PATTERNS = {
  password: [
    { pattern: /\b(passwords?|passcode|pass phrase)\b/i, label: 'password' }
  ],
  otp: [
    { pattern: /\b(otp|one[- ]time[- ]password|verification code|security code)\b/i, label: 'OTP' }
  ],
  pin: [
    { pattern: /\b(pin|pin code|mpin|atm pin)\b/i, label: 'PIN' }
  ],
  general: [
    { pattern: /\b(login credentials?|user credentials?|username and password)\b/i, label: 'login credentials' },
    { pattern: /\b(social security|ssn|secret key|private key)\b/i, label: 'sensitive secret' }
  ]
};

const PAYMENT_PATTERNS = [
  { pattern: /\b(pay immediately|make a payment|send money|transfer funds)\b/i, label: 'direct payment demand' },
  { pattern: /\b(payment failed|payment declined|overdue payment|unpaid bill|unpaid invoice)\b/i, label: 'failed payment notice' },
  { pattern: /\b(bank account|credit card|debit card|cvv|expiry date)\b/i, label: 'banking / card details' },
  { pattern: /\b(upi pin|wire transfer|crypto payment|wallet address)\b/i, label: 'wire / wallet transaction' }
];

const VERIFICATION_PATTERNS = [
  { pattern: /\b(verify your (account|identity|details|profile|phone|email))\b/i, label: 'verify your account' },
  { pattern: /\b(requires? verification|verification required|identity verification)\b/i, label: 'requires verification' },
  { pattern: /\b(re-verify|confirm your identity|validate your account)\b/i, label: 'confirm identity' }
];

const CALL_TO_ACTION_PATTERNS = [
  { pattern: /\b(click here|click this link|click below)\b/i, label: 'click here' },
  { pattern: /\b(verify now|verify your account now)\b/i, label: 'verify now' },
  { pattern: /\b(login now|log in now|sign in now)\b/i, label: 'login now' },
  { pattern: /\b(confirm now|confirm identity now)\b/i, label: 'confirm now' },
  { pattern: /\b(update account|update your details now)\b/i, label: 'update account' },
  { pattern: /\b(open the link|tap this link|follow the link|visit the link)\b/i, label: 'open the link' }
];

const AUTHORITY_PATTERNS = [
  { pattern: /\b(security team|fraud department|customer support|official notice|compliance division)\b/i, label: 'official authority body' },
  { pattern: /\b(internal revenue|irs|tax department|fbi|cyber crime)\b/i, label: 'government authority' }
];

module.exports = {
  URGENCY_PATTERNS,
  THREAT_PATTERNS,
  CREDENTIAL_PATTERNS,
  PAYMENT_PATTERNS,
  VERIFICATION_PATTERNS,
  CALL_TO_ACTION_PATTERNS,
  AUTHORITY_PATTERNS
};

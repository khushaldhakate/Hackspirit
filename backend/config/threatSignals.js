/**
 * Threat Signals Configuration for PhishGuard
 * Contains configurable dictionaries for heuristic inspection
 */

const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'verify',
  'verification',
  'account',
  'secure',
  'security',
  'update',
  'password',
  'credential',
  'wallet',
  'payment',
  'confirm',
  'confirmation',
  'bank',
  'banking',
  'unlock',
  'suspended',
  'suspension',
  'support',
  'billing',
  'auth',
  'authenticate',
  'authentication',
  'recover',
  'recovery',
  'safety',
  'alert',
  'validate',
  'validation',
  'claim',
  'prize',
  'bonus',
  'tax-refund',
  'invoice'
];

const SUSPICIOUS_TLDS = [
  '.xyz',
  '.top',
  '.tk',
  '.ml',
  '.cf',
  '.gq',
  '.buzz',
  '.fit',
  '.rest',
  '.icu',
  '.work',
  '.click',
  '.link',
  '.cc',
  '.to',
  '.gdn',
  '.racing',
  '.download',
  '.stream',
  '.loan',
  '.win',
  '.bid',
  '.vip',
  '.party',
  '.trade',
  '.date',
  '.review',
  '.country',
  '.kim',
  '.cricket',
  '.science',
  '.space',
  '.monster',
  '.cfd',
  '.sbs',
  '.quest',
  '.mom',
  '.beauty',
  '.hair',
  '.skin',
  '.boats',
  '.homes'
];

/**
 * Trusted Brand Profiles for Lookalike / Typosquatting Detection
 * Each brand defines its canonical name, alias patterns, and legitimate root domains.
 */
const BRAND_PROFILES = [
  {
    brand: 'paypal',
    patterns: ['paypal', 'paypa1', 'paypaI', 'pay-pal', 'paypol', 'payp4l'],
    legitDomains: ['paypal.com', 'paypal.me', 'paypal-community.com']
  },
  {
    brand: 'microsoft',
    patterns: ['microsoft', 'micros0ft', 'micr0soft', 'micro-soft', 'm1crosoft', 'microsof1'],
    legitDomains: [
      'microsoft.com',
      'live.com',
      'office.com',
      'office365.com',
      'outlook.com',
      'windows.com',
      'msn.com',
      'sharepoint.com',
      'azure.com',
      'bing.com',
      'visualstudio.com'
    ]
  },
  {
    brand: 'google',
    patterns: ['google', 'g00gle', 'g0ogle', 'go0gle', 'goog1e', 'googl-e', 'gooogle'],
    legitDomains: [
      'google.com',
      'youtube.com',
      'gmail.com',
      'google.co.in',
      'google.co.uk',
      'google.ca',
      'google.de',
      'google.fr',
      'google.com.br',
      'google.com.au',
      'android.com',
      'googleusercontent.com',
      'googlevideo.com',
      'gstatic.com',
      'googleapis.com'
    ]
  },
  {
    brand: 'apple',
    patterns: ['apple', 'app1e', 'app-le', 'appie', 'appl-e'],
    legitDomains: ['apple.com', 'icloud.com', 'itunes.com']
  },
  {
    brand: 'amazon',
    patterns: ['amazon', 'amaz0n', 'amazn', 'amz-on', 'amaz-on', 'am4zon'],
    legitDomains: [
      'amazon.com',
      'amazon.co.uk',
      'amazon.in',
      'amazon.de',
      'amazon.fr',
      'amazon.co.jp',
      'amazon.ca',
      'primevideo.com',
      'media-amazon.com',
      'amazonaws.com'
    ]
  },
  {
    brand: 'facebook',
    patterns: ['facebook', 'faceb00k', 'faceb0k', 'face-book', 'fb'],
    legitDomains: ['facebook.com', 'meta.com', 'fb.com', 'messenger.com', 'meta.com']
  },
  {
    brand: 'instagram',
    patterns: ['instagram', '1nstagram', 'instagr4m', 'insta-gram'],
    legitDomains: ['instagram.com', 'cdninstagram.com']
  },
  {
    brand: 'netflix',
    patterns: ['netflix', 'netf1ix', 'net-flix', 'netflx', 'netfllx'],
    legitDomains: ['netflix.com', 'nflximg.net', 'nflxext.com']
  },
  {
    brand: 'chase',
    patterns: ['chase', 'ch4se', 'cha-se'],
    legitDomains: ['chase.com']
  },
  {
    brand: 'wellsfargo',
    patterns: ['wellsfargo', 'wells-fargo', 'wellsfarg0', 'we11sfargo'],
    legitDomains: ['wellsfargo.com']
  },
  {
    brand: 'bankofamerica',
    patterns: ['bankofamerica', 'bank-of-america', 'bofa', 'bank0famerica'],
    legitDomains: ['bankofamerica.com', 'bofa.com']
  },
  {
    brand: 'citibank',
    patterns: ['citibank', 'citi-bank', 'c1tibank', 'cit1bank', 'citi'],
    legitDomains: ['citi.com', 'citibank.com']
  },
  {
    brand: 'binance',
    patterns: ['binance', 'b1nance', 'bin-ance', 'binanc3'],
    legitDomains: ['binance.com', 'binance.org', 'binance.us', 'binance.me']
  },
  {
    brand: 'coinbase',
    patterns: ['coinbase', 'c0inbase', 'coin-base', 'coinbas3'],
    legitDomains: ['coinbase.com']
  },
  {
    brand: 'github',
    patterns: ['github', 'g1thub', 'git-hub', 'githvb'],
    legitDomains: ['github.com', 'github.io', 'githubassets.com', 'githubusercontent.com']
  },
  {
    brand: 'linkedin',
    patterns: ['linkedin', '1inkedin', 'linked-in', 'linkedln'],
    legitDomains: ['linkedin.com', 'licdn.com']
  },
  {
    brand: 'dropbox',
    patterns: ['dropbox', 'dr0pbox', 'drop-box'],
    legitDomains: ['dropbox.com', 'dropboxstatic.com']
  },
  {
    brand: 'adobe',
    patterns: ['adobe', 'ad0be', 'adob3'],
    legitDomains: ['adobe.com']
  },
  {
    brand: 'whatsapp',
    patterns: ['whatsapp', 'whats-app', 'wh4tsapp', 'whatsaap'],
    legitDomains: ['whatsapp.com', 'wa.me']
  },
  {
    brand: 'telegram',
    patterns: ['telegram', 'te1egram', 'tele-gram', 'telegrm'],
    legitDomains: ['telegram.org', 't.me']
  },
  {
    brand: 'spotify',
    patterns: ['spotify', 'sp0tify', 'spot-ify', 'spot1fy'],
    legitDomains: ['spotify.com', 'scdn.co']
  },
  {
    brand: 'twitter',
    patterns: ['twitter', 'tw1tter', 'twitt3r', 'tw-itter'],
    legitDomains: ['twitter.com', 'x.com', 't.co', 'twimg.com']
  },
  {
    brand: 'steam',
    patterns: ['steam', 'steampowered', 'st3am', 'steam-powered'],
    legitDomains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com']
  },
  {
    brand: 'roblox',
    patterns: ['roblox', 'r0blox', 'rob1ox', 'ro-blox', 'robl0x'],
    legitDomains: ['roblox.com', 'rbxcdn.com']
  }
];

module.exports = {
  SUSPICIOUS_KEYWORDS,
  SUSPICIOUS_TLDS,
  BRAND_PROFILES
};

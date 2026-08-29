import re
from urllib.parse import urlparse, unquote

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "password", "signin",
    "wallet", "payment", "bank", "billing", "confirm", "support", "credential",
    "security", "recovery", "auth", "authorize", "checkpoint", "validation"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "zip", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "monster", "fit", "rest", "country", "biz", "info", "cam", "kim", "party",
    "science", "gdn", "stream", "download", "link", "online", "site", "space"
}

KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "meta", "whatsapp", "bankofamerica", "wellsfargo", "chase",
    "binance", "coinbase", "metamask", "steam", "discord", "outlook", "yahoo"
]

KNOWN_OFFICIAL_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr", "google.org",
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "amazon.in",
    "github.com", "netflix.com", "facebook.com", "instagram.com", "meta.com",
    "whatsapp.com", "wikipedia.org", "youtube.com", "linkedin.com", "twitter.com", "x.com"
}

LOOKALIKE_REPLACEMENTS = {
    '0': 'o', '1': 'l', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', 'v': 'u'
}

def is_ip_address(hostname: str) -> bool:
    """Checks if hostname is an IPv4 address."""
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(ip_pattern, hostname))

def detect_lookalike_domain(domain_name: str) -> tuple[bool, str]:
    """Detects typosquatting / homoglyph tricks trying to mimic known brands."""
    domain_lower = domain_name.lower().strip()
    
    # 1. Check if domain is a verified authentic brand domain
    if domain_lower in KNOWN_OFFICIAL_DOMAINS or any(domain_lower.endswith(f".{d}") for d in KNOWN_OFFICIAL_DOMAINS):
        return False, ""

    # 2. Normalize numbers/digits commonly swapped in domain names (e.g., paypa1 -> paypal, go0gle -> google)
    normalized = domain_lower
    for digit, char in [('1', 'l'), ('0', 'o'), ('3', 'e'), ('4', 'a'), ('5', 's'), ('8', 'b')]:
        normalized = normalized.replace(digit, char)

    for brand in KNOWN_BRANDS:
        # Exact brand present in domain with digits swapped (e.g. paypa1)
        if brand in normalized and brand not in domain_lower:
            return True, f"Domain attempts to mimic brand '{brand.capitalize()}' using character substitution."
        
        # Check if brand is combined with deceptive hyphens / prefixes (e.g. paypal-login, google-verify)
        if brand in domain_lower:
            parts = domain_lower.split('.')
            main_sld = parts[-2] if len(parts) >= 2 else parts[0]
            if main_sld != brand and '-' in main_sld:
                return True, f"Domain contains brand name '{brand.capitalize()}' within an unofficial lookalike domain ('{main_sld}')."

    return False, ""

def analyze_url(raw_url: str) -> dict:
    """
    Performs passive structural analysis of a given URL.
    Returns signals and structured flag items (name, severity, reason).
    """
    # Ensure scheme for URL parsing
    url_to_parse = raw_url.strip()
    if not url_to_parse.startswith(("http://", "https://")):
        url_to_parse = "http://" + url_to_parse

    parsed = urlparse(url_to_parse)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = raw_url.strip()

    is_https = (scheme == "https")
    ip_based = is_ip_address(hostname)
    url_len = len(full_url)
    dot_count = full_url.count('.')
    hyphen_count = full_url.count('-')

    # Subdomain count
    host_parts = hostname.split('.')
    if ip_based:
        subdomain_count = 0
        tld = ""
    else:
        # e.g., sub.example.com -> 3 parts -> 1 subdomain
        subdomain_count = max(0, len(host_parts) - 2)
        tld = host_parts[-1].lower() if len(host_parts) > 1 else ""

    # Suspicious characters
    suspicious_chars = []
    for char in ['@', '%', '~', '!', '$']:
        if char in full_url:
            suspicious_chars.append(char)

    # URL encoding / obfuscation
    unquoted = unquote(full_url)
    has_encoding = ('%' in full_url)
    is_obfuscated = has_encoding or (unquoted != full_url and '%' in unquoted)

    # Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower()]

    # TLD check
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Lookalike & Impersonation check
    is_lookalike, lookalike_reason = detect_lookalike_domain(hostname)
    
    # Impersonation pattern in subdomains or subpaths
    impersonation_detected = False
    for brand in KNOWN_BRANDS:
        if brand in hostname.lower() and not hostname.lower().endswith(f".{brand}.com") and hostname.lower() != f"{brand}.com":
            impersonation_detected = True

    # Compile Signals
    signals = {
        "https": is_https,
        "ip_based": ip_based,
        "url_length": url_len,
        "subdomain_count": subdomain_count,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "suspicious_characters": suspicious_chars,
        "url_encoding_obfuscation": is_obfuscated,
        "suspicious_keywords": found_keywords,
        "suspicious_tld": is_suspicious_tld,
        "lookalike_domain": is_lookalike,
        "impersonation_patterns": impersonation_detected,
        "hostname": hostname,
        "tld": tld
    }

    # Generate Flags
    flags = []

    if not is_https:
        flags.append({
            "name": "Missing HTTPS Encryption",
            "severity": "MEDIUM",
            "reason": "URL uses unencrypted HTTP protocol, exposing sensitive input data to interception."
        })

    if ip_based:
        flags.append({
            "name": "IP-Based Hostname",
            "severity": "HIGH",
            "reason": "Domain points directly to a raw IP address instead of a registered domain name."
        })

    if is_lookalike:
        flags.append({
            "name": "Lookalike / Typosquatted Domain",
            "severity": "CRITICAL",
            "reason": lookalike_reason
        })

    if is_suspicious_tld:
        flags.append({
            "name": "High-Risk Top Level Domain (TLD)",
            "severity": "MEDIUM",
            "reason": f"TLD '.{tld}' is frequently associated with disposable phishing campaigns."
        })

    if url_len > 75:
        flags.append({
            "name": "Excessive URL Length",
            "severity": "LOW",
            "reason": f"URL length ({url_len} characters) is unusually long, often used to hide destination parameters."
        })

    if len(found_keywords) > 0:
        flags.append({
            "name": "Targeted Authentication Keywords",
            "severity": "MEDIUM",
            "reason": f"URL contains sensitive action keywords: {', '.join(found_keywords)}."
        })

    if '@' in suspicious_chars:
        flags.append({
            "name": "Embedded Credentials User Info (@ symbol)",
            "severity": "CRITICAL",
            "reason": "URL contains an '@' character used to obscure the actual destination server."
        })

    if subdomain_count >= 3:
        flags.append({
            "name": "Excessive Subdomains",
            "severity": "MEDIUM",
            "reason": f"URL contains {subdomain_count} subdomains, which can mask the true root host."
        })

    return {
        "signals": signals,
        "flags": flags
    }

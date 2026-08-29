import re

# Regex for extracting HTTP/HTTPS URLs from message body
URL_REGEX = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin \d+ hours?\b", r"\baction required\b",
    r"\basap\b", r"\bexpire\b", r"\bexpiring\b", r"\blimited time\b", r"\b24 hours\b"
]

THREAT_PATTERNS = [
    r"\bsuspend(ed)?\b", r"\bterminat(ed)?\b", r"\block(ed)?\b", r"\bblock(ed)?\b",
    r"\blegal action\b", r"\bunauthorized\b", r"\bsecurity alert\b", r"\bpenalty\b"
]

OTP_PATTERNS = [
    r"\botp\b", r"\bone-?time password\b", r"\bverification code\b", r"\bsecurity code\b",
    r"\b2fa code\b", r"\bpin code\b"
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bcredential\b", r"\blogin details\b", r"\bsecret key\b",
    r"\bsocial security\b", r"\bpasscode\b"
]

PAYMENT_PATTERNS = [
    r"\bpayment\b", r"\bbilling\b", r"\binvoice\b", r"\bcredit card\b",
    r"\brefund\b", r"\bbank account\b", r"\bwire transfer\b"
]

VERIFICATION_PATTERNS = [
    r"\bverify\b", r"\bverification\b", r"\bconfirm identity\b", r"\bvalidate\b",
    r"\bupdate account\b"
]

CTA_PATTERNS = [
    r"\bclick (here|the link|below)\b", r"\bverify now\b", r"\bact now\b",
    r"\bupdate immediately\b", r"\bopen link\b"
]

def extract_urls_from_message(text: str) -> list[str]:
    """Finds all URLs present in a message text."""
    matches = re.findall(URL_REGEX, text, re.IGNORECASE)
    cleaned_urls = []
    for match in matches:
        # Trim trailing punctuation like period, comma, bracket
        clean = match.rstrip(".,!?:;)")
        if clean not in cleaned_urls:
            cleaned_urls.append(clean)
    return cleaned_urls

def analyze_message(text: str) -> dict:
    """
    Analyzes message content for social engineering tactics.
    Extracts embedded URLs and generates explainable evidence signals & flags.
    """
    text_lower = text.lower()
    extracted_urls = extract_urls_from_message(text)

    # Signal evaluations
    has_urgency = any(re.search(p, text_lower) for p in URGENCY_PATTERNS)
    has_threat = any(re.search(p, text_lower) for p in THREAT_PATTERNS)
    has_otp_req = any(re.search(p, text_lower) for p in OTP_PATTERNS)
    has_cred_req = any(re.search(p, text_lower) for p in CREDENTIAL_PATTERNS)
    has_payment_req = any(re.search(p, text_lower) for p in PAYMENT_PATTERNS)
    has_verification_req = any(re.search(p, text_lower) for p in VERIFICATION_PATTERNS)
    has_strong_cta = any(re.search(p, text_lower) for p in CTA_PATTERNS)

    signals = {
        "extracted_urls": extracted_urls,
        "urgency": has_urgency,
        "threat_language": has_threat,
        "otp_request": has_otp_req,
        "credential_request": has_cred_req,
        "payment_request": has_payment_req,
        "verification_request": has_verification_req,
        "strong_call_to_action": has_strong_cta
    }

    flags = []

    if has_urgency:
        flags.append({
            "name": "Artificial Urgency & Time Pressure",
            "severity": "HIGH",
            "reason": "Message uses high-pressure time limits to force immediate action without verification."
        })

    if has_threat:
        flags.append({
            "name": "Coercive Threat Language",
            "severity": "CRITICAL",
            "reason": "Message threatens account suspension, deactivation, or legal penalties."
        })

    if has_otp_req:
        flags.append({
            "name": "One-Time Password (OTP) Solicit",
            "severity": "CRITICAL",
            "reason": "Message requests a 2FA/OTP code, a key vector for account takeover attacks."
        })

    if has_cred_req:
        flags.append({
            "name": "Sensitive Credential Request",
            "severity": "HIGH",
            "reason": "Message prompts the user to provide login credentials or secret authentication details."
        })

    if has_payment_req:
        flags.append({
            "name": "Financial Solicit / Payment Demand",
            "severity": "HIGH",
            "reason": "Message references urgent payments, invoice clearing, or bank transfer requests."
        })

    if has_verification_req:
        flags.append({
            "name": "Identity Verification Bait",
            "severity": "MEDIUM",
            "reason": "Message claims your identity or account requires immediate verification."
        })

    if has_strong_cta:
        flags.append({
            "name": "Direct Call-To-Action Link Prompt",
            "severity": "MEDIUM",
            "reason": "Message contains explicit prompts directing the recipient to click external links."
        })

    return {
        "signals": signals,
        "flags": flags
    }

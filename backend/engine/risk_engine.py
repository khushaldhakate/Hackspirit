from backend.config import (
    RULE_SCORE_WEIGHT,
    ML_SCORE_WEIGHT,
    RISK_LEVEL_LOW_MAX,
    RISK_LEVEL_MEDIUM_MAX,
    RISK_LEVEL_HIGH_MAX
)

SEVERITY_POINTS = {
    "CRITICAL": 35,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5
}

def compute_risk(
    url_analysis: dict = None,
    message_analysis: dict = None,
    ml_analysis: dict = None,
    redirect_analysis: dict = None
) -> dict:
    """
    Deterministic Risk Engine.
    Combines rule-based flags (60%) and ML probabilities (40%) to calculate 
    an explainable risk score (0-100), risk level, threat type, and evidence list.
    """
    evidence_list = []
    rule_score_total = 0.0

    # 1. Collect flags from URL Analyzer
    if url_analysis and "flags" in url_analysis:
        for flag in url_analysis["flags"]:
            pts = SEVERITY_POINTS.get(flag["severity"], 10)
            rule_score_total += pts
            evidence_list.append({
                "name": flag["name"],
                "severity": flag["severity"],
                "reason": flag["reason"],
                "source": "URL Analyzer"
            })

    # 2. Collect flags from Message Analyzer
    if message_analysis and "flags" in message_analysis:
        for flag in message_analysis["flags"]:
            pts = SEVERITY_POINTS.get(flag["severity"], 10)
            rule_score_total += pts
            evidence_list.append({
                "name": flag["name"],
                "severity": flag["severity"],
                "reason": flag["reason"],
                "source": "Message Analyzer"
            })

    # 3. Collect flags from Redirect Analyzer
    if redirect_analysis and "flags" in redirect_analysis:
        for flag in redirect_analysis["flags"]:
            pts = SEVERITY_POINTS.get(flag["severity"], 10)
            rule_score_total += pts
            evidence_list.append({
                "name": flag["name"],
                "severity": flag["severity"],
                "reason": flag["reason"],
                "source": "Redirect Analyzer"
            })

    # Cap rule score to 100
    rule_score = min(100.0, rule_score_total)

    # 4. Compute ML Score from URLBERT Model prediction probabilities
    ml_score = 0.0
    ml_label = "benign"
    ml_confidence = 0.0

    if ml_analysis:
        ml_label = ml_analysis.get("label", "benign").lower()
        ml_confidence = ml_analysis.get("confidence", 0.0)
        probs = ml_analysis.get("probabilities", {})

        if probs:
            # Sum malicious probabilities (phishing + malware + defacement)
            phish_p = probs.get("phishing", 0.0)
            mal_p = probs.get("malware", 0.0)
            defac_p = probs.get("defacement", 0.0)
            malicious_sum = phish_p + mal_p + defac_p
            ml_score = malicious_sum * 100.0
        else:
            if ml_label == "phishing":
                ml_score = ml_confidence * 100.0
            elif ml_label == "malware":
                ml_score = max(85.0, ml_confidence * 100.0)
            elif ml_label == "defacement":
                ml_score = ml_confidence * 80.0
            elif ml_label == "benign":
                ml_score = (1.0 - ml_confidence) * 25.0

        if ml_label in ["phishing", "malware", "defacement"] and ml_confidence >= 0.60:
            evidence_list.append({
                "name": f"ML Model Classified as '{ml_label.capitalize()}'",
                "severity": "HIGH" if ml_confidence < 0.85 else "CRITICAL",
                "reason": f"Pretrained URLBERT neural network classified the target with {int(ml_confidence * 100)}% confidence as {ml_label}.",
                "source": "Pretrained ML Model"
            })

    # 5. Calculate Final Risk Score (60% Rule + 40% ML)
    final_score = int(round(rule_score * RULE_SCORE_WEIGHT + ml_score * ML_SCORE_WEIGHT))
    final_score = max(0, min(100, final_score))

    # 6. Determine Risk Level
    if final_score <= RISK_LEVEL_LOW_MAX:
        risk_level = "LOW"
    elif final_score <= RISK_LEVEL_MEDIUM_MAX:
        risk_level = "MEDIUM"
    elif final_score <= RISK_LEVEL_HIGH_MAX:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # 7. Determine Threat Type
    threat_type = "Likely Benign"
    if ml_label == "malware" or any(e["name"] == "ML Model Classified as 'Malware'" for e in evidence_list):
        threat_type = "Malware Delivery / Payload Risk"
    elif ml_label == "defacement":
        threat_type = "Defacement Threat"
    elif ml_label == "phishing" or any(k in [e["name"] for e in evidence_list] for k in ["Lookalike / Typosquatted Domain", "Targeted Authentication Keywords", "Sensitive Credential Request", "One-Time Password (OTP) Solicit"]):
        threat_type = "Credential Phishing & Identity Theft"
    elif message_analysis and any(e["source"] == "Message Analyzer" for e in evidence_list):
        threat_type = "Social Engineering Scam"
    elif final_score >= 50:
        threat_type = "High Suspicious Threat"
    elif final_score >= 25:
        threat_type = "Potential Risk / Anomalous Signals"

    return {
        "score": final_score,
        "level": risk_level,
        "threat_type": threat_type,
        "evidence": evidence_list,
        "rule_score": round(rule_score, 1),
        "ml_score": round(ml_score, 1)
    }

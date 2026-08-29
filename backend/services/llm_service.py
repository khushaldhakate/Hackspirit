import logging
import os
import json
import re
import httpx
from backend.config import GEMINI_API_KEY

logger = logging.getLogger("phishguard.llm")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

def clean_json_response(raw_text: str) -> dict | None:
    """Extracts and parses JSON from LLM text response."""
    try:
        # Direct parse
        return json.loads(raw_text)
    except Exception:
        pass
    
    # Try finding markdown code block ```json ... ``` or { ... }
    try:
        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except Exception as e:
        logger.warning(f"Failed to parse LLM JSON: {e}")
    return None

def call_groq_llm(prompt: str) -> dict | None:
    """Calls Groq model for instant structured threat explanation."""
    groq_key = os.getenv("GROQ_API_KEY") or GROQ_API_KEY
    if not groq_key:
        return None
    
    models = ["qwen/qwen3.8-27b", "openai/gpt-oss-120b"]
    for model in models:
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {groq_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a top-tier cybersecurity AI threat analyst for PhishGuard. Respond ONLY in valid JSON format with keys: 'why_risky', 'attack_intent', and 'recommended_action'."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.2,
                "max_tokens": 500
            }
            with httpx.Client(timeout=6.0) as client:
                res = client.post(url, headers=headers, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    parsed = clean_json_response(content)
                    if parsed and "why_risky" in parsed:
                        parsed["powered_by"] = "Groq AI (Ultra-Fast)"
                        return parsed
                else:
                    logger.warning(f"Groq API ({model}) returned {res.status_code}: {res.text[:100]}")
        except Exception as e:
            logger.error(f"Groq API call error with model {model}: {e}")
    return None

def call_gemini_llm(prompt: str, api_key: str) -> dict | None:
    """Calls Gemini API for threat intelligence explanation."""
    if not api_key:
        return None
    
    models = ["gemini-3.5-flash-lite", "gemini-3.6-flash"]
    for model in models:
        try:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "response_mime_type": "application/json",
                    "temperature": 0.2
                }
            }
            with httpx.Client(timeout=6.0) as client:
                res = client.post(endpoint, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get('candidates', [])
                    if candidates:
                        parts = candidates[0].get('content', {}).get('parts', [])
                        if parts:
                            text_content = parts[0].get('text', '')
                            parsed = clean_json_response(text_content)
                            if parsed and "why_risky" in parsed:
                                parsed["powered_by"] = "Gemini 3.5 AI"
                                return parsed
                else:
                    logger.warning(f"Gemini API ({model}) returned {res.status_code}: {res.text[:100]}")
        except Exception as e:
            logger.error(f"Gemini API call error with model {model}: {e}")
    return None

def generate_llm_explanation(
    input_text: str,
    risk: dict,
    url_analysis: dict = None,
    message_analysis: dict = None,
    ml_analysis: dict = None
) -> dict | None:
    """
    Generates natural language security context using Gemini or Groq API.
    Does NOT calculate or modify risk scores or invent signals.
    """
    gemini_key = os.getenv("GEMINI_API_KEY") or GEMINI_API_KEY
    groq_key = os.getenv("GROQ_API_KEY") or GROQ_API_KEY

    if not gemini_key and not groq_key:
        logger.info("No LLM API keys configured. Skipping LLM explanation layer.")
        return None

    # Format evidence summary
    evidence_summary = []
    for item in risk.get("evidence", []):
        evidence_summary.append(f"- {item['name']} ({item['severity']}): {item['reason']}")
    
    evidence_text = "\n".join(evidence_summary) if evidence_summary else "No severe risk flags detected. General safety verification."

    prompt = f"""
You are an expert cybersecurity threat analyst for PhishGuard.
Provide a concise, plain-English security explanation for the following security scan result.

Target Input: {input_text}
Risk Score: {risk.get('score')}/100
Risk Level: {risk.get('level')}
Threat Classification: {risk.get('threat_type')}
ML Model Prediction: {ml_analysis.get('label', 'N/A') if ml_analysis else 'N/A'} (Confidence: {ml_analysis.get('confidence', 0)*100 if ml_analysis else 0:.1f}%)

Detected Evidence Signals:
{evidence_text}

Instructions:
Respond strictly in JSON with three keys:
"why_risky": "1-2 sentences explaining why this input is or isn't dangerous based strictly on the detected evidence.",
"attack_intent": "1 sentence describing the likely goal of the attacker (e.g. credential theft, malware distribution, financial phishing, or benign message).",
"recommended_action": "1 sentence specifying immediate user safety action."

Do not alter or re-calculate scores. Do not invent unlisted evidence.
"""

    # Try Gemini API first
    if gemini_key:
        result = call_gemini_llm(prompt, gemini_key)
        if result:
            return result

    # Fallback to Groq API
    if groq_key:
        result = call_groq_llm(prompt)
        if result:
            return result

    return None


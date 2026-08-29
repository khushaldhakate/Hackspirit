import logging
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.ml.model_service import ml_service
from backend.analyzers.url_analyzer import analyze_url
from backend.analyzers.message_analyzer import analyze_message, extract_urls_from_message
from backend.analyzers.redirect_analyzer import trace_url_redirects
from backend.engine.risk_engine import compute_risk
from backend.services.llm_service import generate_llm_explanation

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("phishguard.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler: loads ML model ONCE during backend startup."""
    logger.info("Initializing PhishGuard backend services...")
    ml_service.load_model()
    yield
    logger.info("Shutting down PhishGuard backend services...")

app = FastAPI(
    title="PhishGuard Security API",
    description="AI-Powered Multi-Layer Phishing & Threat Detection System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    input: str = Field(..., description="Suspicious URL or text message to analyze", min_length=1)

def is_single_url(text: str) -> bool:
    """Checks if the input is predominantly a single URL."""
    text_clean = text.strip()
    if text_clean.startswith(("http://", "https://")):
        return True
    
    # Check if string looks like domain/url without spaces
    if " " not in text_clean and ("." in text_clean or "localhost" in text_clean):
        # Quick sanity check
        pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$"
        if re.match(pattern, text_clean):
            return True
    return False

@app.get("/health")
def health_check():
    return {
        "status": "online",
        "model_loaded": ml_service.is_loaded,
        "labels": list(ml_service.id2label.values()) if ml_service.is_loaded else []
    }

@app.post("/api/analyze")
def analyze_threat(payload: AnalyzeRequest):
    raw_input = payload.input.strip()
    if not raw_input:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Input text cannot be empty.")

    logger.info(f"Processing analysis request for input length: {len(raw_input)}")

    # 1. Input Detection
    is_url_input = is_single_url(raw_input)
    input_type = "url" if is_url_input else "message"

    target_url = None
    url_analysis_result = None
    message_analysis_result = None
    redirect_analysis_result = None
    ml_analysis_result = None

    if is_url_input:
        target_url = raw_input
        url_analysis_result = analyze_url(target_url)
    else:
        # Message input
        message_analysis_result = analyze_message(raw_input)
        extracted_urls = message_analysis_result["signals"]["extracted_urls"]
        if extracted_urls:
            target_url = extracted_urls[0] # Analyze primary embedded URL
            url_analysis_result = analyze_url(target_url)

    # 2. Redirect Analysis (if URL present)
    if target_url:
        redirect_analysis_result = trace_url_redirects(target_url)

    # 3. Pretrained ML Model Analysis (if URL present)
    if target_url:
        ml_analysis_result = ml_service.analyze_url_with_model(target_url)
    else:
        ml_analysis_result = {
            "label": "benign",
            "confidence": 0.0,
            "probabilities": {"benign": 1.0}
        }

    # 4. Deterministic Risk Engine Synthesis
    risk_output = compute_risk(
        url_analysis=url_analysis_result,
        message_analysis=message_analysis_result,
        ml_analysis=ml_analysis_result,
        redirect_analysis=redirect_analysis_result
    )

    # 5. Optional LLM Security Context
    llm_output = generate_llm_explanation(
        input_text=raw_input,
        risk=risk_output,
        url_analysis=url_analysis_result,
        message_analysis=message_analysis_result,
        ml_analysis=ml_analysis_result
    )

    # Construct Response
    return {
        "input": raw_input,
        "type": input_type,
        "target_url": target_url,
        "url_analysis": url_analysis_result,
        "message_analysis": message_analysis_result,
        "redirect_analysis": redirect_analysis_result,
        "ml_analysis": ml_analysis_result,
        "risk": {
            "score": risk_output["score"],
            "level": risk_output["level"],
            "threat_type": risk_output["threat_type"]
        },
        "evidence": risk_output["evidence"],
        "llm_explanation": llm_output
    }

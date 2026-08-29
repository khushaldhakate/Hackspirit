"""
PhishGuard ML Inference Microservice (Phase 5)
Loads CrabInHoney/urlbert-tiny-v4-malicious-url-classifier ONCE at startup,
extracts dynamic id2label mapping, and provides fast local REST inference.
"""

import time
import os
import sys
import socket
from typing import Dict, Any, List
from contextlib import asynccontextmanager

# Force IPv4 socket resolution to prevent timeouts on environments without IPv6 default routing
orig_getaddrinfo = socket.getaddrinfo
def getaddrinfo_ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    return orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = getaddrinfo_ipv4_only

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
import uvicorn

MODEL_NAME = "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"

# Official label mapping defined in CrabInHoney/urlbert-tiny-v4-malicious-url-classifier model card:
# LABEL_0 -> benign, LABEL_1 -> defacement, LABEL_2 -> malware, LABEL_3 -> phishing
OFFICIAL_LABEL_MAP: Dict[Any, str] = {
    0: "benign",
    1: "defacement",
    2: "malware",
    3: "phishing",
    "LABEL_0": "benign",
    "LABEL_1": "defacement",
    "LABEL_2": "malware",
    "LABEL_3": "phishing"
}

# Global variables for model state
model = None
tokenizer = None
id2label_resolved: Dict[int, str] = {}
model_loaded: bool = False
initialization_time_ms: float = 0.0

class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL string to classify")

class PredictResponse(BaseModel):
    success: bool
    model: str
    prediction: str
    probability: float
    probabilities: Dict[str, float]
    inference_time_ms: float

class HealthResponse(BaseModel):
    status: str
    model: str
    loaded: bool
    label_count: int
    labels: List[str]
    initialization_time_ms: float

def load_model():
    """
    Load model and tokenizer once at startup, extracting the actual id2label mapping.
    """
    global model, tokenizer, id2label_resolved, model_loaded, initialization_time_ms
    start_time = time.perf_counter()
    print(f"[ML Service] Loading pretrained model: {MODEL_NAME}...")

    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        model.eval()

        # Read actual id2label mapping from model configuration
        raw_id2label = getattr(model.config, "id2label", None)
        id2label_resolved = {}

        if raw_id2label and isinstance(raw_id2label, dict):
            for k, v in raw_id2label.items():
                idx = int(k)
                str_val = str(v)
                # Map raw label (e.g. 'LABEL_0' -> 'benign' according to model card)
                mapped = OFFICIAL_LABEL_MAP.get(str_val, OFFICIAL_LABEL_MAP.get(idx, str_val.lower()))
                id2label_resolved[idx] = mapped
        else:
            num_labels = getattr(model.config, "num_labels", 4)
            for i in range(num_labels):
                id2label_resolved[i] = OFFICIAL_LABEL_MAP.get(i, f"class_{i}")

        initialization_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        model_loaded = True
        print(f"[ML Service] Model loaded successfully in {initialization_time_ms}ms")
        print(f"[ML Service] Config id2label: {raw_id2label}")
        print(f"[ML Service] Resolved label mapping: {id2label_resolved}")
    except Exception as e:
        model_loaded = False
        print(f"[ML Service ERROR] Failed to load model: {e}", file=sys.stderr)
        raise e

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager that initializes the model once at service startup
    """
    load_model()
    yield

# Initialize FastAPI application with modern lifespan handler
app = FastAPI(
    title="PhishGuard ML Inference Service",
    version="1.0.0",
    description="Dedicated microservice for pretrained URLBERT malicious URL classification",
    lifespan=lifespan
)

@app.get("/health", response_model=HealthResponse)
def health_check():
    """
    Health check endpoint reporting model readiness and configuration
    """
    if not model_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Model not loaded"
        )
    return HealthResponse(
        status="ok",
        model=MODEL_NAME,
        loaded=True,
        label_count=len(id2label_resolved),
        labels=list(id2label_resolved.values()),
        initialization_time_ms=initialization_time_ms
    )

@app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest):
    """
    Run actual tokenizer + model inference on URL text
    """
    if not model_loaded or model is None or tokenizer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Model is not ready for inference"
        )

    url = payload.url.strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty"
        )

    t0 = time.perf_counter()
    try:
        # Tokenize purely as text without network access
        inputs = tokenizer(
            url,
            return_tensors="pt",
            truncation=True,
            max_length=256,
            padding=False
        )

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits[0]
            # Softmax to produce true normalized probability distribution
            probabilities_tensor = torch.softmax(logits, dim=-1)
            probs_list = probabilities_tensor.cpu().tolist()

        # Build dynamic probability dictionary using model's real id2label mapping
        probabilities_dict = {}
        for idx, prob in enumerate(probs_list):
            label_name = id2label_resolved.get(idx, f"label_{idx}")
            probabilities_dict[label_name] = round(prob, 6)

        # Determine predicted class with highest probability
        predicted_idx = int(torch.argmax(probabilities_tensor).item())
        predicted_class = id2label_resolved.get(predicted_idx, f"label_{predicted_idx}")
        highest_probability = round(probs_list[predicted_idx], 6)

        inf_time_ms = round((time.perf_counter() - t0) * 1000, 2)

        return PredictResponse(
            success=True,
            model=MODEL_NAME,
            prediction=predicted_class,
            probability=highest_probability,
            probabilities=probabilities_dict,
            inference_time_ms=inf_time_ms
        )
    except Exception as e:
        print(f"[ML Service ERROR] Inference failed for input '{url}': {e}", file=sys.stderr)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )

if __name__ == "__main__":
    port = int(os.environ.get("ML_PORT", 5001))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")

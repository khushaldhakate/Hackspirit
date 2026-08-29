import os
from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier")

# Deterministic Risk Engine Weights
RULE_SCORE_WEIGHT = float(os.getenv("RULE_SCORE_WEIGHT", "0.60"))
ML_SCORE_WEIGHT = float(os.getenv("ML_SCORE_WEIGHT", "0.40"))

# Risk Thresholds
RISK_LEVEL_LOW_MAX = 24
RISK_LEVEL_MEDIUM_MAX = 49
RISK_LEVEL_HIGH_MAX = 74

# Gemini API Key (Optional)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

import logging
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from backend.config import MODEL_NAME

logger = logging.getLogger("phishguard.ml")

class URLBERTModelService:
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.id2label = {}
        self.is_loaded = False

    def load_model(self):
        """Loads model and tokenizer ONCE during backend startup."""
        try:
            logger.info(f"Loading Hugging Face model: {MODEL_NAME}...")
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
            self.model.eval()
            
            # Check if model config has meaningful id2label or generic LABEL_X
            DEFAULT_CLASSES = {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"}
            
            if hasattr(self.model.config, "id2label") and self.model.config.id2label:
                raw_mapping = self.model.config.id2label
                # If config contains generic 'LABEL_0', 'LABEL_1'..., fallback to dataset standard labels
                if any("LABEL_" in str(v) for v in raw_mapping.values()):
                    self.id2label = DEFAULT_CLASSES
                else:
                    self.id2label = {int(k): str(v).lower() for k, v in raw_mapping.items()}
            else:
                self.id2label = DEFAULT_CLASSES

            self.is_loaded = True
            logger.info(f"Model loaded successfully with labels: {self.id2label}")
        except Exception as e:
            logger.error(f"Failed to load ML model '{MODEL_NAME}': {e}", exc_info=True)
            self.is_loaded = False

    def analyze_url_with_model(self, url: str) -> dict:
        """Inference function returning label, confidence, and label probabilities."""
        if not self.is_loaded or self.model is None or self.tokenizer is None:
            logger.warning("ML Model not loaded. Returning fallback prediction.")
            return {
                "label": "unknown",
                "confidence": 0.0,
                "probabilities": {},
                "error": "Model not loaded"
            }

        try:
            inputs = self.tokenizer(
                url,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            )
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1).squeeze(0)

            probabilities = {}
            for idx, prob in enumerate(probs):
                label_name = self.id2label.get(idx, f"class_{idx}")
                probabilities[label_name] = round(float(prob), 4)

            top_prob_idx = torch.argmax(probs).item()
            predicted_label = self.id2label.get(top_prob_idx, "unknown")
            top_confidence = round(float(probs[top_prob_idx]), 4)

            return {
                "label": predicted_label,
                "confidence": top_confidence,
                "probabilities": probabilities
            }
        except Exception as e:
            logger.error(f"Error during ML inference for URL '{url}': {e}", exc_info=True)
            return {
                "label": "unknown",
                "confidence": 0.0,
                "probabilities": {},
                "error": str(e)
            }

# Singleton instance
ml_service = URLBERTModelService()

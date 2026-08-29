# PS10 - PhishGuard
> **AI-Powered Multi-Layer Phishing & Threat Detection System**

PhishGuard is an advanced cybersecurity threat detection platform designed to analyze URLs, email messages, redirects, and threat vectors using multi-layered heuristic rules, machine learning classifications, and explainable AI insights.

---

## 📁 Project Architecture

```
PhishGuard/
├── backend/            # Express.js REST API & Threat Detection Engine
│   ├── server.js       # Main server entry & health endpoints
│   ├── .env.example    # Backend environment template
│   └── package.json
├── frontend/           # React + Vite + Tailwind CSS Dashboard
│   ├── src/            # Components & Application source
│   ├── .env.example    # Frontend environment template
│   └── package.json
├── ml/                 # Machine Learning Models & Inference Scripts
│   ├── models/         # Pretrained ML model artifacts
│   └── scripts/        # Feature extraction & inference
├── data/               # Reference datasets & offline threat feeds
├── .gitignore          # Repository gitignore rules
└── README.md           # Documentation & setup guide
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v18+ (tested with v24+)
- **npm**: v9+ (tested with v11+)
- **MongoDB**: (Required in later phases for scan history storage)

---

### 1. Backend Setup

1. Open a terminal and navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   ```
   *Default configuration:*
   - `PORT=5000`
   - `MONGODB_URI=mongodb://localhost:27017/phishguard`
   - `NODE_ENV=development`

4. Start the backend server:
   ```bash
   # Production / direct mode:
   npm start

   # Development mode with auto-reload:
   npm run dev
   ```

5. Verify Backend Health:
   - Endpoint: `http://localhost:5000/api/health`
   - Expected Output:
     ```json
     {
       "status": "ok",
       "service": "PhishGuard API"
     }
     ```

---

### 2. Frontend Setup

1. Open a second terminal and navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   ```
   *Default configuration:*
   - `VITE_API_BASE_URL=http://localhost:5000`

4. Start the development server:
   ```bash
   npm run dev
   ```

5. Open your browser:
   - Visit: `http://localhost:5173`

---

---

## 🛡️ Implementation Status (Phases 1–7 Complete)
- ✅ **Phase 1 (Baseline Architecture)**: Standardized modular structure (`backend/`, `frontend/`, `ml/`, `data/`), environment variable isolation, and health monitoring.
- ✅ **Phase 2 (Static URL Analyzer)**: Pure static textual parsing, homoglyph lookalike brand impersonation, suspicious TLD detection, and obfuscation extraction (12/12 tests).
- ✅ **Phase 3 (Message Analyzer)**: Social engineering detection, credential/OTP/PIN theft analysis, urgency/threat recognition, and static URL extraction (9/9 tests).
- ✅ **Phase 4 (Safe Redirect Analyzer)**: Header-only single-hop HTTP inspector with strict hop limits and comprehensive SSRF IP range filtering (12/12 tests).
- ✅ **Phase 5 (Pretrained ML Microservice)**: FastAPI inference service using `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier` with normalized softmax probability distributions (5/5 tests).
- ✅ **Phase 6 (Deterministic Risk Engine)**: Evidence-based normalized risk scoring (0–100), configurable group caps, cross-signal correlation dampening, threat category classification, and `/api/analyze/risk` (17/17 tests).
- ✅ **Phase 7 (AI Explainability Layer)**: Advisory Grok / Groq AI security explanation, strict grounded prompt constraints, anti-hallucination schema validation, and `/api/analyze/explain` & `/api/analyze` (17/17 tests).

### 🧪 Automated Test Suite Summary
```
Total Tests: 72 | Passed: 72 | Failed: 0
```

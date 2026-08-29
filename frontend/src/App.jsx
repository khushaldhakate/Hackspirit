import React, { useState } from 'react';
import Header from './components/Header';
import ScannerInput from './components/ScannerInput';
import ScanProgress from './components/ScanProgress';
import RiskGauge from './components/RiskGauge';
import EvidenceList from './components/EvidenceList';
import ActionCard from './components/ActionCard';
import LlmExplanation from './components/LlmExplanation';
import { AlertCircle, Shield, Terminal } from 'lucide-react';

const API_ENDPOINT = '/api/analyze';

export default function App() {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleAnalyze = async (inputText) => {
    setIsLoading(true);
    setErrorMsg(null);
    setAnalysisResult(null);

    try {
      let response;
      try {
        response = await fetch(API_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input: inputText }),
        });
      } catch (err) {
        // Fallback to absolute localhost backend URL if relative fetch fails
        response = await fetch('http://127.0.0.1:8000/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input: inputText }),
        });
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Server returned status ${response.status}`);
      }

      const data = await response.json();
      setAnalysisResult(data);
    } catch (err) {
      console.error('Analysis request error:', err);
      setErrorMsg(
        err.message || 'Failed to connect to PhishGuard security backend service.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-between cyber-grid">
      
      <div>
        <Header />

        <main className="max-w-5xl mx-auto px-4 sm:px-6 pb-16">
          
          {/* Main Input Form */}
          <ScannerInput onAnalyze={handleAnalyze} isLoading={isLoading} />

          {/* Loading Animation */}
          {isLoading && <ScanProgress />}

          {/* Error Banner */}
          {errorMsg && (
            <div className="glass-panel p-6 mb-8 border-rose-500/30 bg-rose-950/20 text-rose-300 flex items-start gap-3">
              <AlertCircle className="w-6 h-6 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-bold text-sm">ANALYSIS REQUEST ERROR</h4>
                <p className="text-xs text-rose-200 mt-1">{errorMsg}</p>
                <p className="text-[11px] text-slate-400 mt-2 font-mono">
                  Make sure backend server is running on http://127.0.0.1:8000
                </p>
              </div>
            </div>
          )}

          {/* Analysis Results Display */}
          {analysisResult && !isLoading && (
            <div className="space-y-6 animate-fade-in">
              
              {/* Risk Gauge & Overview */}
              <RiskGauge
                risk={analysisResult.risk}
                mlAnalysis={analysisResult.ml_analysis}
                inputType={analysisResult.type}
                targetUrl={analysisResult.target_url}
              />

              {/* Evidence Flags Breakdown */}
              <EvidenceList evidence={analysisResult.evidence} />

              {/* Optional LLM AI Explanation */}
              {analysisResult.llm_explanation && (
                <LlmExplanation llmExplanation={analysisResult.llm_explanation} />
              )}

              {/* Action Recommendation */}
              <ActionCard riskLevel={analysisResult.risk?.level} />

            </div>
          )}

        </main>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-6 bg-slate-950/80 text-center text-xs text-slate-500">
        <div className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-slate-400">PhishGuard HackSprint Project</span>
          </div>
          <p className="font-mono text-[11px]">
            Hugging Face Transformer (urlbert-tiny-v4) + Deterministic Risk Engine (60/40)
          </p>
        </div>
      </footer>

    </div>
  );
}

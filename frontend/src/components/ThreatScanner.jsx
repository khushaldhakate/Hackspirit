import React, { useState } from 'react';
import {
  Search,
  ShieldAlert,
  Sparkles,
  ShieldCheck,
  ShieldQuestion,
  AlertOctagon,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Info,
  Lock,
  Target,
  Brain,
  Terminal,
  Activity,
  ArrowRight,
  ExternalLink
} from 'lucide-react';

export default function ThreatScanner({
  analysisResult,
  isLoading,
  errorMsg,
  onAnalyze,
  onOpenStudio
}) {
  const [inputText, setInputText] = useState('');

  const PRESETS = [
    {
      label: 'Google.com (Safe)',
      value: 'https://google.com',
      badge: 'theme-badge-safe'
    },
    {
      label: 'PayPal Lookalike (Phishing)',
      value: 'https://paypa1-security.com/login',
      badge: 'theme-badge-critical'
    },
    {
      label: 'CDN File Share (Malware)',
      value: 'https://cdn-docs-share.net/download/payload.exe',
      badge: 'theme-badge-high'
    },
    {
      label: 'Urgent Bank SMS (Coercion)',
      value: 'URGENT: Your bank account is locked. Verify now at https://paypa1-security.com/login',
      badge: 'theme-badge-critical'
    }
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    onAnalyze(inputText.trim());
  };

  const handleSelectPreset = (value) => {
    setInputText(value);
    onAnalyze(value);
  };

  // Helper for gauge colors
  const getRiskTheme = (level) => {
    switch (level) {
      case 'CRITICAL':
        return {
          textColor: 'text-critical',
          strokeColor: '#ed6066',
          badgeClass: 'theme-badge-critical',
          icon: AlertOctagon,
          bgClass: 'bg-red-50/50'
        };
      case 'HIGH':
        return {
          textColor: 'text-high',
          strokeColor: '#f4be50',
          badgeClass: 'theme-badge-high',
          icon: ShieldAlert,
          bgClass: 'bg-amber-50/50'
        };
      case 'MEDIUM':
        return {
          textColor: 'text-amber-600',
          strokeColor: '#f59e0b',
          badgeClass: 'theme-badge-high',
          icon: ShieldQuestion,
          bgClass: 'bg-amber-50/40'
        };
      default:
        return {
          textColor: 'text-safe',
          strokeColor: '#48bb78',
          badgeClass: 'theme-badge-safe',
          icon: ShieldCheck,
          bgClass: 'bg-emerald-50/50'
        };
    }
  };

  const risk = analysisResult?.risk;
  const mlAnalysis = analysisResult?.ml_analysis;
  const score = risk?.score ?? 0;
  const level = risk?.level ?? 'SAFE';
  const theme = getRiskTheme(level);
  const IconComp = theme.icon;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8 animate-fade-in">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="theme-badge theme-badge-primary">REAL-TIME INSPECTION</span>
            <span className="text-xs font-mono text-slate-400">ML + Heuristics + Gemini AI</span>
          </div>
          <h2 className="text-2xl font-extrabold text-slate-900">
            Threat Scanner Portal
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Submit any suspicious URL, domain, or message payload to detect phishing, typosquats, and malware.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="theme-badge theme-badge-safe flex items-center gap-1">
            <Activity className="w-3 h-3 animate-pulse" /> Engine Online
          </span>
        </div>
      </div>

      {/* Main Scanner Input Card */}
      <div className="theme-card p-6 sm:p-8 mb-8">
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="relative">
            <textarea
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste suspicious URL (e.g. https://paypa1-security.com/login) or SMS text message..."
              rows={3}
              disabled={isLoading}
              className="w-full bg-[#fcfcfc] border border-slate-200 rounded-xl px-4 py-3.5 text-slate-800 placeholder-slate-400 focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/10 text-sm md:text-base resize-none transition-all mono-text"
            />
            {inputText && (
              <button
                type="button"
                onClick={() => setInputText('')}
                className="absolute top-3 right-3 text-xs text-slate-400 hover:text-slate-600 bg-slate-100 hover:bg-slate-200 px-2.5 py-1 rounded-md transition-colors"
              >
                Clear
              </button>
            )}
          </div>

          {/* Controls & Quick Test Chips */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <span className="text-xs text-slate-500 font-semibold flex items-center gap-1 mr-1">
                <Sparkles className="w-3.5 h-3.5 text-primary" /> Test Samples:
              </span>
              {PRESETS.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSelectPreset(preset.value)}
                  disabled={isLoading}
                  className={`text-xs px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition-all hover:border-slate-300 shadow-sm`}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={isLoading || !inputText.trim()}
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-[#247de8] hover:bg-[#176cd6] text-white font-bold text-sm tracking-wide shadow-md shadow-blue-500/20 hover:shadow-blue-500/35 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>{isLoading ? 'ANALYZING THREAT...' : 'RUN THREAT SCAN'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Loading Progress State */}
      {isLoading && (
        <div className="theme-card p-8 mb-8 text-center animate-fade-in border-blue-200 bg-blue-50/20">
          <div className="max-w-md mx-auto flex flex-col items-center">
            <div className="relative mb-5">
              <div className="w-16 h-16 rounded-full border-2 border-blue-200 flex items-center justify-center bg-blue-50 relative overflow-hidden">
                <ShieldAlert className="w-8 h-8 text-primary animate-pulse" />
                <div className="absolute inset-0 border-t-2 border-primary rounded-full animate-spin" />
              </div>
            </div>
            <h3 className="text-lg font-bold text-slate-900 mb-1">
              SCANNING TARGET SIGNALS
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              Running URLBERT transformer model & deterministic threat engine
            </p>
            <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
              <div className="bg-primary h-full rounded-full animate-pulse w-3/4"></div>
            </div>
          </div>
        </div>
      )}

      {/* Error Message */}
      {errorMsg && (
        <div className="theme-card p-6 mb-8 border-red-200 bg-red-50 text-red-800 flex items-start gap-3">
          <AlertOctagon className="w-5 h-5 text-critical shrink-0 mt-0.5" />
          <div>
            <h4 className="font-bold text-sm">SCAN EXECUTION ERROR</h4>
            <p className="text-xs text-red-700 mt-1">{errorMsg}</p>
          </div>
        </div>
      )}

      {/* Scan Results View */}
      {analysisResult && !isLoading && (
        <div className="space-y-6 animate-fade-in">
          {/* Risk Overview Card */}
          <div className={`theme-card p-6 sm:p-8 ${theme.bgClass}`}>
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
              {/* Circular Gauge */}
              <div className="lg:col-span-5 flex flex-col items-center justify-center p-6 rounded-2xl bg-white border border-slate-200 shadow-sm">
                <div className="gauge-box-light mb-3">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      stroke="#e2e8f0"
                      strokeWidth="8"
                      fill="transparent"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      stroke={theme.strokeColor}
                      strokeWidth="8"
                      strokeDasharray="251.2"
                      strokeDashoffset={251.2 - (251.2 * score) / 100}
                      strokeLinecap="round"
                      fill="transparent"
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute flex flex-col items-center justify-center text-center">
                    <span className="text-3xl font-extrabold text-slate-900 mono-text">
                      {score}
                    </span>
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">
                      / 100 RISK
                    </span>
                  </div>
                </div>

                <span className={`theme-badge ${theme.badgeClass} text-xs py-1 px-3`}>
                  <IconComp className="w-3.5 h-3.5" />
                  <span>{level} RISK</span>
                </span>
              </div>

              {/* Classification & Neural Confidence */}
              <div className="lg:col-span-7 flex flex-col justify-between h-full gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="theme-badge theme-badge-indigo">
                      {analysisResult.type === 'url' ? 'URL SCAN' : 'MESSAGE SCAN'}
                    </span>
                    {analysisResult.target_url && (
                      <span className="text-xs text-slate-500 truncate max-w-md mono-text">
                        Target: {analysisResult.target_url}
                      </span>
                    )}
                  </div>

                  <h3 className="text-2xl font-extrabold text-slate-900 mb-1">
                    {risk.threat_type || 'Benign URL'}
                  </h3>

                  <p className="text-xs text-slate-600 leading-relaxed">
                    Evaluated by PhishGuard Deterministic Heuristics (60%) and Hugging Face Transformer Neural Model (40%).
                  </p>
                </div>

                {/* Pretrained Neural Inference Metrics */}
                <div className="p-4 rounded-xl bg-white border border-slate-200">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
                      <Cpu className="w-4 h-4 text-primary" />
                      <span>URLBERT Neural Classifier</span>
                    </div>
                    <span className="text-xs mono-text font-bold text-primary">
                      {mlAnalysis?.label?.toUpperCase()} ({Math.round((mlAnalysis?.confidence || 0) * 100)}% Confidence)
                    </span>
                  </div>

                  {/* Bar */}
                  <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary transition-all duration-700 rounded-full"
                      style={{ width: `${Math.round((mlAnalysis?.confidence || 0) * 100)}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2 font-mono">
                    <span>Model Class Probabilities:</span>
                    <span>
                      {mlAnalysis?.probabilities
                        ? Object.entries(mlAnalysis.probabilities)
                            .map(([k, v]) => `${k}: ${Math.round(v * 100)}%`)
                            .join(' | ')
                        : 'Active'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Detected Evidence Flags */}
          <div className="theme-card p-6 sm:p-8">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-2">
                <AlertOctagon className="w-5 h-5 text-critical" />
                <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                  DETECTED EVIDENCE SIGNALS ({analysisResult.evidence?.length || 0})
                </h3>
              </div>
              <span className="text-xs text-slate-500 font-mono">
                Deterministic Findings
              </span>
            </div>

            {(!analysisResult.evidence || analysisResult.evidence.length === 0) ? (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 text-safe" />
                <div>
                  <h4 className="font-bold text-sm">NO SUSPICIOUS SIGNALS DETECTED</h4>
                  <p className="text-xs text-emerald-700 mt-0.5">
                    Target did not trigger structural heuristic flags or malicious classification thresholds.
                  </p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {analysisResult.evidence.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl border border-slate-200 bg-[#fdfdfd] hover:bg-slate-50/50 transition-all flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <h4 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                          <span>{item.name}</span>
                        </h4>
                        <span className={`theme-badge ${item.severity === 'CRITICAL' ? 'theme-badge-critical' : 'theme-badge-high'}`}>
                          {item.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed pl-6 mb-3">
                        {item.reason}
                      </p>
                    </div>

                    <div className="pl-6 flex items-center justify-between text-[11px] text-slate-400 font-mono pt-2 border-t border-slate-100">
                      <span>Source Layer:</span>
                      <span className="text-slate-600 font-semibold">{item.source}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Gemini AI Threat Intelligence Card */}
          {analysisResult.llm_explanation && (
            <div className="theme-card p-6 sm:p-8 border-indigo-200 bg-indigo-50/20">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-lg bg-indigo-100 text-indigo-600">
                    <Brain className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                      AI THREAT INTELLIGENCE BRIEF
                    </h3>
                    <p className="text-xs text-slate-500">
                      Contextual threat synthesis powered by Gemini 3.5 AI
                    </p>
                  </div>
                </div>

                <span className="theme-badge theme-badge-indigo">
                  <Sparkles className="w-3 h-3" />
                  {analysisResult.llm_explanation.powered_by || 'Gemini 3.5 AI'}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-white border border-indigo-100">
                  <div className="flex items-center gap-2 text-xs font-bold text-indigo-600 uppercase tracking-wider mb-2">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Why Flagged</span>
                  </div>
                  <p className="text-xs text-slate-700 leading-relaxed">
                    {analysisResult.llm_explanation.why_risky}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-white border border-indigo-100">
                  <div className="flex items-center gap-2 text-xs font-bold text-blue-600 uppercase tracking-wider mb-2">
                    <Target className="w-3.5 h-3.5" />
                    <span>Attack Vector Intent</span>
                  </div>
                  <p className="text-xs text-slate-700 leading-relaxed">
                    {analysisResult.llm_explanation.attack_intent}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-white border border-indigo-100">
                  <div className="flex items-center gap-2 text-xs font-bold text-emerald-600 uppercase tracking-wider mb-2">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>AI Safety Guidance</span>
                  </div>
                  <p className="text-xs text-slate-700 leading-relaxed">
                    {analysisResult.llm_explanation.recommended_action}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Action Recommendation Card */}
          <div className="theme-card p-6 sm:p-8">
            <div className="flex items-center gap-3 mb-4">
              <div className={`p-2 rounded-xl ${score >= 50 ? 'bg-red-50 text-critical' : 'bg-emerald-50 text-safe'}`}>
                {score >= 50 ? <AlertOctagon className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
              </div>
              <div>
                <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                  RECOMMENDED SAFETY ACTION
                </h3>
                <p className="text-xs text-slate-500">
                  Immediate protocol for level: <strong className="text-slate-800">{level}</strong>
                </p>
              </div>
            </div>

            {score >= 50 ? (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="p-4 rounded-xl bg-red-50/40 border border-red-100 flex flex-col gap-2">
                  <div className="text-critical font-bold text-xs uppercase tracking-wider flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-critical animate-ping" />
                    1. DO NOT OPEN LINK
                  </div>
                  <p className="text-xs text-slate-600">
                    Do not click or browse to this destination from any corporate or personal device.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-amber-50/40 border border-amber-100 flex flex-col gap-2">
                  <div className="text-amber-600 font-bold text-xs uppercase tracking-wider flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5" />
                    2. NEVER SHARE CREDENTIALS
                  </div>
                  <p className="text-xs text-slate-600">
                    Never input login credentials, MFA codes, or payment data into unverified domains.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-blue-50/40 border border-blue-100 flex flex-col gap-2">
                  <div className="text-primary font-bold text-xs uppercase tracking-wider flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    3. USE DIRECT PORTAL
                  </div>
                  <p className="text-xs text-slate-600">
                    Navigate to the brand's service via official mobile app or bookmark.
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-emerald-50/50 border border-emerald-100 text-xs text-slate-700">
                <p className="font-bold text-safe mb-1">
                  ✅ Low Risk Detected
                </p>
                <p>
                  No deceptive typosquats or malicious payloads found. Always verify domain spelling before submitting passwords.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

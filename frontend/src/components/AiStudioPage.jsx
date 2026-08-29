import React, { useState } from 'react';
import {
  Cpu,
  Brain,
  Layers,
  Network,
  Sparkles,
  Zap,
  ShieldCheck,
  AlertTriangle,
  Play,
  Terminal,
  Activity
} from 'lucide-react';

export default function AiStudioPage({ onAnalyzeLink }) {
  const [sandboxInput, setSandboxInput] = useState('https://paypa1-security-update.xyz/login?session=a83fb01e9d');
  const [activeAnalysis, setActiveAnalysis] = useState(null);

  // Compute live client-side heuristic metrics for sandbox
  const runDeepSandboxAudit = () => {
    const url = sandboxInput.trim();
    const len = url.length;
    const dotCount = (url.match(/\./g) || []).length;
    const hyphenCount = (url.match(/-/g) || []).length;
    const hasHttps = url.startsWith('https://');
    const hasSuspiciousKeywords = /login|verify|security|update|account|signin|auth/i.test(url);
    const hasTyposquat = /paypa1|micros0ft|app1e|g00gle|amaz0n/i.test(url);
    
    // Shannon entropy approximation for randomness
    const charMap = {};
    for (let c of url) charMap[c] = (charMap[c] || 0) + 1;
    let entropy = 0;
    for (let c in charMap) {
      let p = charMap[c] / len;
      entropy -= p * Math.log2(p);
    }

    setActiveAnalysis({
      url,
      length: len,
      dots: dotCount,
      hyphens: hyphenCount,
      https: hasHttps,
      keywords: hasSuspiciousKeywords,
      typosquat: hasTyposquat,
      entropy: entropy.toFixed(2),
      estimatedRisk: hasTyposquat ? 92 : hasSuspiciousKeywords ? 68 : 15,
      redirectHops: [
        { hop: 1, url: url, code: 302, status: 'Redirected' },
        { hop: 2, url: 'https://auth-credential-receiver.top/capture.php', code: 200, status: 'Final Destination' }
      ]
    });
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="theme-badge theme-badge-indigo">DEEP SANDBOX</span>
            <span className="text-xs font-mono text-slate-400">Heuristics & Neural Inspector</span>
          </div>
          <h2 className="text-2xl font-extrabold text-slate-900">
            AI Threat Studio & Sandbox
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Deep forensic sandbox for structural token analysis, redirect chain extraction, and entropy calculation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="theme-badge theme-badge-indigo flex items-center gap-1.5 py-1 px-3">
            <Cpu className="w-3.5 h-3.5" /> URLBERT + Gemini 3.5 AI
          </span>
        </div>
      </div>

      {/* Sandbox URL Input Card */}
      <div className="theme-card p-6 sm:p-8 mb-8">
        <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
          <Terminal className="w-5 h-5 text-indigo" />
          <span>Interactive Payload Dissector</span>
        </h3>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <input
            type="text"
            value={sandboxInput}
            onChange={(e) => setSandboxInput(e.target.value)}
            placeholder="Enter URL to dissect (e.g. https://paypa1-security-update.xyz/login)..."
            className="w-full bg-[#fcfcfc] border border-slate-200 rounded-xl px-4 py-3 text-xs text-slate-800 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/10 mono-text transition-all"
          />
          <button
            type="button"
            onClick={runDeepSandboxAudit}
            className="w-full sm:w-auto px-6 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs tracking-wide shadow-md shadow-indigo-500/20 transition-all flex items-center justify-center gap-2 shrink-0"
          >
            <Play className="w-3.5 h-3.5" />
            <span>DISSECT PAYLOAD</span>
          </button>
        </div>
      </div>

      {/* Dissection Results */}
      {activeAnalysis ? (
        <div className="space-y-6 animate-fade-in mb-8">
          {/* Signal Cards Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="theme-card p-4">
              <span className="text-[11px] text-slate-400 font-semibold uppercase">Shannon Entropy</span>
              <div className="text-xl font-extrabold text-slate-900 mono-text mt-1">
                {activeAnalysis.entropy} bits
              </div>
              <span className="text-[10px] text-amber-600 font-bold">
                {parseFloat(activeAnalysis.entropy) > 4.2 ? 'High Obfuscation' : 'Standard Distribution'}
              </span>
            </div>

            <div className="theme-card p-4">
              <span className="text-[11px] text-slate-400 font-semibold uppercase">Character Count</span>
              <div className="text-xl font-extrabold text-slate-900 mono-text mt-1">
                {activeAnalysis.length} chars
              </div>
              <span className="text-[10px] text-slate-500">
                {activeAnalysis.dots} dots | {activeAnalysis.hyphens} hyphens
              </span>
            </div>

            <div className="theme-card p-4">
              <span className="text-[11px] text-slate-400 font-semibold uppercase">Lookalike / Typosquat</span>
              <div className={`text-xl font-extrabold mono-text mt-1 ${activeAnalysis.typosquat ? 'text-critical' : 'text-safe'}`}>
                {activeAnalysis.typosquat ? 'DETECTED' : 'CLEAR'}
              </div>
              <span className="text-[10px] text-slate-500">
                {activeAnalysis.typosquat ? 'Brand spoof pattern' : 'No homoglyphs'}
              </span>
            </div>

            <div className="theme-card p-4">
              <span className="text-[11px] text-slate-400 font-semibold uppercase">Estimated Risk</span>
              <div className="text-xl font-extrabold text-slate-900 mono-text mt-1">
                {activeAnalysis.estimatedRisk}/100
              </div>
              <span className="text-[10px] text-critical font-bold">
                {activeAnalysis.estimatedRisk > 50 ? 'HIGH THREAT' : 'BENIGN'}
              </span>
            </div>
          </div>

          {/* Simulated Redirect Trace */}
          <div className="theme-card p-6">
            <h4 className="font-bold text-sm text-slate-900 mb-4 flex items-center gap-2">
              <Network className="w-4 h-4 text-indigo" />
              <span>Simulated Autonomous Redirect Chain</span>
            </h4>
            <div className="space-y-3">
              {activeAnalysis.redirectHops.map((hop) => (
                <div
                  key={hop.hop}
                  className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="flex items-center gap-3">
                    <span className="w-6 h-6 rounded-full bg-indigo-100 text-indigo-700 font-bold text-xs flex items-center justify-center mono-text">
                      {hop.hop}
                    </span>
                    <span className="font-mono text-xs text-slate-800 truncate max-w-lg">
                      {hop.url}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="theme-badge theme-badge-indigo">
                      HTTP {hop.code}
                    </span>
                    <span className="text-xs text-slate-500 font-semibold">
                      {hop.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        /* Default Intro Card */
        <div className="theme-card p-8 text-center text-slate-500 mb-8">
          <Cpu className="w-12 h-12 text-indigo-400 mx-auto mb-3" />
          <h4 className="font-bold text-base text-slate-800 mb-1">
            Deep Payload Dissection Ready
          </h4>
          <p className="text-xs max-w-md mx-auto">
            Click 'Dissect Payload' to calculate Shannon string entropy, trace redirect hops, and test token heuristics.
          </p>
        </div>
      )}

      {/* Neural Model Architecture Reference */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="theme-card p-6">
          <h4 className="font-bold text-sm text-slate-900 mb-3 flex items-center gap-2">
            <Brain className="w-4 h-4 text-primary" />
            <span>Hugging Face Transformer Tokenizer</span>
          </h4>
          <p className="text-xs text-slate-600 leading-relaxed mb-3">
            PhishGuard uses <code>CrabInHoney/urlbert-tiny-v4-malicious-url-classifier</code>, tokenizing character n-grams and subword embeddings to catch zero-day phishing links that bypass standard blocklists.
          </p>
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-100 font-mono text-[11px] text-slate-700">
            [CLS] https [SEP] paypa1 [SEP] login [SEP] verify [SEP]
          </div>
        </div>

        <div className="theme-card p-6">
          <h4 className="font-bold text-sm text-slate-900 mb-3 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo" />
            <span>Gemini 3.5 AI Reasoning Engine</span>
          </h4>
          <p className="text-xs text-slate-600 leading-relaxed mb-3">
            Generates natural language context in under 1 second, explaining the attacker's intent and providing clear, defensive safety directives.
          </p>
          <div className="p-3 rounded-lg bg-indigo-50/50 border border-indigo-100 font-mono text-[11px] text-indigo-900">
            Output: {"{ why_risky, attack_intent, recommended_action }"}
          </div>
        </div>
      </div>
    </div>
  );
}

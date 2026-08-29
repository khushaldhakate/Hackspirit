import React from 'react';
import { ShieldAlert, ShieldCheck, ShieldQuestion, AlertOctagon, Cpu, Zap } from 'lucide-react';

export default function RiskGauge({ risk, mlAnalysis, inputType, targetUrl }) {
  const score = risk?.score ?? 0;
  const level = risk?.level ?? 'LOW';
  const threatType = risk?.threat_type ?? 'Likely Benign';

  const mlLabel = mlAnalysis?.label ?? 'benign';
  const mlConfidence = mlAnalysis?.confidence ?? 0.0;
  const mlProbPercent = Math.round(mlConfidence * 100);

  const getTheme = () => {
    switch (level) {
      case 'CRITICAL':
        return {
          glowClass: 'glass-panel-glow-crimson',
          textClass: 'text-rose-400',
          bgClass: 'bg-rose-500/10',
          borderClass: 'border-rose-500/40',
          progressClass: 'from-amber-500 via-rose-500 to-red-600',
          icon: AlertOctagon,
          badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/30'
        };
      case 'HIGH':
        return {
          glowClass: 'border-amber-500/30 shadow-amber-500/10',
          textClass: 'text-amber-400',
          bgClass: 'bg-amber-500/10',
          borderClass: 'border-amber-500/40',
          progressClass: 'from-yellow-400 via-amber-500 to-rose-500',
          icon: ShieldAlert,
          badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/30'
        };
      case 'MEDIUM':
        return {
          glowClass: 'border-yellow-500/30 shadow-yellow-500/10',
          textClass: 'text-yellow-400',
          bgClass: 'bg-yellow-500/10',
          borderClass: 'border-yellow-500/40',
          progressClass: 'from-cyan-400 via-yellow-400 to-amber-500',
          icon: ShieldQuestion,
          badgeBg: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
        };
      default:
        return {
          glowClass: 'border-emerald-500/30 shadow-emerald-500/10',
          textClass: 'text-emerald-400',
          bgClass: 'bg-emerald-500/10',
          borderClass: 'border-emerald-500/30',
          progressClass: 'from-cyan-400 via-emerald-400 to-emerald-500',
          icon: ShieldCheck,
          badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
        };
    }
  };

  const theme = getTheme();
  const IconComponent = theme.icon;

  return (
    <div className={`glass-panel p-6 sm:p-8 mb-8 ${theme.glowClass} transition-all`}>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        
        {/* Risk Score Circle / Gauge (Cols 1-5) */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-6 rounded-2xl bg-slate-950/60 border border-slate-800 relative">
          
          <div className="gauge-box mb-4">
            
            {/* SVG Ring Gauge */}
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="42"
                stroke="currentColor"
                strokeWidth="8"
                className="text-slate-800"
                fill="transparent"
              />
              <circle
                cx="50"
                cy="50"
                r="42"
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray="264"
                strokeDashoffset={264 - (264 * score) / 100}
                strokeLinecap="round"
                className={`${theme.textClass} transition-all duration-1000 ease-out`}
                fill="transparent"
              />
            </svg>

            {/* Score Center Text */}
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-4xl font-extrabold tracking-tight text-white mono-text">
                {score}
              </span>
              <span className="text-xs text-slate-400 font-semibold tracking-wider uppercase mt-0.5">
                / 100 RISK
              </span>
            </div>
          </div>

          {/* Risk Level Badge */}
          <div className={`px-4 py-1.5 rounded-full border text-xs font-bold tracking-widest uppercase flex items-center gap-1.5 ${theme.badgeBg}`}>
            <IconComponent className="w-4 h-4" />
            <span>{level} RISK</span>
          </div>

        </div>

        {/* Threat Overview & ML Metrics (Cols 6-12) */}
        <div className="lg:col-span-7 flex flex-col justify-between h-full gap-6">
          
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold uppercase bg-slate-800 text-slate-300">
                {inputType === 'url' ? 'URL SCAN' : 'MESSAGE SCAN'}
              </span>
              {targetUrl && (
                <span className="text-xs text-slate-400 truncate max-w-md mono-text">
                  Target: {targetUrl}
                </span>
              )}
            </div>

            <h2 className="text-2xl font-bold text-slate-100 mb-2">
              {threatType}
            </h2>
            
            <p className="text-sm text-slate-400 leading-relaxed">
              Assessment based on multi-layer structural heuristics (60%) and Hugging Face neural classifier inference (40%).
            </p>
          </div>

          {/* ML Classifier Sub-card */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span>Pretrained ML Classifier (urlbert-tiny-v4)</span>
              </div>
              <span className="text-xs mono-text font-bold text-cyan-400">
                {mlLabel.toUpperCase()} ({mlProbPercent}% Confidence)
              </span>
            </div>

            {/* Confidence Bar */}
            <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-700"
                style={{ width: `${mlProbPercent}%` }}
              />
            </div>
            
            <div className="flex items-center justify-between text-[11px] text-slate-500 mt-2 font-mono">
              <span>Class Probabilities:</span>
              <span>
                {mlAnalysis?.probabilities ? (
                  Object.entries(mlAnalysis.probabilities)
                    .map(([k, v]) => `${k}: ${Math.round(v * 100)}%`)
                    .join(' | ')
                ) : (
                  'Active'
                )}
              </span>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}

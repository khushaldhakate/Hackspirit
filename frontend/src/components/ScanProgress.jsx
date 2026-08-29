import React, { useEffect, useState } from 'react';
import { Shield, Cpu, Binary, Search, CheckCircle2 } from 'lucide-react';

const STEPS = [
  { id: 1, label: 'Extracting URL structural signals & protocol features...', icon: Search },
  { id: 2, label: 'Scanning text for social-engineering coercion & urgency...', icon: Binary },
  { id: 3, label: 'Running Hugging Face URLBERT-v4 neural inference...', icon: Cpu },
  { id: 4, label: 'Computing deterministic Risk Engine weights (60% Rule / 40% ML)...', icon: Shield },
];

export default function ScanProgress() {
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveStep((prev) => (prev < STEPS.length - 1 ? prev + 1 : prev));
    }, 450);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="glass-panel p-8 mb-8 border-cyan-500/30 glass-panel-glow-cyan text-center">
      <div className="max-w-md mx-auto flex flex-col items-center">
        
        {/* Animated Scanner Radar */}
        <div className="relative mb-6">
          <div className="w-20 h-20 rounded-full border-2 border-cyan-500/30 flex items-center justify-center bg-cyan-500/5 relative overflow-hidden">
            <Shield className="w-10 h-10 text-cyan-400 animate-pulse" />
            <div className="absolute inset-0 border-t-2 border-cyan-400 rounded-full animate-spin" />
          </div>
        </div>

        <h3 className="text-xl font-bold text-slate-100 mb-2">
          SCANNING THREAT SIGNALS
        </h3>
        <p className="text-xs text-slate-400 mb-6">
          PhishGuard Multi-Layer Security Engine is evaluating target input
        </p>

        {/* Step Progress Items */}
        <div className="w-full flex flex-col gap-3 text-left">
          {STEPS.map((step, idx) => {
            const Icon = step.icon;
            const isDone = idx < activeStep;
            const isCurrent = idx === activeStep;

            return (
              <div
                key={step.id}
                className={`flex items-center gap-3 p-3 rounded-lg border text-xs transition-all ${
                  isCurrent
                    ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300 font-semibold'
                    : isDone
                    ? 'border-slate-800 bg-slate-900/60 text-slate-400 opacity-80'
                    : 'border-slate-900 bg-slate-950/40 text-slate-600'
                }`}
              >
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <Icon className={`w-4 h-4 shrink-0 ${isCurrent ? 'text-cyan-400 animate-bounce' : 'text-slate-600'}`} />
                )}
                <span>{step.label}</span>
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}

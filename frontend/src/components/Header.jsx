import React from 'react';
import { ShieldAlert, Cpu, Activity } from 'lucide-react';

export default function Header() {
  return (
    <header className="w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 py-4 px-6 mb-8">
      <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Brand Logo & Name */}
        <div className="flex items-center gap-3">
          <div className="relative p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 text-cyan-400">
            <ShieldAlert className="w-7 h-7 text-cyan-400 animate-pulse-glow" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full animate-ping opacity-75" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-extrabold tracking-wider bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent">
                PHISHGUARD
              </h1>
              <span className="px-2 py-0.5 text-xs font-semibold uppercase tracking-widest bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-md">
                MVP v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">
              AI-Powered Multi-Layer Phishing & Threat Detection System
            </p>
          </div>
        </div>

        {/* Engine Status Indicators */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="mono-text">CrabInHoney/urlbert-tiny-v4</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 font-semibold">
            <Activity className="w-3.5 h-3.5 animate-pulse" />
            <span>Risk Engine Active</span>
          </div>
        </div>

      </div>
    </header>
  );
}

import React from 'react';
import { Sparkles, Brain, Target, ShieldCheck } from 'lucide-react';

export default function LlmExplanation({ llmExplanation }) {
  if (!llmExplanation) return null;

  return (
    <div className="glass-panel p-6 sm:p-8 mb-8 border-indigo-500/30 bg-indigo-950/10">
      
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
              AI THREAT INTELLIGENCE SUMMARY
            </h3>
            <p className="text-xs text-slate-400">
              Natural language explanation powered by Gemini AI
            </p>
          </div>
        </div>

        <span className="px-2.5 py-1 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-bold tracking-wider uppercase flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-indigo-400" />
          {llmExplanation.powered_by || 'Gemini AI'}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Why Risky */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300 uppercase tracking-wider mb-2">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Why Flagged</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {llmExplanation.why_risky}
          </p>
        </div>

        {/* Attack Intent */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300 uppercase tracking-wider mb-2">
            <Target className="w-3.5 h-3.5" />
            <span>Attack Vector Intent</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {llmExplanation.attack_intent}
          </p>
        </div>

        {/* Action Summary */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-semibold text-emerald-300 uppercase tracking-wider mb-2">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>AI Safety Recommendation</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {llmExplanation.recommended_action}
          </p>
        </div>

      </div>

    </div>
  );
}

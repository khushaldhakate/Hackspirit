import React from 'react';
import { AlertCircle, AlertOctagon, AlertTriangle, Info, CheckCircle } from 'lucide-react';

export default function EvidenceList({ evidence = [] }) {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="glass-panel p-6 mb-8 border-emerald-500/20 bg-emerald-500/5">
        <div className="flex items-center gap-3 text-emerald-400">
          <CheckCircle className="w-6 h-6 shrink-0" />
          <div>
            <h3 className="font-bold text-base">NO SUSPICIOUS SIGNALS DETECTED</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Target input did not trigger any heuristic threat flags or malicious ML classification thresholds.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          cardBg: 'bg-rose-950/30 border-rose-500/40 text-rose-300',
          badgeBg: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
          icon: AlertOctagon,
          iconColor: 'text-rose-400'
        };
      case 'HIGH':
        return {
          cardBg: 'bg-amber-950/30 border-amber-500/40 text-amber-300',
          badgeBg: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
          icon: AlertTriangle,
          iconColor: 'text-amber-400'
        };
      case 'MEDIUM':
        return {
          cardBg: 'bg-yellow-950/20 border-yellow-500/30 text-yellow-300',
          badgeBg: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
          icon: AlertCircle,
          iconColor: 'text-yellow-400'
        };
      default:
        return {
          cardBg: 'bg-slate-900/60 border-slate-800 text-slate-300',
          badgeBg: 'bg-slate-800 text-slate-400 border-slate-700',
          icon: Info,
          iconColor: 'text-cyan-400'
        };
    }
  };

  return (
    <div className="glass-panel p-6 sm:p-8 mb-8 border-slate-800">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <AlertOctagon className="w-5 h-5 text-rose-400" />
          <h3 className="text-lg font-bold text-slate-100 uppercase tracking-wider">
            WHY FLAGGED? DETECTED EVIDENCE ({evidence.length})
          </h3>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          Deterministic Signals
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {evidence.map((item, idx) => {
          const style = getSeverityStyle(item.severity);
          const IconComp = style.icon;

          return (
            <div
              key={idx}
              className={`p-4 rounded-xl border transition-all ${style.cardBg} flex flex-col justify-between`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <IconComp className={`w-4 h-4 shrink-0 ${style.iconColor}`} />
                    <h4 className="font-semibold text-sm text-slate-100">
                      {item.name}
                    </h4>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border shrink-0 ${style.badgeBg}`}>
                    {item.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed pl-6 mb-3">
                  {item.reason}
                </p>
              </div>

              <div className="pl-6 flex items-center justify-between text-[11px] text-slate-500 font-mono pt-2 border-t border-white/5">
                <span>Source Layer:</span>
                <span className="text-slate-400 font-medium">{item.source}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

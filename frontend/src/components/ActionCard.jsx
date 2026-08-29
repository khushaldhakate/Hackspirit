import React from 'react';
import { ShieldCheck, Lock, AlertOctagon, CheckCircle2, ArrowRight } from 'lucide-react';

export default function ActionCard({ riskLevel }) {
  const isHighRisk = riskLevel === 'CRITICAL' || riskLevel === 'HIGH';
  const isMediumRisk = riskLevel === 'MEDIUM';

  return (
    <div className={`glass-panel p-6 sm:p-8 mb-8 border-slate-800 ${
      isHighRisk ? 'border-rose-500/30 bg-rose-950/10' : 'border-emerald-500/20 bg-emerald-950/10'
    }`}>
      
      <div className="flex items-center gap-3 mb-4">
        <div className={`p-2 rounded-xl ${isHighRisk ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
          {isHighRisk ? <AlertOctagon className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
        </div>
        <div>
          <h3 className="text-lg font-bold text-slate-100 uppercase tracking-wider">
            RECOMMENDED SAFETY ACTION
          </h3>
          <p className="text-xs text-slate-400">
            Immediate security advice based on risk level ({riskLevel})
          </p>
        </div>
      </div>

      {isHighRisk ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-rose-500/20 flex flex-col gap-2">
            <div className="flex items-center gap-2 text-rose-400 font-semibold text-xs uppercase tracking-wider">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
              1. DO NOT OPEN LINK
            </div>
            <p className="text-xs text-slate-300">
              Do not click or browse to the suspicious URL from any device or browser.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-rose-500/20 flex flex-col gap-2">
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs uppercase tracking-wider">
              <Lock className="w-3.5 h-3.5" />
              2. NEVER SHARE PASSWORDS/OTP
            </div>
            <p className="text-xs text-slate-300">
              Never input credentials, 2FA codes, or banking details into unverified forms.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-rose-500/20 flex flex-col gap-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider">
              <CheckCircle2 className="w-3.5 h-3.5" />
              3. VERIFY VIA OFFICIAL APP
            </div>
            <p className="text-xs text-slate-300">
              Log into the service directly via official app or bookmarked domain.
            </p>
          </div>
        </div>
      ) : isMediumRisk ? (
        <div className="p-4 rounded-xl bg-slate-900/80 border border-yellow-500/20 text-xs text-slate-300 space-y-2">
          <p className="font-semibold text-yellow-400">
            ⚠️ Exercise Caution & Verify Destination
          </p>
          <p>
            Anomalous domain features or wording were detected. Double check domain spelling in your browser address bar before interacting.
          </p>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-slate-900/80 border border-emerald-500/20 text-xs text-slate-300 space-y-2">
          <p className="font-semibold text-emerald-400">
            ✅ No Severe Threat Signals Detected
          </p>
          <p>
            No major phishing indicators found. Remember to remain vigilant against unexpected requests.
          </p>
        </div>
      )}

      {/* Security Disclaimer */}
      <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
        <span>PhishGuard Security Intelligence Engine</span>
        <span className="italic">Evaluates risk probabilities; not an absolute safe guarantee.</span>
      </div>

    </div>
  );
}

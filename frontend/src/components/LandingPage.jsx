import React from 'react';
import {
  ShieldCheck,
  ChevronRight,
  Check,
  Clock3,
  Radar,
  ArrowDownRight,
  CheckCircle2,
  LockKeyhole,
  Sparkles,
  Globe,
  Network,
  ShieldAlert,
  Database,
  ArrowRight,
  FileText
} from 'lucide-react';

export default function LandingPage({ onOpenScanner, onSelectPreset, onSelectTab }) {
  return (
    <div className="animate-fade-in">
      {/* Hero Section */}
      <section className="landing-hero" aria-labelledby="landing-title">
        {/* Floating Badges (Desktop & Large Tablets) */}
        <div className="landing-decoration landing-note hidden lg:block">
          <div className="landing-pin"></div>
          <p>
            Stay ahead of
            <br />
            the next lure.
          </p>
          <span>PROTECT WITH CONTEXT</span>
        </div>

        <div className="landing-decoration landing-check hidden lg:flex">
          <span className="landing-check-icon">
            <Check className="w-4 h-4" />
          </span>
          <span>Safe to open</span>
        </div>

        <div className="landing-decoration landing-node hidden lg:grid">
          <span></span>
          <span></span>
          <span></span>
          <span></span>
        </div>

        <div className="landing-decoration landing-reminder hidden lg:block">
          <div className="landing-reminder-head">
            <span>Signal watch</span>
            <Clock3 className="w-4 h-4" />
          </div>
          <strong>
            Review critical
            <br />
            findings
          </strong>
          <div className="landing-reminder-time">
            <span>Today</span>
            <b>09:30 — 10:00</b>
          </div>
        </div>

        {/* Hero Copy & Core Actions */}
        <div className="landing-copy">
          <div className="landing-kicker">
            <span className="landing-kicker-dot"></span> Threat intelligence, made clear
          </div>

          <h1 id="landing-title">
            See the threat.
            <br />
            <span>Make the call.</span>
          </h1>

          <p>
            PhishGuard turns suspicious links and urgent messages into clear, defensible
            decisions—powered by dual-engine AI (Transformer + Gemini Intelligence).
          </p>

          <div className="landing-hero-actions flex-wrap">
            <button
              type="button"
              onClick={() => onOpenScanner()}
              className="landing-primary-cta w-full sm:w-auto"
            >
              Analyze a URL <Radar className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => onSelectTab('intel')}
              className="landing-secondary-cta w-full sm:w-auto justify-center"
            >
              Live Threat Feed <ArrowDownRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="landing-proof flex-wrap">
            <span>
              <ShieldCheck className="w-3.5 h-3.5" /> Isolated analysis
            </span>
            <span>
              <CheckCircle2 className="w-3.5 h-3.5" /> 28 signals per scan
            </span>
            <span>
              <LockKeyhole className="w-3.5 h-3.5" /> No device requests
            </span>
          </div>
        </div>

        {/* Floating Detections Card (Desktop only) */}
        <div className="landing-decoration landing-tasks hidden lg:block">
          <div className="landing-card-title">
            <span>Today's detections</span>
            <span className="landing-card-count">03 live</span>
          </div>

          <div
            className="landing-task cursor-pointer"
            onClick={() => onSelectPreset('https://paypa1-security.com/login')}
            title="Click to test in scanner"
          >
            <span className="landing-task-dot critical"></span>
            <div>
              <b>account-verify-mail.com</b>
              <span>Credential harvest</span>
            </div>
            <em>91%</em>
          </div>

          <div
            className="landing-task cursor-pointer"
            onClick={() => onSelectPreset('https://paypa1-login.xyz/verify')}
            title="Click to test in scanner"
          >
            <span className="landing-task-dot high"></span>
            <div>
              <b>cdn-docs-share.net</b>
              <span>Malware delivery</span>
            </div>
            <em>78%</em>
          </div>

          <div
            className="landing-task cursor-pointer"
            onClick={() => onSelectPreset('https://google.com')}
            title="Click to test in scanner"
          >
            <span className="landing-task-dot low"></span>
            <div>
              <b>notion.so</b>
              <span>Legitimate</span>
            </div>
            <em>08%</em>
          </div>
        </div>

        {/* Connected Signals Floating Card (Desktop only) */}
        <div className="landing-decoration landing-stack hidden lg:block">
          <div className="landing-card-title">
            <span>Connected signals</span>
            <Sparkles className="w-3.5 h-3.5 text-primary" />
          </div>
          <div className="landing-stack-icons">
            <span>
              <Globe className="w-4 h-4" />
            </span>
            <span>
              <Network className="w-4 h-4" />
            </span>
            <span>
              <ShieldAlert className="w-4 h-4" />
            </span>
            <span>
              <Database className="w-4 h-4" />
            </span>
          </div>
          <p>One clear read from every source.</p>
        </div>
      </section>

      {/* Mobile Detection Cards Preview (Visible on mobile/tablet) */}
      <section className="block lg:hidden max-w-xl mx-auto px-4 mb-12">
        <div className="theme-card p-5 bg-white shadow-sm border border-slate-200">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold text-slate-800">Quick Test Detections</span>
            <span className="theme-badge theme-badge-primary">Interactive</span>
          </div>
          <div className="space-y-2">
            {[
              {
                domain: 'account-verify-mail.com',
                type: 'Credential Harvest (91%)',
                url: 'https://paypa1-security.com/login',
                dot: 'critical'
              },
              {
                domain: 'cdn-docs-share.net',
                type: 'Malware Drop (78%)',
                url: 'https://cdn-docs-share.net/download/payload.exe',
                dot: 'high'
              },
              {
                domain: 'google.com',
                type: 'Verified Safe (0%)',
                url: 'https://google.com',
                dot: 'safe'
              }
            ].map((d, i) => (
              <div
                key={i}
                onClick={() => onSelectPreset(d.url)}
                className="p-3 rounded-xl bg-slate-50 border border-slate-100 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <span className={`landing-task-dot ${d.dot === 'safe' ? '' : d.dot}`} />
                  <div>
                    <strong className="text-xs text-slate-800 mono-text block">{d.domain}</strong>
                    <span className="text-[10px] text-slate-500">{d.type}</span>
                  </div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-primary" />
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why PhishGuard Strip */}
      <section className="landing-signal-strip" id="why-phishguard">
        <div>
          <span className="landing-strip-index">01</span>
          <strong>Spot the signal</strong>
          <p>Reputation, domain heuristics, and neural embeddings in one unified view.</p>
        </div>
        <div>
          <span className="landing-strip-index">02</span>
          <strong>Decide with confidence</strong>
          <p>Every score comes with transparent evidence signals and AI reasoning.</p>
        </div>
        <div>
          <span className="landing-strip-index">03</span>
          <strong>Move as one team</strong>
          <p>Share a crisp security brief with immediate recommendations.</p>
        </div>
      </section>

      {/* How It Works / Workflow Section */}
      <section className="landing-workflow" id="workflow">
        <div>
          <span className="landing-kicker">A better handoff</span>
          <h2>
            Less noise.
            <br />
            <span>More knowing.</span>
          </h2>
        </div>
        <p>
          From the first suspicious URL to the final response, PhishGuard keeps the
          important context close. Scan, understand, and take the safest next step
          without leaving the flow.
        </p>
        <button
          type="button"
          onClick={() => onOpenScanner()}
          className="landing-text-link"
        >
          Try the workspace <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </section>

      {/* Multi-Page Quick Access Grid */}
      <section className="max-w-6xl mx-auto px-4 sm:px-6 py-12">
        <div className="text-center mb-8 sm:mb-10">
          <span className="theme-badge theme-badge-primary mb-2">COMPLETE DEFENSE SUITE</span>
          <h3 className="text-xl sm:text-2xl font-extrabold text-slate-900 mt-1">
            Enterprise Threat Platform Capabilities
          </h3>
          <p className="text-xs sm:text-sm text-slate-500 max-w-xl mx-auto mt-2">
            Explore dedicated modules built for security analysts, incident responders, and end-users.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6">
          <div
            onClick={() => onSelectTab('scanner')}
            className="theme-card p-5 sm:p-6 cursor-pointer hover:border-blue-400 group"
          >
            <div className="p-2.5 w-10 h-10 rounded-xl bg-blue-50 text-primary mb-4 flex items-center justify-center">
              <Radar className="w-5 h-5" />
            </div>
            <h4 className="font-bold text-base text-slate-900 mb-1 flex items-center justify-between">
              <span>Threat Scanner</span>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-primary transition-all group-hover:translate-x-1" />
            </h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Deep link inspection combining urlbert-tiny-v4 transformer inference with Gemini threat intelligence.
            </p>
          </div>

          <div
            onClick={() => onSelectTab('intel')}
            className="theme-card p-5 sm:p-6 cursor-pointer hover:border-amber-400 group"
          >
            <div className="p-2.5 w-10 h-10 rounded-xl bg-amber-50 text-amber-600 mb-4 flex items-center justify-center">
              <Globe className="w-5 h-5" />
            </div>
            <h4 className="font-bold text-base text-slate-900 mb-1 flex items-center justify-between">
              <span>Live Threat Feed</span>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-amber-600 transition-all group-hover:translate-x-1" />
            </h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Real-time telemetry showing active malicious domains, typosquats, and campaign targets across the web.
            </p>
          </div>

          <div
            onClick={() => onSelectTab('reports')}
            className="theme-card p-5 sm:p-6 cursor-pointer hover:border-indigo-400 group"
          >
            <div className="p-2.5 w-10 h-10 rounded-xl bg-indigo-50 text-indigo-600 mb-4 flex items-center justify-center">
              <FileText className="w-5 h-5" />
            </div>
            <h4 className="font-bold text-base text-slate-900 mb-1 flex items-center justify-between">
              <span>Detection Reports</span>
              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-indigo-600 transition-all group-hover:translate-x-1" />
            </h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Historical scan ledger, deterministic evidence archive, and exportable forensic JSON audit logs.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

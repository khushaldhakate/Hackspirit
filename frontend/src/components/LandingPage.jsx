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
  Database
} from 'lucide-react';

export default function LandingPage({ onOpenScanner, onSelectPreset }) {
  return (
    <div className="landing-page">
      {/* Navigation Header */}
      <header className="landing-nav">
        <a href="#top" className="landing-brand">
          <span className="landing-brand-mark" aria-hidden="true">
            <ShieldCheck className="w-4 h-4" />
          </span>
          <span>
            phish<span>guard</span>
          </span>
        </a>

        <nav className="landing-links" aria-label="Landing page navigation">
          <a href="#why-phishguard">Why PhishGuard</a>
          <a href="#workflow">How it works</a>
          <a href="#teams">For teams</a>
        </nav>

        <div className="landing-nav-actions">
          <button
            type="button"
            onClick={() => onOpenScanner()}
            className="landing-sign-in"
          >
            Open workspace
          </button>
          <button
            type="button"
            onClick={() => onOpenScanner()}
            className="landing-nav-cta"
          >
            Get a demo <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main id="top">
        {/* Hero Section */}
        <section className="landing-hero" aria-labelledby="landing-title">
          {/* Floating Sticky Note */}
          <div className="landing-decoration landing-note">
            <div className="landing-pin"></div>
            <p>
              Stay ahead of
              <br />
              the next lure.
            </p>
            <span>PROTECT WITH CONTEXT</span>
          </div>

          {/* Floating Safe Check Card */}
          <div className="landing-decoration landing-check">
            <span className="landing-check-icon">
              <Check className="w-4 h-4" />
            </span>
            <span>Safe to open</span>
          </div>

          {/* Floating Node Grid */}
          <div className="landing-decoration landing-node">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
          </div>

          {/* Floating Reminder Card */}
          <div className="landing-decoration landing-reminder">
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
              PhishGuard turns suspicious links into clear, defensible decisions—so your
              team can move fast without guessing.
            </p>

            <div className="landing-hero-actions">
              <button
                type="button"
                onClick={() => onOpenScanner()}
                className="landing-primary-cta"
              >
                Analyze a URL <Radar className="w-4 h-4" />
              </button>
              <a href="#workflow" className="landing-secondary-cta">
                See how it works <ArrowDownRight className="w-3.5 h-3.5" />
              </a>
            </div>

            <div className="landing-proof">
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

          {/* Floating Detections Card */}
          <div className="landing-decoration landing-tasks">
            <div className="landing-card-title">
              <span>Today's detections</span>
              <span className="landing-card-count">03 open</span>
            </div>

            <div
              className="landing-task cursor-pointer hover:opacity-80 transition-opacity"
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
              className="landing-task cursor-pointer hover:opacity-80 transition-opacity"
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
              className="landing-task cursor-pointer hover:opacity-80 transition-opacity"
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

          {/* Connected Signals Floating Card */}
          <div className="landing-decoration landing-stack">
            <div className="landing-card-title">
              <span>Connected signals</span>
              <Sparkles className="w-3.5 h-3.5 text-cyan-500" />
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

        {/* Why PhishGuard Strip */}
        <section className="landing-signal-strip" id="why-phishguard">
          <div>
            <span className="landing-strip-index">01</span>
            <strong>Spot the signal</strong>
            <p>Reputation, infrastructure, and behavior in one view.</p>
          </div>
          <div>
            <span className="landing-strip-index">02</span>
            <strong>Decide with confidence</strong>
            <p>Every score comes with the evidence behind it.</p>
          </div>
          <div>
            <span className="landing-strip-index">03</span>
            <strong>Move as one team</strong>
            <p>Share a crisp decision brief, not a data dump.</p>
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
      </main>

      {/* Footer */}
      <footer className="landing-footer" id="teams">
        <span>phishguard</span>
        <span>Quiet where it should be. Ready when it matters.</span>
        <button
          type="button"
          onClick={() => onOpenScanner()}
          className="flex items-center gap-1 text-[#247de8] font-bold"
        >
          Open the workspace <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </footer>
    </div>
  );
}

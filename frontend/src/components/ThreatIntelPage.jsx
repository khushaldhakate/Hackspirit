import React, { useState } from 'react';
import {
  Activity,
  Globe,
  ShieldAlert,
  AlertOctagon,
  Radar,
  TrendingUp,
  Cpu,
  Layers,
  ArrowRight,
  Filter,
  CheckCircle2
} from 'lucide-react';

export default function ThreatIntelPage({ onAnalyzePreset }) {
  const [filterCategory, setFilterCategory] = useState('ALL');

  const TELEMETRY_METRICS = [
    {
      label: 'Detections Today',
      value: '1,428',
      change: '+14.2%',
      color: 'text-primary'
    },
    {
      label: 'Phishing Intercept Rate',
      value: '99.4%',
      change: 'High Precision',
      color: 'text-safe'
    },
    {
      label: 'Typosquatted Lookalikes',
      value: '439',
      change: 'Surge Detected',
      color: 'text-critical'
    },
    {
      label: 'Avg Model Inference',
      value: '18ms',
      change: 'urlbert-v4',
      color: 'text-indigo'
    }
  ];

  const RECENT_FEED = [
    {
      domain: 'paypa1-security.com',
      url: 'https://paypa1-security.com/login',
      brand: 'PayPal',
      type: 'Credential Harvest',
      severity: 'CRITICAL',
      score: 91,
      detectedAt: '2 mins ago',
      technique: 'Typosquatting (1 vs l)'
    },
    {
      domain: 'cdn-docs-share.net',
      url: 'https://cdn-docs-share.net/download/payload.exe',
      brand: 'Generic Cloud',
      type: 'Malware Drop',
      severity: 'HIGH',
      score: 78,
      detectedAt: '7 mins ago',
      technique: 'Binary Executable in Path'
    },
    {
      domain: 'micros0ft-support-alert.xyz',
      url: 'https://micros0ft-support-alert.xyz/verify',
      brand: 'Microsoft 365',
      type: 'Account Takeover',
      severity: 'CRITICAL',
      score: 95,
      detectedAt: '14 mins ago',
      technique: 'Homoglyph & Suspicious TLD'
    },
    {
      domain: 'chase-security-update.info',
      url: 'https://chase-security-update.info/auth',
      brand: 'Chase Bank',
      type: 'Banking Phish',
      severity: 'CRITICAL',
      score: 89,
      detectedAt: '22 mins ago',
      technique: 'Urgency & Keyword Stuffing'
    },
    {
      domain: 'apple-id-suspended-now.top',
      url: 'https://apple-id-suspended-now.top/recovery',
      brand: 'Apple ID',
      type: 'Credential Theft',
      severity: 'CRITICAL',
      score: 94,
      detectedAt: '35 mins ago',
      technique: 'High-risk TLD & Brand Impersonation'
    },
    {
      domain: 'github.com',
      url: 'https://github.com',
      brand: 'GitHub',
      type: 'Benign Destination',
      severity: 'SAFE',
      score: 0,
      detectedAt: '40 mins ago',
      technique: 'Verified Authority Domain'
    }
  ];

  const filteredFeed =
    filterCategory === 'ALL'
      ? RECENT_FEED
      : filterCategory === 'CRITICAL'
      ? RECENT_FEED.filter((i) => i.severity === 'CRITICAL')
      : filterCategory === 'MALWARE'
      ? RECENT_FEED.filter((i) => i.type.includes('Malware'))
      : RECENT_FEED.filter((i) => i.severity === 'SAFE');

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="theme-badge theme-badge-primary">GLOBAL TELEMETRY</span>
            <span className="text-xs font-mono text-slate-400">Threat Radar v1.0</span>
          </div>
          <h2 className="text-2xl font-extrabold text-slate-900">
            Live Threat Intelligence & Feeds
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time feed of malicious links, brand impersonation campaigns, and heuristic telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="theme-badge theme-badge-safe flex items-center gap-1.5 py-1 px-3">
            <Activity className="w-3.5 h-3.5 animate-pulse" /> Live Telemetry Feed
          </span>
        </div>
      </div>

      {/* Telemetry KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {TELEMETRY_METRICS.map((kpi, idx) => (
          <div key={idx} className="theme-card p-5">
            <span className="text-xs text-slate-500 font-semibold">{kpi.label}</span>
            <div className="flex items-baseline justify-between mt-2">
              <span className={`text-2xl font-extrabold mono-text ${kpi.color}`}>
                {kpi.value}
              </span>
              <span className="text-[11px] font-bold text-slate-400 bg-slate-50 border border-slate-100 px-2 py-0.5 rounded">
                {kpi.change}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Main Feed Card */}
      <div className="theme-card p-6 sm:p-8 mb-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-primary" />
            <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
              RECENT THREAT DETECTIONS ({filteredFeed.length})
            </h3>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-2">
            {['ALL', 'CRITICAL', 'MALWARE', 'SAFE'].map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setFilterCategory(cat)}
                className={`text-xs px-3 py-1 rounded-lg font-bold transition-all border ${
                  filterCategory === cat
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Feed Table */}
        <div className="overflow-x-auto">
          <table className="theme-table">
            <thead>
              <tr>
                <th>Target Domain</th>
                <th>Target Brand</th>
                <th>Threat Category</th>
                <th>Technique</th>
                <th>Risk Score</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredFeed.map((item, idx) => (
                <tr key={idx}>
                  <td>
                    <div className="font-semibold text-slate-900 mono-text text-xs">
                      {item.domain}
                    </div>
                    <span className="text-[11px] text-slate-400">{item.detectedAt}</span>
                  </td>
                  <td>
                    <span className="text-xs font-semibold text-slate-700">
                      {item.brand}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`theme-badge ${
                        item.severity === 'CRITICAL'
                          ? 'theme-badge-critical'
                          : item.severity === 'HIGH'
                          ? 'theme-badge-high'
                          : 'theme-badge-safe'
                      }`}
                    >
                      {item.type}
                    </span>
                  </td>
                  <td>
                    <span className="text-xs text-slate-500">{item.technique}</span>
                  </td>
                  <td>
                    <span className="text-xs font-bold mono-text text-slate-800">
                      {item.score}/100
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      onClick={() => onAnalyzePreset(item.url)}
                      className="inline-flex items-center gap-1 text-xs font-bold text-primary hover:text-blue-700 bg-blue-50 hover:bg-blue-100 px-2.5 py-1 rounded-lg transition-colors"
                    >
                      <span>Analyze</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Brand Impersonation Threat Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="theme-card p-6">
          <h4 className="font-bold text-sm text-slate-900 mb-3 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-critical" />
            <span>Top Impersonated Brands This Week</span>
          </h4>
          <div className="space-y-3">
            {[
              { brand: 'PayPal Services', percent: 38, count: '542 links' },
              { brand: 'Microsoft 365 / Azure', percent: 29, count: '410 links' },
              { brand: 'Apple ID Portal', percent: 18, count: '256 links' },
              { brand: 'Chase & Banking Systems', percent: 15, count: '220 links' }
            ].map((b, i) => (
              <div key={i} className="text-xs">
                <div className="flex justify-between font-semibold text-slate-700 mb-1">
                  <span>{b.brand}</span>
                  <span className="mono-text text-slate-500">{b.count} ({b.percent}%)</span>
                </div>
                <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full"
                    style={{ width: `${b.percent}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="theme-card p-6">
          <h4 className="font-bold text-sm text-slate-900 mb-3 flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo" />
            <span>Multi-Layer Defense Architecture</span>
          </h4>
          <div className="space-y-2.5 text-xs text-slate-600">
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100 flex items-start gap-2">
              <span className="font-bold text-primary mono-text">01.</span>
              <div>
                <strong className="text-slate-800">Lexical & Heuristic Rules (60%):</strong>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Detects typosquatting, character substitution, high-risk TLDs, and keyword stuffing.
                </p>
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100 flex items-start gap-2">
              <span className="font-bold text-primary mono-text">02.</span>
              <div>
                <strong className="text-slate-800">Neural ML Classifier (40%):</strong>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Pretrained URLBERT-tiny-v4 transformer generates vector embeddings for unknown threats.
                </p>
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100 flex items-start gap-2">
              <span className="font-bold text-primary mono-text">03.</span>
              <div>
                <strong className="text-slate-800">Gemini 3.5 AI Context Layer:</strong>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Synthesizes why the payload is risky and outlines direct security actions.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

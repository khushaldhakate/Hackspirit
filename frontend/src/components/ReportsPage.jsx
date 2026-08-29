import React, { useState } from 'react';
import {
  FileText,
  Download,
  Search,
  Filter,
  CheckCircle2,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  Calendar
} from 'lucide-react';

export default function ReportsPage({ onReinspect, history = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Default demo records if history is fresh
  const INITIAL_REPORTS = [
    {
      id: 'REP-8041',
      target: 'https://paypa1-security.com/login',
      type: 'URL',
      threat: 'Typosquatted Credential Phishing',
      score: 91,
      level: 'CRITICAL',
      mlConfidence: '99.9%',
      date: '2026-08-29 11:44:16',
      status: 'BLOCKED'
    },
    {
      id: 'REP-8040',
      target: 'https://cdn-docs-share.net/download/payload.exe',
      type: 'URL',
      threat: 'Malware Delivery / Payload Risk',
      score: 78,
      level: 'HIGH',
      mlConfidence: '94.2%',
      date: '2026-08-29 11:32:05',
      status: 'FLAGGED'
    },
    {
      id: 'REP-8039',
      target: 'URGENT: Your account is locked. Verify at https://paypa1-login.xyz/verify',
      type: 'MESSAGE',
      threat: 'Coercive SMS + Phishing Domain',
      score: 95,
      level: 'CRITICAL',
      mlConfidence: '98.5%',
      date: '2026-08-29 11:15:42',
      status: 'BLOCKED'
    },
    {
      id: 'REP-8038',
      target: 'https://google.com',
      type: 'URL',
      threat: 'Benign Authority Domain',
      score: 0,
      level: 'SAFE',
      mlConfidence: '99.9%',
      date: '2026-08-29 10:58:19',
      status: 'PASSED'
    },
    {
      id: 'REP-8037',
      target: 'https://micros0ft-support-alert.xyz/verify',
      type: 'URL',
      threat: 'Microsoft 365 Impersonation',
      score: 96,
      level: 'CRITICAL',
      mlConfidence: '99.8%',
      date: '2026-08-29 10:41:02',
      status: 'BLOCKED'
    }
  ];

  const allReports = [...history, ...INITIAL_REPORTS];

  const filteredReports = allReports.filter((item) => {
    const matchesSearch =
      item.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.threat.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === 'ALL' || item.level === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const handleExportJSON = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(filteredReports, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `phishguard_audit_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="theme-badge theme-badge-primary">AUDIT LOGS</span>
            <span className="text-xs font-mono text-slate-400">Security Reports</span>
          </div>
          <h2 className="text-2xl font-extrabold text-slate-900">
            Detection Reports & History
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Historical scan records, deterministic findings, and forensic export logs.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleExportJSON}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-xs font-bold text-slate-700 shadow-sm transition-all"
          >
            <Download className="w-4 h-4 text-primary" />
            <span>Export Report (JSON)</span>
          </button>
        </div>
      </div>

      {/* Filter Bar Card */}
      <div className="theme-card p-6 mb-8">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative w-full sm:w-96">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search reports by domain, threat type, or ID..."
              className="w-full bg-[#fcfcfc] border border-slate-200 rounded-xl pl-10 pr-4 py-2 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/10 transition-all mono-text"
            />
          </div>

          {/* Severity Filters */}
          <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
            <span className="text-xs text-slate-400 font-semibold mr-1 flex items-center gap-1">
              <Filter className="w-3.5 h-3.5" /> Severity:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'SAFE'].map((lvl) => (
              <button
                key={lvl}
                type="button"
                onClick={() => setSeverityFilter(lvl)}
                className={`text-xs px-3 py-1 rounded-lg font-bold border transition-all ${
                  severityFilter === lvl
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Reports Table Card */}
      <div className="theme-card p-6 sm:p-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
              SCAN AUDIT TRAIL ({filteredReports.length})
            </h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            PhishGuard Unified Ledger
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="theme-table">
            <thead>
              <tr>
                <th>Report ID</th>
                <th>Target Payload</th>
                <th>Classification</th>
                <th>Score</th>
                <th>ML Confidence</th>
                <th>Date / Time</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredReports.map((r, idx) => (
                <tr key={idx}>
                  <td>
                    <span className="font-mono text-xs font-bold text-slate-900">
                      {r.id}
                    </span>
                  </td>
                  <td className="max-w-xs">
                    <div className="text-xs font-semibold text-slate-800 truncate mono-text" title={r.target}>
                      {r.target}
                    </div>
                    <span className="text-[10px] text-slate-400 font-mono uppercase">
                      {r.type}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`theme-badge ${
                        r.level === 'CRITICAL'
                          ? 'theme-badge-critical'
                          : r.level === 'HIGH'
                          ? 'theme-badge-high'
                          : 'theme-badge-safe'
                      }`}
                    >
                      {r.threat}
                    </span>
                  </td>
                  <td>
                    <span className="text-xs font-bold mono-text text-slate-800">
                      {r.score}/100
                    </span>
                  </td>
                  <td>
                    <span className="text-xs text-slate-600 font-mono">
                      {r.mlConfidence}
                    </span>
                  </td>
                  <td>
                    <span className="text-xs text-slate-500 font-mono">
                      {r.date}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      onClick={() => onReinspect(r.target)}
                      className="inline-flex items-center gap-1 text-xs font-bold text-primary hover:text-blue-700 bg-blue-50 hover:bg-blue-100 px-2.5 py-1 rounded-lg transition-colors"
                    >
                      <span>Re-Inspect</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

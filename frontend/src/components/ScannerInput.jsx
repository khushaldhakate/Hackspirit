import React, { useState } from 'react';
import { Search, ShieldAlert, Sparkles, AlertTriangle, Link2, MessageSquareText } from 'lucide-react';

export default function ScannerInput({ onAnalyze, isLoading }) {
  const [inputText, setInputText] = useState('');

  const PRESETS = [
    {
      label: 'Google.com (Benign)',
      type: 'url',
      color: 'hover:border-emerald-500/50 hover:bg-emerald-500/10 text-emerald-400',
      value: 'https://google.com'
    },
    {
      label: 'PayPal Lookalike (Phishing)',
      type: 'phishing',
      color: 'hover:border-rose-500/50 hover:bg-rose-500/10 text-rose-400',
      value: 'https://paypa1-login.xyz/verify'
    },
    {
      label: 'Urgent SMS Threat',
      type: 'message',
      color: 'hover:border-amber-500/50 hover:bg-amber-500/10 text-amber-400',
      value: 'URGENT! Your account will be suspended. Verify immediately: https://paypa1-login.xyz/verify'
    },
    {
      label: 'Safe Text Message',
      type: 'text',
      color: 'hover:border-cyan-500/50 hover:bg-cyan-500/10 text-cyan-400',
      value: 'Hey! Are we still meeting for lunch at 1 PM today?'
    }
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    onAnalyze(inputText.trim());
  };

  const handleSelectPreset = (value) => {
    setInputText(value);
    onAnalyze(value);
  };

  return (
    <div className="glass-panel p-6 sm:p-8 mb-8 border-slate-800">
      <div className="flex flex-col gap-4">
        
        {/* Title / Description */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-200 font-semibold text-lg">
            <Search className="w-5 h-5 text-cyan-400" />
            <span>Threat Inspection Portal</span>
          </div>
          <span className="text-xs text-slate-400 hidden sm:inline">
            Paste suspicious URL or full message
          </span>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="relative">
            <textarea
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste a suspicious link (e.g. https://paypa1-login.xyz/verify) or complete text message..."
              rows={3}
              disabled={isLoading}
              className="w-full bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-3.5 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20 text-sm md:text-base resize-none transition-all mono-text"
            />
            {inputText && (
              <button
                type="button"
                onClick={() => setInputText('')}
                className="absolute top-3 right-3 text-xs text-slate-500 hover:text-slate-300 bg-slate-800/60 px-2 py-1 rounded"
              >
                Clear
              </button>
            )}
          </div>

          {/* Action Row */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            
            {/* Sample Presets */}
            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <span className="text-xs text-slate-400 font-medium mr-1 flex items-center gap-1">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                Quick Test:
              </span>
              {PRESETS.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSelectPreset(preset.value)}
                  disabled={isLoading}
                  className={`text-xs px-2.5 py-1 rounded-lg border border-slate-800 bg-slate-900/60 transition-all font-medium ${preset.color}`}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || !inputText.trim()}
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-sm tracking-wide shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/35 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>{isLoading ? 'ANALYZING...' : 'ANALYZE THREAT'}</span>
            </button>

          </div>
        </form>

      </div>
    </div>
  );
}

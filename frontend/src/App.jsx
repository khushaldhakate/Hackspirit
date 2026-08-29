import React, { useState } from 'react';
import Navbar from './components/Navbar';
import LandingPage from './components/LandingPage';
import ThreatScanner from './components/ThreatScanner';
import ThreatIntelPage from './components/ThreatIntelPage';
import ReportsPage from './components/ReportsPage';
import AiStudioPage from './components/AiStudioPage';
import { ShieldCheck, ChevronRight } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_ENDPOINT = API_BASE ? `${API_BASE.replace(/\/$/, '')}/api/analyze` : '/api/analyze';

export default function App() {
  const [currentTab, setCurrentTab] = useState('home'); // 'home' | 'scanner' | 'intel' | 'reports' | 'studio'
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);

  const handleAnalyze = async (inputText) => {
    setIsLoading(true);
    setErrorMsg(null);
    setAnalysisResult(null);
    setCurrentTab('scanner');

    try {
      let response;
      try {
        response = await fetch(API_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input: inputText }),
        });
      } catch (err) {
        // Direct localhost fallback if proxy is inactive
        response = await fetch('http://127.0.0.1:8000/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input: inputText }),
        });
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Server returned status ${response.status}`);
      }

      const data = await response.json();
      setAnalysisResult(data);

      // Append to history
      const newHistoryItem = {
        id: `REP-${Math.floor(1000 + Math.random() * 9000)}`,
        target: inputText,
        type: data.type?.toUpperCase() || 'URL',
        threat: data.risk?.threat_type || 'Benign URL',
        score: data.risk?.score ?? 0,
        level: data.risk?.level || 'SAFE',
        mlConfidence: `${Math.round((data.ml_analysis?.confidence || 0) * 100)}%`,
        date: new Date().toISOString().replace('T', ' ').substring(0, 19),
        status: data.risk?.score >= 50 ? 'BLOCKED' : 'PASSED'
      };
      setScanHistory((prev) => [newHistoryItem, ...prev]);
    } catch (err) {
      console.error('Analysis request error:', err);
      setErrorMsg(
        err.message || 'Failed to connect to PhishGuard backend service. Ensure server is running on :8000'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectTab = (tab) => {
    setCurrentTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handlePresetSelect = (url) => {
    handleAnalyze(url);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="landing-page">
      <div className="app-bg-overlay" />

      <div className="app-content">
        {/* Global Unified Navbar */}
        <Navbar currentTab={currentTab} onSelectTab={handleSelectTab} />

        {/* Dynamic Multi-Page Router View */}
        <main>
          {currentTab === 'home' && (
            <LandingPage
              onOpenScanner={() => handleSelectTab('scanner')}
              onSelectPreset={handlePresetSelect}
              onSelectTab={handleSelectTab}
            />
          )}

          {currentTab === 'scanner' && (
            <ThreatScanner
              analysisResult={analysisResult}
              isLoading={isLoading}
              errorMsg={errorMsg}
              onAnalyze={handleAnalyze}
              onOpenStudio={() => handleSelectTab('studio')}
            />
          )}

          {currentTab === 'intel' && (
            <ThreatIntelPage onAnalyzePreset={handlePresetSelect} />
          )}

          {currentTab === 'reports' && (
            <ReportsPage
              history={scanHistory}
              onReinspect={handlePresetSelect}
            />
          )}

          {currentTab === 'studio' && (
            <AiStudioPage onAnalyzeLink={handlePresetSelect} />
          )}
        </main>

        {/* Global Clean Unified Footer */}
        <footer className="landing-footer" id="teams">
          <span>phishguard</span>
          <span>Quiet where it should be. Ready when it matters.</span>
          <button
            type="button"
            onClick={() => handleSelectTab('scanner')}
            className="flex items-center gap-1 text-[#247de8] font-bold bg-transparent border-none cursor-pointer"
          >
            Open workspace <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </footer>
      </div>
    </div>
  );
}

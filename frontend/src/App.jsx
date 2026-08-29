import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { ShieldCheck, Server, Globe, CheckCircle2, AlertCircle, RefreshCw, Cpu, Layers } from 'lucide-react'

function App() {
  const [healthData, setHealthData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastChecked, setLastChecked] = useState(null)

  const checkHealth = async () => {
    setLoading(true)
    setError(null)
    try {
      const apiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
      const response = await axios.get(`${apiBase}/api/health`)
      setHealthData(response.data)
      setLastChecked(new Date().toLocaleTimeString())
    } catch (err) {
      console.error('Health check failed:', err)
      setError(err.message || 'Could not connect to PhishGuard API')
      setLastChecked(new Date().toLocaleTimeString())
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    checkHealth()
  }, [])

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between selection:bg-cyan-500 selection:text-white">
      {/* Top Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-tr from-cyan-500 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/20 text-white">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                PhishGuard
              </span>
              <span className="ml-2 text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Phase 1 Active
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              Frontend: Ready
            </span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-4xl mx-auto px-6 py-12 flex-1 flex flex-col items-center justify-center text-center">
        {/* Hero badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300 mb-6 shadow-inner">
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          <span>PS10 · AI-Powered Multi-Layer Threat Detection System</span>
        </div>

        {/* Hero title */}
        <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight text-white mb-4">
          PhishGuard System Initialized
        </h1>
        <p className="text-slate-400 text-base md:text-lg max-w-2xl mb-10 leading-relaxed">
          Frontend and Backend baseline initialized successfully. Phase 1 environment is established and ready for multi-layer threat analysis pipelines.
        </p>

        {/* System Health Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 w-full text-left mb-8">
          {/* Frontend Status Card */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl relative overflow-hidden group hover:border-slate-700 transition">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-blue-500/10 text-blue-400 rounded-xl border border-blue-500/20">
                <Globe className="w-5 h-5" />
              </div>
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Operational
              </span>
            </div>
            <h3 className="text-lg font-semibold text-white mb-1">Frontend Service</h3>
            <p className="text-xs text-slate-400 mb-4">React + Vite + Tailwind CSS</p>
            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
              <span>Port: 5173</span>
              <span>Client State: Active</span>
            </div>
          </div>

          {/* Backend API Health Status Card */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl relative overflow-hidden group hover:border-slate-700 transition">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl border border-cyan-500/20">
                <Server className="w-5 h-5" />
              </div>
              {loading ? (
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Checking...
                </span>
              ) : error ? (
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <AlertCircle className="w-3.5 h-3.5" />
                  Connection Offline
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  API Healthy ({healthData?.status})
                </span>
              )}
            </div>
            <h3 className="text-lg font-semibold text-white mb-1">Backend API Health</h3>
            <p className="text-xs text-slate-400 mb-4">
              {error ? (
                <span className="text-rose-400 font-mono text-xs">{error}</span>
              ) : healthData ? (
                <span className="text-slate-300 font-mono text-xs">{JSON.stringify(healthData)}</span>
              ) : (
                'Connecting to backend API...'
              )}
            </p>
            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
              <span>Endpoint: /api/health</span>
              <button 
                onClick={checkHealth}
                disabled={loading}
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                Recheck
              </button>
            </div>
          </div>
        </div>

        {/* Architecture Checklist */}
        <div className="w-full bg-slate-900/40 border border-slate-800/60 rounded-xl p-5 text-left text-xs text-slate-400">
          <div className="flex items-center justify-between mb-3 text-slate-300 font-medium">
            <span className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Phase 1 Verification Matrix
            </span>
            {lastChecked && <span>Last verified: {lastChecked}</span>}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span className="text-slate-300">Backend API</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span className="text-slate-300">Vite React Client</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span className="text-slate-300">Tailwind Styling</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span className="text-slate-300">Env Configuration</span>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-500">
        PhishGuard Security Framework · Phase 1 Initialized · Ready for Multi-Layer Engine Integration
      </footer>
    </div>
  )
}

export default App

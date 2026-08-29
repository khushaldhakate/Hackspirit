import React from 'react';
import {
  ShieldCheck,
  Search,
  Activity,
  FileText,
  Cpu,
  Radar,
  Home
} from 'lucide-react';

export default function Navbar({ currentTab, onSelectTab }) {
  return (
    <div className="global-nav-container">
      <header className="global-nav">
        {/* Brand */}
        <div
          className="landing-brand"
          onClick={() => onSelectTab('home')}
          role="button"
          tabIndex={0}
        >
          <span className="landing-brand-mark" aria-hidden="true">
            <ShieldCheck className="w-4 h-4" />
          </span>
          <span>
            phish<span>guard</span>
          </span>
        </div>

        {/* Multi-Page Navigation Tabs */}
        <nav className="nav-tab-links" aria-label="Main application tabs">
          <button
            type="button"
            onClick={() => onSelectTab('home')}
            className={`nav-tab-btn ${currentTab === 'home' ? 'active' : ''}`}
          >
            <Home className="w-3.5 h-3.5" />
            <span>Home</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('scanner')}
            className={`nav-tab-btn ${currentTab === 'scanner' ? 'active' : ''}`}
          >
            <Search className="w-3.5 h-3.5" />
            <span>Threat Scanner</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('intel')}
            className={`nav-tab-btn ${currentTab === 'intel' ? 'active' : ''}`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Live Intel</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('reports')}
            className={`nav-tab-btn ${currentTab === 'reports' ? 'active' : ''}`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Detection Reports</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('studio')}
            className={`nav-tab-btn ${currentTab === 'studio' ? 'active' : ''}`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>AI Studio</span>
          </button>
        </nav>

        {/* Action Button */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => onSelectTab('scanner')}
            className="nav-cta-btn"
          >
            <Radar className="w-4 h-4" />
            <span>Scan URL</span>
          </button>
        </div>
      </header>
    </div>
  );
}

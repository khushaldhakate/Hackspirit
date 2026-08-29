import React, { useState } from 'react';
import {
  ShieldCheck,
  Search,
  Activity,
  FileText,
  Cpu,
  Radar,
  Home,
  Menu,
  X
} from 'lucide-react';

export default function Navbar({ currentTab, onSelectTab }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleTabClick = (tab) => {
    onSelectTab(tab);
    setMobileMenuOpen(false);
  };

  return (
    <div className="global-nav-container">
      <header className="global-nav">
        {/* Brand Logo */}
        <div
          className="landing-brand"
          onClick={() => handleTabClick('home')}
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

        {/* Desktop Multi-Page Navigation Tabs */}
        <nav className="nav-tab-links desktop-only" aria-label="Main navigation">
          <button
            type="button"
            onClick={() => handleTabClick('home')}
            className={`nav-tab-btn ${currentTab === 'home' ? 'active' : ''}`}
          >
            <Home className="w-3.5 h-3.5" />
            <span>Home</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('scanner')}
            className={`nav-tab-btn ${currentTab === 'scanner' ? 'active' : ''}`}
          >
            <Search className="w-3.5 h-3.5" />
            <span>Threat Scanner</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('intel')}
            className={`nav-tab-btn ${currentTab === 'intel' ? 'active' : ''}`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Live Intel</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('reports')}
            className={`nav-tab-btn ${currentTab === 'reports' ? 'active' : ''}`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Reports</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('studio')}
            className={`nav-tab-btn ${currentTab === 'studio' ? 'active' : ''}`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>AI Studio</span>
          </button>
        </nav>

        {/* Desktop Action + Mobile Menu Toggle */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => handleTabClick('scanner')}
            className="nav-cta-btn"
          >
            <Radar className="w-4 h-4" />
            <span className="hidden sm:inline">Scan URL</span>
          </button>

          {/* Mobile Hamburger Button */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="mobile-menu-toggle-btn"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </header>

      {/* Mobile Drawer Dropdown */}
      {mobileMenuOpen && (
        <div className="mobile-nav-drawer animate-fade-in">
          <button
            type="button"
            onClick={() => handleTabClick('home')}
            className={`mobile-nav-item ${currentTab === 'home' ? 'active' : ''}`}
          >
            <Home className="w-4 h-4" />
            <span>Home (Overview)</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('scanner')}
            className={`mobile-nav-item ${currentTab === 'scanner' ? 'active' : ''}`}
          >
            <Search className="w-4 h-4" />
            <span>Threat Scanner</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('intel')}
            className={`mobile-nav-item ${currentTab === 'intel' ? 'active' : ''}`}
          >
            <Activity className="w-4 h-4" />
            <span>Live Threat Feed</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('reports')}
            className={`mobile-nav-item ${currentTab === 'reports' ? 'active' : ''}`}
          >
            <FileText className="w-4 h-4" />
            <span>Detection Reports</span>
          </button>

          <button
            type="button"
            onClick={() => handleTabClick('studio')}
            className={`mobile-nav-item ${currentTab === 'studio' ? 'active' : ''}`}
          >
            <Cpu className="w-4 h-4" />
            <span>AI Threat Studio</span>
          </button>
        </div>
      )}
    </div>
  );
}

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const analyzeRoutes = require('./routes/analyzeRoutes');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/analyze', analyzeRoutes);

// Health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'PhishGuard API'
  });
});

// Root fallback
app.get('/', (req, res) => {
  res.json({
    message: 'PhishGuard API is running',
    healthCheck: '/api/health',
    endpoints: {
      health: 'GET /api/health',
      analyzeUrl: 'POST /api/analyze/url',
      analyzeMessage: 'POST /api/analyze/message',
      analyzeRedirect: 'POST /api/analyze/redirect',
      analyzeRisk: 'POST /api/analyze/risk',
      analyzeExplain: 'POST /api/analyze/explain',
      analyzeUnified: 'POST /api/analyze'
    }
  });
});

// Start server
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[PhishGuard API] Server running on port ${PORT}`);
    console.log(`[PhishGuard API] Health check at http://localhost:${PORT}/api/health`);
    console.log(`[PhishGuard API] URL Analyzer at POST http://localhost:${PORT}/api/analyze/url`);
  });
}

module.exports = app;

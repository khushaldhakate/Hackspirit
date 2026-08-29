const express = require('express');
const router = express.Router();
const { analyzeUrl } = require('../services/urlAnalyzer');
const { analyzeMessage } = require('../services/messageAnalyzer');
const { analyzeRedirect } = require('../services/redirectAnalyzer');
const { analyzeUrlWithML } = require('../services/mlService');
const { evaluateRisk } = require('../services/riskEngine');
const { generateSecurityExplanation } = require('../services/grokService');

/**
 * POST /api/analyze/url
 * Analyzes a URL string statically without executing or visiting it.
 */
router.post('/url', (req, res) => {
  const { url } = req.body || {};

  if (!url || typeof url !== 'string' || url.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'URL is required and must be a non-empty string.',
      analysis: {
        valid: false,
        flags: ['Empty or missing URL parameter']
      }
    });
  }

  try {
    const analysis = analyzeUrl(url);

    if (!analysis.valid) {
      return res.status(400).json({
        success: false,
        error: analysis.error || 'Failed to parse URL',
        analysis
      });
    }

    return res.status(200).json({
      success: true,
      analysis
    });
  } catch (err) {
    console.error('URL analysis error:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error while analyzing URL',
      details: err.message
    });
  }
});

/**
 * POST /api/analyze/message
 * Analyzes SMS, email, WhatsApp message text for phishing indicators and social engineering
 */
router.post('/message', (req, res) => {
  const { message } = req.body || {};

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Message is required and must be a non-empty string.',
      analysis: {
        valid: false,
        flags: ['Empty or missing message parameter']
      }
    });
  }

  try {
    const analysis = analyzeMessage(message);

    return res.status(200).json({
      success: true,
      analysis
    });
  } catch (err) {
    console.error('Message analysis error:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error while analyzing message',
      details: err.message
    });
  }
});

/**
 * POST /api/analyze/redirect
 * Safely inspects redirect chains with strict SSRF protection and hop limits
 */
router.post('/redirect', async (req, res) => {
  const { url } = req.body || {};

  if (!url || typeof url !== 'string' || url.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'URL is required and must be a non-empty string.',
      analysis: {
        valid: false,
        redirectDetected: false,
        redirectCount: 0,
        chain: [],
        finalUrl: null,
        finalDomain: null,
        blocked: false,
        error: 'Empty or missing URL parameter'
      }
    });
  }

  try {
    // Only pass URL — client cannot customize headers, timeout, or SSRF controls
    const analysis = await analyzeRedirect(url);

    return res.status(200).json({
      success: true,
      analysis
    });
  } catch (err) {
    console.error('Redirect analysis error:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error while analyzing redirects',
      details: err.message
    });
  }
});

/**
 * POST /api/analyze/ml
 * Classifies URL using pretrained CrabInHoney/urlbert-tiny-v4-malicious-url-classifier model
 */
router.post('/ml', async (req, res) => {
  const { url } = req.body || {};

  if (!url || typeof url !== 'string' || url.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'URL is required and must be a non-empty string.',
      analysis: null
    });
  }

  try {
    const result = await analyzeUrlWithML(url);

    if (!result.success) {
      return res.status(503).json(result);
    }

    return res.status(200).json(result);
  } catch (err) {
    console.error('ML route error:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error during ML inference',
      details: err.message
    });
  }
});

/**
 * POST /api/analyze/risk
 * Holistic evidence fusion and risk evaluation across URL, message, redirect, and ML layers
 */
router.post('/risk', async (req, res) => {
  const {
    url,
    message,
    urlAnalysis: preUrlAnalysis,
    messageAnalysis: preMessageAnalysis,
    redirectAnalysis: preRedirectAnalysis,
    mlAnalysis: preMlAnalysis
  } = req.body || {};

  const hasUrl = typeof url === 'string' && url.trim().length > 0;
  const hasMessage = typeof message === 'string' && message.trim().length > 0;
  const hasPrecomputed = preUrlAnalysis || preMessageAnalysis || preRedirectAnalysis || preMlAnalysis;

  if (!hasUrl && !hasMessage && !hasPrecomputed) {
    return res.status(400).json({
      success: false,
      error: 'Either url or message must be provided for risk analysis.'
    });
  }

  try {
    let urlAnalysis = preUrlAnalysis || null;
    let messageAnalysis = preMessageAnalysis || null;
    let redirectAnalysis = preRedirectAnalysis || null;
    let mlAnalysis = preMlAnalysis || null;

    // Static textual URL analysis
    if (hasUrl && !urlAnalysis) {
      urlAnalysis = analyzeUrl(url);
      if (!urlAnalysis.valid) {
        return res.status(400).json({
          success: false,
          error: urlAnalysis.error || 'Invalid URL provided',
          analysis: { urlAnalysis }
        });
      }
    }

    // Message social engineering analysis
    if (hasMessage && !messageAnalysis) {
      messageAnalysis = analyzeMessage(message);
      if (!messageAnalysis.text) {
        return res.status(400).json({
          success: false,
          error: messageAnalysis.error || 'Invalid message provided',
          analysis: { messageAnalysis }
        });
      }
    }

    // Safe redirect inspection (only if URL present)
    if (hasUrl && !redirectAnalysis) {
      redirectAnalysis = await analyzeRedirect(url);
    }

    // Pretrained ML inference (only if URL present)
    if (hasUrl && !mlAnalysis) {
      const mlResult = await analyzeUrlWithML(url);
      if (!mlResult.success) {
        return res.status(503).json({
          success: false,
          error: 'ML_SERVICE_UNAVAILABLE',
          message: 'Pretrained ML inference service is unavailable or returned an error',
          details: mlResult.error || mlResult.details
        });
      }
      mlAnalysis = mlResult.analysis;
    }

    // Evaluate Risk Engine
    const riskAssessment = evaluateRisk({
      urlAnalysis,
      messageAnalysis,
      redirectAnalysis,
      mlAnalysis
    });

    return res.status(200).json({
      success: true,
      ...riskAssessment
    });
  } catch (err) {
    console.error('Risk evaluation route error:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error during risk evaluation',
      details: err.message
    });
  }
});

/**
 * POST /api/analyze/explain
 * Consumes structured Risk Engine results and generates a human-readable security explanation via Grok
 */
router.post('/explain', async (req, res) => {
  const riskResult = req.body;

  if (!riskResult || typeof riskResult !== 'object' || Object.keys(riskResult).length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Risk assessment payload is required for explanation generation.'
    });
  }

  // Extract or default risk metrics
  const target = riskResult.risk ? riskResult.risk : riskResult;
  const risk = {
    riskScore: typeof target.riskScore === 'number' ? target.riskScore : 0,
    riskLevel: target.riskLevel || 'UNKNOWN',
    threatCategory: target.threatCategory || 'unknown'
  };

  try {
    const aiResult = await generateSecurityExplanation(riskResult);

    return res.status(200).json({
      success: true,
      risk,
      explanation: aiResult.explanation,
      aiStatus: aiResult.aiStatus,
      ...(aiResult.error ? { error: aiResult.error } : {})
    });
  } catch (err) {
    console.error('Explanation route error:', err);
    return res.status(200).json({
      success: true,
      risk,
      explanation: null,
      aiStatus: 'unavailable',
      error: err.message
    });
  }
});

/**
 * POST /api/analyze
 * Optional combined unified pipeline:
 * Analyzers -> URLBERT ML -> Risk Engine -> Grok AI Explanation
 */
router.post('/', async (req, res) => {
  const { url, message } = req.body || {};

  const hasUrl = typeof url === 'string' && url.trim().length > 0;
  const hasMessage = typeof message === 'string' && message.trim().length > 0;

  if (!hasUrl && !hasMessage) {
    return res.status(400).json({
      success: false,
      error: 'Either url or message must be provided for complete analysis.'
    });
  }

  try {
    let urlAnalysis = null;
    let messageAnalysis = null;
    let redirectAnalysis = null;
    let mlAnalysis = null;

    if (hasUrl) {
      urlAnalysis = analyzeUrl(url);
      if (!urlAnalysis.valid) {
        return res.status(400).json({
          success: false,
          error: urlAnalysis.error || 'Invalid URL provided',
          analysis: { urlAnalysis }
        });
      }
      redirectAnalysis = await analyzeRedirect(url);
      const mlResult = await analyzeUrlWithML(url);
      if (mlResult.success) {
        mlAnalysis = mlResult.analysis;
      }
    }

    if (hasMessage) {
      messageAnalysis = analyzeMessage(message);
    }

    // 1. Authoritative Risk Engine Assessment
    const riskAssessment = evaluateRisk({
      urlAnalysis,
      messageAnalysis,
      redirectAnalysis,
      mlAnalysis
    });

    // 2. Advisory Grok AI Explainability
    const aiResult = await generateSecurityExplanation(riskAssessment);

    return res.status(200).json({
      success: true,
      risk: riskAssessment,
      explanation: aiResult.explanation,
      aiStatus: aiResult.aiStatus,
      ...(aiResult.error ? { aiError: aiResult.error } : {})
    });
  } catch (err) {
    console.error('Unified analysis error:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error during analysis pipeline',
      details: err.message
    });
  }
});

module.exports = router;

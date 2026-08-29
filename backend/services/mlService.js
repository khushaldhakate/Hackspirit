/**
 * PhishGuard ML Service Adapter (Phase 5)
 * Communicates with the local pretrained ML microservice via HTTP.
 * Keeps ML inference modular and decoupled from the main Node.js backend.
 */

const http = require('http');

function getMLServiceUrl() {
  return process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';
}

function getMLTimeoutMs() {
  return parseInt(process.env.ML_TIMEOUT_MS || '10000', 10);
}

/**
 * Check health and readiness of the local ML microservice
 * @returns {Promise<{ available: boolean, data?: object, error?: string }>}
 */
async function checkMLServiceHealth() {
  const serviceUrl = getMLServiceUrl();
  const urlObj = new URL(`${serviceUrl}/health`);

  return new Promise((resolve) => {
    const req = http.request(
      {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname,
        method: 'GET',
        timeout: 3000
      },
      (res) => {
        let rawData = '';
        res.on('data', chunk => { rawData += chunk; });
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const data = JSON.parse(rawData);
              resolve({ available: true, data });
            } catch (err) {
              resolve({ available: false, error: `Invalid health JSON: ${err.message}` });
            }
          } else {
            resolve({ available: false, error: `Health returned status ${res.statusCode}` });
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ available: false, error: 'ML service health check timed out' });
    });

    req.on('error', (err) => {
      resolve({ available: false, error: `ML service connection error: ${err.message}` });
    });

    req.end();
  });
}

/**
 * Send a URL to the ML service for classification using CrabInHoney/urlbert-tiny-v4-malicious-url-classifier
 * @param {string} url - Target URL to classify
 * @returns {Promise<object>} Inference result or controlled error
 */
async function analyzeUrlWithML(url) {
  if (!url || typeof url !== 'string' || url.trim().length === 0) {
    return {
      success: false,
      error: 'URL is required and must be a non-empty string'
    };
  }

  const trimmedUrl = url.trim();
  const postData = JSON.stringify({ url: trimmedUrl });
  const serviceUrl = getMLServiceUrl();
  const timeoutMs = getMLTimeoutMs();
  const urlObj = new URL(`${serviceUrl}/predict`);

  return new Promise((resolve) => {
    const req = http.request(
      {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: timeoutMs
      },
      (res) => {
        let rawData = '';
        res.on('data', chunk => { rawData += chunk; });
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const result = JSON.parse(rawData);
              resolve({
                success: true,
                analysis: {
                  model: result.model,
                  prediction: result.prediction,
                  probability: result.probability,
                  probabilities: result.probabilities,
                  inferenceTimeMs: result.inference_time_ms
                }
              });
            } catch (parseErr) {
              resolve({
                success: false,
                error: 'ML_INVALID_RESPONSE',
                details: parseErr.message
              });
            }
          } else {
            resolve({
              success: false,
              error: 'ML_INFERENCE_FAILED',
              statusCode: res.statusCode,
              details: rawData
            });
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({
        success: false,
        error: 'ML_SERVICE_TIMEOUT',
        message: `Inference request exceeded timeout of ${timeoutMs}ms`
      });
    });

    req.on('error', (err) => {
      resolve({
        success: false,
        error: 'ML_SERVICE_UNAVAILABLE',
        message: `Could not connect to ML service at ${serviceUrl}: ${err.message}`
      });
    });

    req.write(postData);
    req.end();
  });
}

module.exports = {
  checkMLServiceHealth,
  analyzeUrlWithML
};

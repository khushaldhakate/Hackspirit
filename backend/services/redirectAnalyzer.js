/**
 * PhishGuard Safe Redirect Analyzer Service (Phase 4)
 * Traces HTTP/HTTPS redirect chains safely without rendering, executing JavaScript,
 * or downloading response bodies. Enforces strict SSRF protection and hop limits.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { validateDestinationSafe } = require('../utils/securityUtils');
const { extractDomainComponents } = require('../utils/urlUtils');

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 5000;
const USER_AGENT = 'PhishGuard-Security-Scanner/1.0 (+https://github.com/Vatsal-Maske/HackSpirit)';
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * Perform a safe, single-hop HTTP request using HEAD (falling back to GET if necessary)
 * Closes the socket immediately upon receiving headers to avoid body transfer.
 */
function fetchSingleHop(urlObj, method = 'HEAD') {
  return new Promise((resolve, reject) => {
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const reqOptions = {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: `${urlObj.pathname || '/'}${urlObj.search || ''}`,
      method: method,
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': '*/*',
        'Connection': 'close'
      },
      timeout: REQUEST_TIMEOUT_MS
    };

    let settled = false;

    const req = client.request(reqOptions, (res) => {
      if (settled) return;
      settled = true;

      const statusCode = res.statusCode || 200;
      const location = res.headers.location || null;

      // Abort/destroy immediately to prevent receiving response body
      res.destroy();
      req.destroy();

      resolve({
        statusCode,
        location,
        headers: res.headers
      });
    });

    req.on('timeout', () => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });

    req.end();
  });
}

/**
 * Safely inspect a single HTTP hop, attempting HEAD first, then falling back to GET
 */
async function performSafeHop(urlObj) {
  try {
    const headResult = await fetchSingleHop(urlObj, 'HEAD');
    // If HEAD is rejected by the server (e.g. 405 Method Not Allowed or 501 Not Implemented), retry once with GET
    if (headResult.statusCode === 405 || headResult.statusCode === 501) {
      return await fetchSingleHop(urlObj, 'GET');
    }
    return headResult;
  } catch (err) {
    // If HEAD socket closed or failed, retry with GET
    try {
      return await fetchSingleHop(urlObj, 'GET');
    } catch (fallbackErr) {
      throw fallbackErr;
    }
  }
}

/**
 * Analyze the redirect chain of a URL safely
 * @param {string} rawUrl - Initial URL to inspect
 * @param {object} options - Security and testing options (e.g. allowLocalMockPorts)
 * @returns {Promise<object>} Structured redirect analysis
 */
async function analyzeRedirect(rawUrl, options = {}) {
  if (!rawUrl || typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    return {
      valid: false,
      redirectDetected: false,
      redirectCount: 0,
      chain: [],
      finalUrl: null,
      finalDomain: null,
      blocked: false,
      error: 'URL is required and must be a non-empty string'
    };
  }

  let currentUrl = rawUrl.trim();

  // Validate protocol
  let urlObj;
  try {
    urlObj = new URL(currentUrl);
  } catch (err) {
    return {
      valid: false,
      redirectDetected: false,
      redirectCount: 0,
      chain: [],
      finalUrl: currentUrl,
      finalDomain: null,
      blocked: false,
      error: `Malformed URL: ${err.message}`
    };
  }

  if (!['http:', 'https:'].includes(urlObj.protocol)) {
    return {
      valid: false,
      redirectDetected: false,
      redirectCount: 0,
      chain: [],
      finalUrl: currentUrl,
      finalDomain: null,
      blocked: true,
      reason: `Unsupported protocol '${urlObj.protocol}'. Only HTTP and HTTPS are permitted.`,
      error: 'UNSUPPORTED_PROTOCOL'
    };
  }

  const chain = [];
  const visitedUrls = new Set();
  visitedUrls.add(currentUrl);

  while (chain.length <= MAX_REDIRECTS) {
    // 1. SSRF Check: Validate destination before EVERY request
    const ssrfCheck = await validateDestinationSafe(
      urlObj.hostname,
      urlObj.port,
      {
        protocol: urlObj.protocol,
        allowLocalMockPorts: options.allowLocalMockPorts
      }
    );

    if (!ssrfCheck.safe) {
      const finalDomain = extractDomainComponents(urlObj.hostname).domain || urlObj.hostname;
      return {
        redirectDetected: chain.length > 0,
        redirectCount: chain.length,
        chain,
        finalUrl: currentUrl,
        finalDomain,
        blocked: true,
        reason: ssrfCheck.reason,
        error: 'DESTINATION_BLOCKED'
      };
    }

    // 2. Perform safe single-hop network inspection
    let hopResult;
    try {
      hopResult = await performSafeHop(urlObj);
    } catch (err) {
      const finalDomain = extractDomainComponents(urlObj.hostname).domain || urlObj.hostname;
      return {
        redirectDetected: chain.length > 0,
        redirectCount: chain.length,
        chain,
        finalUrl: currentUrl,
        finalDomain,
        blocked: false,
        error: `Network error during redirect inspection: ${err.message}`
      };
    }

    const { statusCode, location } = hopResult;

    // Check if this status code represents a redirect
    if (REDIRECT_STATUS_CODES.has(statusCode) && location) {
      // Check redirect count limit (max 5 hops allowed)
      if (chain.length >= MAX_REDIRECTS) {
        const finalDomain = extractDomainComponents(urlObj.hostname).domain || urlObj.hostname;
        return {
          redirectDetected: true,
          redirectCount: chain.length,
          chain,
          finalUrl: currentUrl,
          finalDomain,
          blocked: false,
          error: 'REDIRECT_LIMIT_EXCEEDED'
        };
      }

      // Resolve relative or absolute target URL
      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch (err) {
        const finalDomain = extractDomainComponents(urlObj.hostname).domain || urlObj.hostname;
        return {
          redirectDetected: true,
          redirectCount: chain.length,
          chain,
          finalUrl: currentUrl,
          finalDomain,
          blocked: false,
          error: `Invalid redirect Location header: ${location}`
        };
      }

      // Record this hop in the chain
      chain.push({
        from: currentUrl,
        statusCode,
        to: nextUrl
      });

      // Redirect loop detection
      if (visitedUrls.has(nextUrl)) {
        let nextDomain = '';
        try {
          nextDomain = extractDomainComponents(new URL(nextUrl).hostname).domain;
        } catch (_) {}

        return {
          redirectDetected: true,
          redirectCount: chain.length,
          chain,
          finalUrl: nextUrl,
          finalDomain: nextDomain,
          blocked: false,
          error: 'REDIRECT_LOOP_DETECTED'
        };
      }

      // Prepare for next iteration
      visitedUrls.add(nextUrl);
      currentUrl = nextUrl;
      try {
        urlObj = new URL(currentUrl);
      } catch (err) {
        return {
          redirectDetected: true,
          redirectCount: chain.length,
          chain,
          finalUrl: currentUrl,
          finalDomain: null,
          blocked: false,
          error: `Malformed target URL: ${err.message}`
        };
      }

      // Validate that the new target protocol is still HTTP/HTTPS
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return {
          redirectDetected: true,
          redirectCount: chain.length,
          chain,
          finalUrl: currentUrl,
          finalDomain: null,
          blocked: true,
          reason: `Redirect target has unsupported protocol '${urlObj.protocol}'.`,
          error: 'UNSUPPORTED_PROTOCOL'
        };
      }
    } else {
      // Non-redirect response (e.g. 200 OK, 404, etc.) -> End of chain reached
      const finalDomain = extractDomainComponents(urlObj.hostname).domain || urlObj.hostname;
      return {
        redirectDetected: chain.length > 0,
        redirectCount: chain.length,
        chain,
        finalUrl: currentUrl,
        finalDomain,
        blocked: false,
        error: null
      };
    }
  }

  const finalDomain = extractDomainComponents(urlObj.hostname).domain || urlObj.hostname;
  return {
    redirectDetected: chain.length > 0,
    redirectCount: chain.length,
    chain,
    finalUrl: currentUrl,
    finalDomain,
    blocked: false,
    error: null
  };
}

module.exports = {
  MAX_REDIRECTS,
  REQUEST_TIMEOUT_MS,
  USER_AGENT,
  REDIRECT_STATUS_CODES,
  analyzeRedirect
};

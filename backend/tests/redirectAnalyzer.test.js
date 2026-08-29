const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { analyzeRedirect } = require('../services/redirectAnalyzer');
const { isPrivateOrReservedIp } = require('../utils/securityUtils');

describe('PhishGuard Safe Redirect Analyzer Test Suite (Phase 4)', () => {
  let mockServer;
  let mockPort;
  let baseUrl;

  before(async () => {
    await new Promise((resolve) => {
      mockServer = http.createServer((req, res) => {
        const url = req.url;

        if (url === '/no-redirect') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('OK');
        } else if (url === '/redirect-301') {
          res.writeHead(301, { 'Location': `${baseUrl}/final-target` });
          res.end();
        } else if (url === '/multi-1') {
          res.writeHead(301, { 'Location': `${baseUrl}/multi-2` });
          res.end();
        } else if (url === '/multi-2') {
          res.writeHead(302, { 'Location': `${baseUrl}/final-target` });
          res.end();
        } else if (url === '/mixed-1') {
          res.writeHead(301, { 'Location': `${baseUrl}/mixed-2` });
          res.end();
        } else if (url === '/mixed-2') {
          res.writeHead(302, { 'Location': `${baseUrl}/final-target` });
          res.end();
        } else if (url === '/loop-a') {
          res.writeHead(302, { 'Location': `${baseUrl}/loop-b` });
          res.end();
        } else if (url === '/loop-b') {
          res.writeHead(302, { 'Location': `${baseUrl}/loop-a` });
          res.end();
        } else if (url.startsWith('/limit-')) {
          const step = parseInt(url.split('-')[1], 10);
          if (step <= 7) {
            res.writeHead(302, { 'Location': `${baseUrl}/limit-${step + 1}` });
            res.end();
          } else {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Reached limit destination');
          }
        } else if (url === '/ssrf-redirect') {
          // Redirect attempt pointing to a blocked private/internal address
          res.writeHead(302, { 'Location': 'http://192.168.1.10:8080/admin' });
          res.end();
        } else if (url === '/final-target') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('Final Destination Reached');
        } else {
          res.writeHead(404);
          res.end('Not Found');
        }
      });

      mockServer.listen(0, '127.0.0.1', () => {
        mockPort = mockServer.address().port;
        baseUrl = `http://127.0.0.1:${mockPort}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => {
      if (mockServer) {
        mockServer.close(resolve);
      } else {
        resolve();
      }
    });
  });

  // TEST 1: No redirect
  it('TEST 1: No redirect (direct 200 response)', async () => {
    const result = await analyzeRedirect(`${baseUrl}/no-redirect`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, false);
    assert.strictEqual(result.redirectCount, 0);
    assert.strictEqual(result.chain.length, 0);
    assert.strictEqual(result.finalUrl, `${baseUrl}/no-redirect`);
    assert.strictEqual(result.blocked, false);
    assert.strictEqual(result.error, null);
  });

  // TEST 2: 301 redirect
  it('TEST 2: Single 301 redirect (A -> B)', async () => {
    const result = await analyzeRedirect(`${baseUrl}/redirect-301`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, true);
    assert.strictEqual(result.redirectCount, 1);
    assert.strictEqual(result.chain.length, 1);
    assert.strictEqual(result.chain[0].statusCode, 301);
    assert.strictEqual(result.chain[0].to, `${baseUrl}/final-target`);
    assert.strictEqual(result.finalUrl, `${baseUrl}/final-target`);
    assert.strictEqual(result.blocked, false);
    assert.strictEqual(result.error, null);
  });

  // TEST 3: Multiple redirects
  it('TEST 3: Multiple redirects (A -> B -> C)', async () => {
    const result = await analyzeRedirect(`${baseUrl}/multi-1`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, true);
    assert.strictEqual(result.redirectCount, 2);
    assert.strictEqual(result.chain.length, 2);
    assert.strictEqual(result.finalUrl, `${baseUrl}/final-target`);
  });

  // TEST 4: Mixed redirects
  it('TEST 4: Mixed redirect status codes (301 and 302 in chain)', async () => {
    const result = await analyzeRedirect(`${baseUrl}/mixed-1`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, true);
    assert.strictEqual(result.chain.length, 2);
    assert.strictEqual(result.chain[0].statusCode, 301);
    assert.strictEqual(result.chain[1].statusCode, 302);
  });

  // TEST 5: Redirect loop
  it('TEST 5: Redirect loop detection (A -> B -> A)', async () => {
    const result = await analyzeRedirect(`${baseUrl}/loop-a`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, true);
    assert.strictEqual(result.error, 'REDIRECT_LOOP_DETECTED');
    assert.ok(result.chain.length >= 2);
  });

  // TEST 6: Redirect limit
  it('TEST 6: Redirect limit exceeded (more than 5 hops)', async () => {
    const result = await analyzeRedirect(`${baseUrl}/limit-1`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, true);
    assert.strictEqual(result.error, 'REDIRECT_LIMIT_EXCEEDED');
    assert.strictEqual(result.redirectCount, 5);
  });

  // TEST 7: Invalid URL
  it('TEST 7: Invalid URL structure validation', async () => {
    const result = await analyzeRedirect('htp://invalid-url::80');
    assert.strictEqual(result.valid, false);
    assert.ok(result.error);

    const emptyResult = await analyzeRedirect('');
    assert.strictEqual(emptyResult.valid, false);
  });

  // TEST 8: Unsupported protocol
  it('TEST 8: Unsupported protocol rejection (file:///etc/passwd)', async () => {
    const result = await analyzeRedirect('file:///etc/passwd');
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.blocked, true);
    assert.strictEqual(result.error, 'UNSUPPORTED_PROTOCOL');
  });

  // TEST 9: Localhost destination
  it('TEST 9: Localhost destination blocked (http://localhost:3000)', async () => {
    const result = await analyzeRedirect('http://localhost:3000');
    assert.strictEqual(result.blocked, true);
    assert.strictEqual(result.error, 'DESTINATION_BLOCKED');
    assert.ok(result.reason.includes('Private or loopback'));
  });

  // TEST 10: Private IP destination
  it('TEST 10: Private IP destination blocked (http://192.168.1.10)', async () => {
    const result = await analyzeRedirect('http://192.168.1.10/login');
    assert.strictEqual(result.blocked, true);
    assert.strictEqual(result.error, 'DESTINATION_BLOCKED');
  });

  // TEST 11: SSRF through redirect
  it('TEST 11: SSRF through redirect chain blocked (Public -> Private IP)', async () => {
    // Initial request is allowed on mockPort, but redirects to 192.168.1.10
    const result = await analyzeRedirect(`${baseUrl}/ssrf-redirect`, {
      allowLocalMockPorts: [mockPort]
    });
    assert.strictEqual(result.redirectDetected, true);
    assert.strictEqual(result.redirectCount, 1);
    assert.strictEqual(result.blocked, true);
    assert.strictEqual(result.error, 'DESTINATION_BLOCKED');
    assert.strictEqual(result.chain[0].to, 'http://192.168.1.10:8080/admin');
  });

  // Direct IP range unit verification
  it('12. Direct IP range security check validation', () => {
    assert.strictEqual(isPrivateOrReservedIp('127.0.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('10.0.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('192.168.1.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('172.20.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIp('169.254.169.254'), true);
    assert.strictEqual(isPrivateOrReservedIp('::1'), true);
    assert.strictEqual(isPrivateOrReservedIp('8.8.8.8'), false);
    assert.strictEqual(isPrivateOrReservedIp('1.1.1.1'), false);
  });
});

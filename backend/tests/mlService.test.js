const { describe, it } = require('node:test');
const assert = require('node:assert');
const { checkMLServiceHealth, analyzeUrlWithML } = require('../services/mlService');

describe('PhishGuard ML Service Test Suite (Phase 5)', () => {

  // Test 1, 2, 3: Health & Model Readiness
  it('1-3. ML service health endpoint reports loaded=true and model name', async () => {
    const health = await checkMLServiceHealth();
    assert.strictEqual(health.available, true, `ML Service should be available: ${health.error}`);
    assert.strictEqual(health.data.status, 'ok');
    assert.strictEqual(health.data.model, 'CrabInHoney/urlbert-tiny-v4-malicious-url-classifier');
    assert.strictEqual(health.data.loaded, true);
    assert.ok(health.data.label_count >= 2);
    assert.ok(Array.isArray(health.data.labels));
  });

  // Test 4-8: Real Model Inference on Valid URL
  it('4-8. Valid URL produces valid prediction with normalized probability distribution', async () => {
    const testUrl = 'https://example.com';
    const result = await analyzeUrlWithML(testUrl);

    assert.strictEqual(result.success, true);
    assert.ok(result.analysis);

    const { model, prediction, probability, probabilities } = result.analysis;

    // 4. Model name and prediction exist
    assert.strictEqual(model, 'CrabInHoney/urlbert-tiny-v4-malicious-url-classifier');
    assert.strictEqual(typeof prediction, 'string');
    assert.ok(prediction.length > 0);

    // 5. Probabilities are numeric
    assert.strictEqual(typeof probability, 'number');
    assert.ok(!isNaN(probability));

    // 6. Probabilities between 0 and 1
    assert.ok(probability >= 0 && probability <= 1, `Probability should be in [0, 1], got ${probability}`);

    const labelKeys = Object.keys(probabilities);
    assert.ok(labelKeys.length >= 2, 'Should have at least 2 label probabilities');

    let sum = 0;
    let maxLabel = '';
    let maxProb = -1;

    for (const label of labelKeys) {
      const p = probabilities[label];
      assert.strictEqual(typeof p, 'number');
      assert.ok(p >= 0 && p <= 1);
      sum += p;
      if (p > maxProb) {
        maxProb = p;
        maxLabel = label;
      }
    }

    // 7. Probabilities approximately sum to 1 (softmax normalization)
    assert.ok(Math.abs(sum - 1.0) < 0.02, `Probabilities must sum to ~1.0, got ${sum}`);

    // 8. Prediction corresponds to highest probability class
    assert.strictEqual(prediction, maxLabel, `Prediction '${prediction}' must match highest probability class '${maxLabel}'`);
    assert.strictEqual(probability, maxProb);
  });

  // Test 9: Empty URL rejected
  it('9. Empty URL is rejected before inference', async () => {
    const result = await analyzeUrlWithML('');
    assert.strictEqual(result.success, false);
    assert.ok(result.error);
  });

  // Test 10: Invalid input rejected
  it('10. Non-string / invalid input is rejected', async () => {
    const result1 = await analyzeUrlWithML(null);
    assert.strictEqual(result1.success, false);

    const result2 = await analyzeUrlWithML(undefined);
    assert.strictEqual(result2.success, false);
  });

  // Test 11: Controlled timeout / service error handling
  it('11. ML service unreachable error is handled gracefully without crashing', async () => {
    // Temporarily point to non-existent port to verify controlled error
    const originalEnv = process.env.ML_SERVICE_URL;
    process.env.ML_SERVICE_URL = 'http://127.0.0.1:59999';

    try {
      const result = await analyzeUrlWithML('https://example.com');
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.error, 'ML_SERVICE_UNAVAILABLE');
    } finally {
      process.env.ML_SERVICE_URL = originalEnv;
    }
  });
});

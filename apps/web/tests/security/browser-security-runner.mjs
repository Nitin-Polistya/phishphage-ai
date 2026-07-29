import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { serializeReportsToCsv } from '../../lib/reports.ts';

const baseURL = 'http://localhost:3000';
const routes = ['/', '/dashboard', '/analyze', '/history', '/reports', '/settings'];
const viewports = [
  { name: 'mobile', width: 390, height: 844 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1440, height: 900 },
];
const storageKey = 'phishphage.preferences.v1';

function syntheticScan(value) {
  return {
    id: 'synthetic-scan', timestamp: '2026-07-26T00:00:00.000Z', subject: value, sender: value,
    classification: 'safe', riskScore: 1, confidence: 0.5, indicators: [], attachmentCount: 0,
    extractedUrlCount: 0, details: { recipients: [], urls: [], attachments: [], recommendations: [] },
  };
}

const launchOptions = { headless: true };
if (process.env.CHROME_EXECUTABLE_PATH) {
  launchOptions.executablePath = process.env.CHROME_EXECUTABLE_PATH;
}
const browser = await chromium.launch(launchOptions);
try {
  for (const viewport of viewports) {
    for (const theme of ['light', 'dark']) {
      const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
      await context.addInitScript(({ theme: selectedTheme, storageKey: key }) => {
        localStorage.clear();
        sessionStorage.clear();
        localStorage.setItem(key, JSON.stringify({
          defaultAnalysisMode: 'quick_paste', saveSuccessfulScans: false,
          confirmBeforeClearingHistory: true, defaultHistorySortOrder: 'newest', theme: selectedTheme,
        }));
      }, { theme, storageKey });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      page.on('console', (message) => {
        if (message.type() === 'error' || message.type() === 'warning') errors.push(message.text());
      });
      for (const route of routes) {
        const response = await page.goto(baseURL + route, { waitUntil: 'networkidle' });
        assert.equal(response?.status(), 200, `${route} status`);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${route} overflow`);
        assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), theme, `${route} theme`);
      }
      assert.deepEqual(errors, [], `${viewport.name}/${theme} browser errors: ${errors.join('; ')}`);
      await context.close();
    }
  }

  const headerContext = await browser.newContext();
  for (const route of routes) {
    const response = await headerContext.request.get(baseURL + route);
    assert.equal(response.status(), 200, `${route} header status`);
    const headers = response.headers();
    assert.match(headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(headers['x-content-type-options'], 'nosniff');
    assert.equal(headers['x-frame-options'], 'DENY');
    assert.equal(headers['referrer-policy'], 'no-referrer');
    assert.match(headers['permissions-policy'], /camera=\(\)/);
  }
  const health = await headerContext.request.get('http://127.0.0.1:8000/api/v1/health');
  assert.ok([200, 503].includes(health.status()));
  assert.match(health.headers()['x-request-id'], /^[A-Za-z0-9._-]{1,80}$/);
  assert.equal(health.headers()['cache-control'], 'no-store');
  await headerContext.close();

  const xssContext = await browser.newContext();
  const page = await xssContext.newPage();
  const unexpectedRequests = [];
  page.on('request', (request) => {
    if (/example\.invalid|127\.0\.0\.1|169\.254\.169\.254|localhost/.test(request.url()) && !request.url().startsWith(baseURL)) unexpectedRequests.push(request.url());
  });
  await page.goto(baseURL + '/analyze', { waitUntil: 'networkidle' });
  await page.locator('#quick-subject').fill('<script>window.__xss = true</script>');
  await page.locator('#quick-body').fill('<img src=x onerror="window.__xss = true"><svg onload="window.__xss = true"> https://example.invalid');
  assert.equal(await page.evaluate(() => window.__xss), undefined);
  assert.equal(await page.locator('[onerror],[onload]').count(), 0);
  assert.deepEqual(unexpectedRequests, []);

  const csv = serializeReportsToCsv(['=', '+', '-', '@'].map((value) => syntheticScan(value)));
  for (const value of ['=', '+', '-', '@']) assert.match(csv, new RegExp(`"'\\${value}"`));

  const storage = await page.evaluate(() => Object.fromEntries(Object.entries(localStorage)));
  const storageText = JSON.stringify(storage);
  assert.equal(storageText.includes('window.__xss'), false);
  assert.equal(storageText.includes('example.invalid'), false);
  await xssContext.close();
  console.log(`PASS: ${routes.length} routes × ${viewports.length} viewports × 2 themes; headers, XSS, CSV, storage, and SSRF observations verified`);
} finally {
  await browser.close();
}

import { expect, test } from '@playwright/test';

const routes = ['/', '/dashboard', '/analyze', '/history', '/reports', '/settings'];
const viewports = [
  { name: 'mobile', width: 390, height: 844 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1440, height: 900 },
];

test.beforeEach(async ({ context }) => {
  await context.clearCookies();
  await context.addInitScript(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
});

for (const viewport of viewports) {
  for (const theme of ['light', 'dark'] as const) {
    test(`routes render safely at ${viewport.name} in ${theme} theme`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.addInitScript((selectedTheme) => {
        localStorage.setItem('phishphage.preferences.v1', JSON.stringify({
          defaultAnalysisMode: 'quick_paste',
          saveSuccessfulScans: false,
          confirmBeforeClearingHistory: true,
          defaultHistorySortOrder: 'newest',
          theme: selectedTheme,
        }));
      }, theme);

      const browserErrors: string[] = [];
      page.on('pageerror', (error) => browserErrors.push(error.message));
      page.on('console', (message) => {
        if (message.type() === 'error' || message.type() === 'warning') browserErrors.push(message.text());
      });

      for (const route of routes) {
        const response = await page.goto(route, { waitUntil: 'networkidle' });
        expect(response?.status(), `${route} status`).toBe(200);
        await expect(page.locator('body')).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
        expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
      }

      expect(browserErrors, browserErrors.join('\n')).toEqual([]);
    });
  }
}

test('HTML routes return required security headers', async ({ request }) => {
  for (const route of routes) {
    const response = await request.get(route);
    expect(response.status()).toBe(200);
    const headers = response.headers();
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['permissions-policy']).toContain('camera=()');
  }
});

test('API health response has request ID and no-store policy', async ({ request }) => {
  const response = await request.get('http://127.0.0.1:8000/api/v1/health');
  expect([200, 503]).toContain(response.status());
  expect(response.headers()['x-request-id']).toMatch(/^[A-Za-z0-9._-]{1,80}$/);
  expect(response.headers()['cache-control']).toBe('no-store');
});

test('synthetic XSS text remains data and does not execute', async ({ page }) => {
  await page.goto('/analyze', { waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: 'Quick Paste' }).click();
  await page.locator('#quick-subject').fill('<script>window.__xss = true</script>');
  await page.locator('#quick-body').fill('<img src=x onerror="window.__xss = true"><svg onload="window.__xss = true">');
  expect(await page.evaluate(() => (window as typeof window & { __xss?: boolean }).__xss)).toBeUndefined();
  expect(await page.locator('script').filter({ hasText: '__xss' }).count()).toBe(0);
  expect(await page.locator('[onerror],[onload]').count()).toBe(0);
});

test('analysis does not fetch synthetic email URLs', async ({ page }) => {
  const unexpected: string[] = [];
  page.on('request', (request) => {
    if (/example\.invalid|127\.0\.0\.1|169\.254\.169\.254|localhost/.test(request.url())) unexpected.push(request.url());
  });
  await page.goto('/analyze', { waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: 'Quick Paste' }).click();
  await page.locator('#quick-body').fill('https://example.invalid https://localhost https://127.0.0.1 https://169.254.169.254');
  expect(unexpected).toEqual([]);
});

test('framing is denied by response policy', async ({ page }) => {
  await page.goto('/');
  const framePolicy = await page.evaluate(() => ({
    csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute('content') ?? null,
  }));
  expect(framePolicy.csp).toBeNull();
  const response = await page.request.get('/');
  expect(response.headers()['x-frame-options']).toBe('DENY');
});

export function buildContentSecurityPolicy(configuredApiOrigin: string, isDevelopment = process.env.NODE_ENV !== 'production'): string {
  const scriptSources = ["'self'", "'unsafe-inline'"];
  if (isDevelopment) scriptSources.push("'unsafe-eval'");

  return [
    "default-src 'self'",
    `script-src ${scriptSources.join(' ')}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    `connect-src 'self' ${configuredApiOrigin}`.trim(),
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');
}

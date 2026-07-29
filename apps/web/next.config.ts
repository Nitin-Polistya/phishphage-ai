import type { NextConfig } from 'next';

const configuredApiOrigin = (() => {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  if (!configured) return '';
  try {
    return new URL(configured).origin;
  } catch {
    return '';
  }
})();

const nextConfig: NextConfig = {
  experimental: {
    webpackBuildWorker: false,
  },
  async headers() {
    return [{
      source: '/(.*)',
      headers: [
        { key: 'Content-Security-Policy', value: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ${configuredApiOrigin}; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'` },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        { key: 'X-Frame-Options', value: 'DENY' },
      ],
    }];
  },
};

export default nextConfig;

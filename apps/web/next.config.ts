import type { NextConfig } from 'next';

import { buildContentSecurityPolicy } from './lib/security-policy';

const configuredApiOrigin = (() => {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL?.trim() || 'http://127.0.0.1:8000';
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
        { key: 'Content-Security-Policy', value: buildContentSecurityPolicy(configuredApiOrigin) },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        { key: 'X-Frame-Options', value: 'DENY' },
      ],
    }];
  },
};

export default nextConfig;

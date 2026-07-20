import type { Metadata } from 'next';
import type { ReactNode } from 'react';

import { ThemeController } from '@/components/theme-controller';

import './globals.css';

const themeInitializationScript = `
  (() => {
    const storageKey = 'phishphage.preferences.v1';
    const validThemes = new Set(['system', 'dark', 'light']);
    let preference = 'system';
    try {
      const stored = JSON.parse(localStorage.getItem(storageKey) || '{}');
      if (validThemes.has(stored.theme)) preference = stored.theme;
    } catch {}
    const resolved = preference === 'system'
      ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : preference;
    document.documentElement.dataset.theme = resolved;
    document.documentElement.style.colorScheme = resolved;
  })();
`;

export const metadata: Metadata = {
  title: {
    default: 'PhishShield AI',
    template: '%s | PhishShield AI',
  },
  description: 'PhishShield AI provides explainable, privacy-conscious phishing risk analysis for suspicious emails.',
  keywords: ['phishing detection', 'email security', 'explainable ML', 'FastAPI', 'Next.js'],
  authors: [{ name: 'PhishShield AI contributors' }],
  creator: 'PhishShield AI',
  openGraph: {
    title: 'PhishShield AI — Explainable email risk analysis',
    description: 'Understand suspicious email signals with calibrated, privacy-conscious analysis.',
    type: 'website',
  },
  twitter: { card: 'summary', title: 'PhishShield AI', description: 'Explainable phishing risk analysis for suspicious emails.' },
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: themeInitializationScript }} /></head>
      <body><ThemeController />{children}</body>
    </html>
  );
}

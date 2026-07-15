import type { Metadata } from 'next';
import type { ReactNode } from 'react';

import { ThemeController } from '@/components/theme-controller';

import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'PhishPhage AI',
    template: '%s | PhishPhage AI',
  },
  description: 'PhishPhage AI email phishing detection and risk analysis.',
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body><ThemeController />{children}</body>
    </html>
  );
}

import type { Metadata } from 'next';
import type { ReactNode } from 'react';

import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'PhishPhage AI',
    template: '%s | PhishPhage AI',
  },
  description: 'PhishPhage AI email phishing detection and risk analysis.',
};

import { AppShell } from '@/components/layout/app-shell';

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <AppShell>
          {children}
        </AppShell>
      </body>
    </html>
  );
}

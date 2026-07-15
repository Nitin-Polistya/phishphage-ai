import type { Metadata } from 'next';

import { ScanHistory } from '@/components/history/scan-history';

export const metadata: Metadata = {
  title: 'Scan History',
};

export default function ScanHistoryPage() {
  return <ScanHistory />;
}

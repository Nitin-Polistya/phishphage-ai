import type { Metadata } from 'next';

import { ReportsWorkspace } from '@/components/reports/reports-workspace';

export const metadata: Metadata = {
  title: 'Reports',
};

export default function ReportsPage() {
  return <ReportsWorkspace />;
}

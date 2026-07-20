import type { Metadata } from 'next';

import { ProductionAnalysis } from '@/components/analysis/production-analysis';

export const metadata: Metadata = {
  title: 'Analyze Email',
};

export default function AnalyzePage() {
  return <ProductionAnalysis />;
}

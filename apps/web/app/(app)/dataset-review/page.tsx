import type { Metadata } from 'next';

import { DatasetReviewWorkspace } from '@/components/dataset-review/dataset-review-workspace';

export const metadata: Metadata = { title: 'Dataset Review' };

export default function DatasetReviewPage() {
  return <DatasetReviewWorkspace />;
}

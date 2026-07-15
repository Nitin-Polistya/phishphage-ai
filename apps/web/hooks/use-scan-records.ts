'use client';

import { useEffect, useState } from 'react';

import { readScans, subscribeToScans } from '@/lib/scan-store';
import type { ScanRecord } from '@/types';

export function useScanRecords() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    const refresh = () => {
      setScans(readScans());
      setIsLoaded(true);
    };
    const unsubscribe = subscribeToScans(refresh);
    refresh();
    return unsubscribe;
  }, []);

  return { scans, isLoaded };
}

import type { ScanRecord } from '@/types';
import type { ThreatClassification } from '@/types/analysis';

export type ScanHistoryFilter = 'all' | ThreatClassification;
export type ScanHistorySortOrder = 'newest' | 'oldest' | 'highest-risk' | 'lowest-risk';

export function filterAndSortScans(scans: ScanRecord[], query: string, filter: ScanHistoryFilter, order: ScanHistorySortOrder) {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const matches = scans.filter((scan) => (
    (filter === 'all' || scan.classification === filter)
    && (!normalizedQuery || scan.subject.toLocaleLowerCase().includes(normalizedQuery) || scan.sender.toLocaleLowerCase().includes(normalizedQuery))
  ));

  return [...matches].sort((left, right) => {
    if (order === 'oldest') return new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime();
    if (order === 'highest-risk') return right.riskScore - left.riskScore || new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
    if (order === 'lowest-risk') return left.riskScore - right.riskScore || new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
    return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
  });
}

export function paginateScans(scans: ScanRecord[], page: number, pageSize: number) {
  const pageCount = Math.max(1, Math.ceil(scans.length / pageSize));
  const currentPage = Math.min(Math.max(1, page), pageCount);
  return {
    currentPage,
    pageCount,
    scans: scans.slice((currentPage - 1) * pageSize, currentPage * pageSize),
  };
}

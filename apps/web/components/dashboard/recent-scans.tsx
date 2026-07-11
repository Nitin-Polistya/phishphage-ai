import { ScanResult } from '@/types';
import { cn } from '@/lib/utils';

interface RecentScansProps {
  scans: ScanResult[];
}

export function RecentScans({ scans }: RecentScansProps) {
  const getStatusStyle = (status: ScanResult['status']) => {
    switch (status) {
      case 'phishing': return 'bg-red-100 text-red-700 border-red-200';
      case 'suspicious': return 'bg-amber-100 text-amber-700 border-amber-200';
      case 'safe': return 'bg-green-100 text-green-700 border-green-200';
    }
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-100">
        <h3 className="font-semibold text-slate-900">Recent Analysis</h3>
        <p className="text-xs text-slate-500">Last 5 email scans performed</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50 text-slate-500 font-medium border-b border-slate-100">
            <tr>
              <th className="px-6 py-3 font-medium">Timestamp</th>
              <th className="px-6 py-3 font-medium">Status</th>
              <th className="px-6 py-3 font-medium">Confidence</th>
              <th className="px-6 py-3 font-medium">Threat Type</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {scans.map((scan) => (
              <tr key={scan.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-4 text-slate-600">
                  {new Date(scan.timestamp).toLocaleString()}
                </td>
                <td className="px-6 py-4">
                  <span className={cn(
                    "px-2 py-1 rounded-full text-[10px] font-bold uppercase border",
                    getStatusStyle(scan.status)
                  )}>
                    {scan.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-slate-600">
                  {(scan.confidence * 100).toFixed(1)}%
                </td>
                <td className="px-6 py-4 text-slate-600 italic">
                  {scan.threatType || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
 export function ThreatOverview() {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-6">
        <h3 className="font-semibold text-slate-900">Threat Overview</h3>
        <p className="text-xs text-slate-500">Distribution of detected phishing vectors</p>
      </div>
      <div className="flex h-64 items-end justify-around gap-4 px-4">
        {[
          { label: 'Brand', value: 65, color: 'bg-blue-500' },
          { label: 'Urgency', value: 45, color: 'bg-amber-500' },
          { label: 'Credential', value: 80, color: 'bg-red-500' },
          { label: 'Malware', value: 30, color: 'bg-purple-500' },
          { label: 'Social', value: 55, color: 'bg-indigo-500' },
        ].map((bar) => (
          <div key={bar.label} className="flex flex-col items-center gap-2 flex-1 max-w-[60px]">
            <div className="relative w-full group">
              <div 
                className={cn("w-full rounded-t-md transition-all duration-500 group-hover:opacity-80", bar.color)} 
                style={{ height: `${bar.value}%` }}
              />
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 text-[10px] font-bold text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity">
                {bar.value}%
              </div>
            </div>
            <span className="text-[10px] font-medium text-slate-500 truncate w-full text-center">
              {bar.label}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-6 flex justify-center gap-4 border-t pt-4">
        <div className="flex items-center gap-1.5">
          <div className="h-2 w-2 rounded-full bg-red-500" />
          <span className="text-[10px] text-slate-500">High Risk</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-2 w-2 rounded-full bg-amber-500" />
          <span className="text-[10px] text-slate-500">Medium Risk</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-2 w-2 rounded-full bg-blue-500" />
          <span className="text-[10px] text-slate-500">Low Risk</span>
        </div>
      </div>
    </div>
  );
}

function cn(...inputs: Array<string | false | null | undefined>) {
  return inputs.filter(Boolean).join(' ');
}

'use client';

import { useEffect, useState } from 'react';
import { Activity, CircleAlert, CircleCheck, Loader2 } from 'lucide-react';

import { ApiError, fetchHealthStatus } from '@/lib/api';
import type { HealthResponse } from '@/types/inference';

type ConnectionState = 'loading' | 'connected' | 'degraded' | 'offline';

export function BackendStatus() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [state, setState] = useState<ConnectionState>('loading');

  useEffect(() => {
    const controller = new AbortController();
    void fetchHealthStatus(controller.signal).then((value) => {
      setHealth(value);
      setState(value.loaded_model && value.status === 'ok' ? 'connected' : 'degraded');
    }).catch((error: unknown) => {
      if (!controller.signal.aborted) {
        setState(error instanceof ApiError && error.kind === 'service_unavailable' ? 'degraded' : 'offline');
      }
    });
    return () => controller.abort();
  }, []);

  const config = {
    loading: { label: 'Loading', icon: Loader2, tone: 'text-muted-foreground' },
    connected: { label: 'Connected', icon: CircleCheck, tone: 'text-success' },
    degraded: { label: 'Degraded', icon: CircleAlert, tone: 'text-warning' },
    offline: { label: 'Offline', icon: CircleAlert, tone: 'text-danger' },
  }[state];
  const Icon = config.icon;

  return (
    <div className="flex items-center gap-3 text-xs" aria-live="polite">
      <span className={`flex items-center gap-1.5 font-medium ${config.tone}`}>
        <Icon className={`h-3.5 w-3.5 motion-reduce:animate-none ${state === 'loading' ? 'animate-spin' : ''}`} aria-hidden="true" />
        <span>{config.label}</span>
      </span>
      {health?.model_version && <span className="hidden border-l border-input pl-3 text-foreground0 sm:inline">Model v{health.model_version}</span>}
      {health?.deployment_candidate && <span className="hidden rounded border border-warning/30 px-1.5 py-0.5 text-warning md:inline">Candidate model</span>}
      <Activity className="hidden h-3.5 w-3.5 text-muted-foreground md:inline" aria-hidden="true" />
    </div>
  );
}

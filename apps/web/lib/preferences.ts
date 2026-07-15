import type { ScanHistorySortOrder } from '@/lib/scan-history';
import type { AnalysisInputMode } from '@/types/analysis';

export type ThemePreference = 'system' | 'dark' | 'light';

export interface AppPreferences {
  defaultAnalysisMode: AnalysisInputMode;
  saveSuccessfulScans: boolean;
  confirmBeforeClearingHistory: boolean;
  defaultHistorySortOrder: ScanHistorySortOrder;
  theme: ThemePreference;
}

export interface PreferenceState {
  preferences: AppPreferences;
  storageAvailable: boolean;
  recoveredFromMalformedData: boolean;
}

export const PREFERENCES_STORAGE_KEY = 'phishphage.preferences.v1';
const PREFERENCES_STORAGE_EVENT = 'phishphage:preferences-changed';

export const DEFAULT_PREFERENCES: AppPreferences = {
  defaultAnalysisMode: 'quick_paste',
  saveSuccessfulScans: true,
  confirmBeforeClearingHistory: true,
  defaultHistorySortOrder: 'newest',
  theme: 'system',
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizePreferences(value: unknown): { preferences: AppPreferences; recovered: boolean } {
  if (!isObject(value)) return { preferences: DEFAULT_PREFERENCES, recovered: true };

  const preferences: AppPreferences = {
    defaultAnalysisMode: value.defaultAnalysisMode === 'raw_email' || value.defaultAnalysisMode === 'eml_upload' || value.defaultAnalysisMode === 'quick_paste'
      ? value.defaultAnalysisMode
      : DEFAULT_PREFERENCES.defaultAnalysisMode,
    saveSuccessfulScans: typeof value.saveSuccessfulScans === 'boolean' ? value.saveSuccessfulScans : DEFAULT_PREFERENCES.saveSuccessfulScans,
    confirmBeforeClearingHistory: typeof value.confirmBeforeClearingHistory === 'boolean' ? value.confirmBeforeClearingHistory : DEFAULT_PREFERENCES.confirmBeforeClearingHistory,
    defaultHistorySortOrder: value.defaultHistorySortOrder === 'oldest' || value.defaultHistorySortOrder === 'highest-risk' || value.defaultHistorySortOrder === 'lowest-risk' || value.defaultHistorySortOrder === 'newest'
      ? value.defaultHistorySortOrder
      : DEFAULT_PREFERENCES.defaultHistorySortOrder,
    theme: value.theme === 'dark' || value.theme === 'light' || value.theme === 'system' ? value.theme : DEFAULT_PREFERENCES.theme,
  };

  const recovered = Object.keys(DEFAULT_PREFERENCES).some((key) => preferences[key as keyof AppPreferences] !== value[key]);
  return { preferences, recovered };
}

export function readPreferenceState(): PreferenceState {
  if (typeof window === 'undefined') {
    return { preferences: DEFAULT_PREFERENCES, storageAvailable: true, recoveredFromMalformedData: false };
  }

  try {
    const stored = window.localStorage.getItem(PREFERENCES_STORAGE_KEY);
    if (!stored) return { preferences: DEFAULT_PREFERENCES, storageAvailable: true, recoveredFromMalformedData: false };
    const normalized = normalizePreferences(JSON.parse(stored) as unknown);
    return { preferences: normalized.preferences, storageAvailable: true, recoveredFromMalformedData: normalized.recovered };
  } catch (error) {
    const malformed = error instanceof SyntaxError;
    return { preferences: DEFAULT_PREFERENCES, storageAvailable: malformed, recoveredFromMalformedData: malformed };
  }
}

export function readPreferences(): AppPreferences {
  return readPreferenceState().preferences;
}

export function savePreferences(preferences: AppPreferences): boolean {
  if (typeof window === 'undefined') return false;
  try {
    window.localStorage.setItem(PREFERENCES_STORAGE_KEY, JSON.stringify(preferences));
    window.dispatchEvent(new Event(PREFERENCES_STORAGE_EVENT));
    return true;
  } catch {
    return false;
  }
}

export function subscribeToPreferences(listener: () => void): () => void {
  if (typeof window === 'undefined') return () => undefined;
  const onStorage = (event: StorageEvent) => {
    if (event.key === PREFERENCES_STORAGE_KEY) listener();
  };
  window.addEventListener(PREFERENCES_STORAGE_EVENT, listener);
  window.addEventListener('storage', onStorage);
  return () => {
    window.removeEventListener(PREFERENCES_STORAGE_EVENT, listener);
    window.removeEventListener('storage', onStorage);
  };
}

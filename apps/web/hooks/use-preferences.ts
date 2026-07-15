'use client';

import { useCallback, useEffect, useState } from 'react';

import {
  DEFAULT_PREFERENCES,
  readPreferenceState,
  savePreferences,
  subscribeToPreferences,
  type AppPreferences,
  type PreferenceState,
} from '@/lib/preferences';

const INITIAL_STATE: PreferenceState = {
  preferences: DEFAULT_PREFERENCES,
  storageAvailable: true,
  recoveredFromMalformedData: false,
};

export function usePreferences() {
  const [state, setState] = useState(INITIAL_STATE);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    const refresh = () => {
      setState(readPreferenceState());
      setIsLoaded(true);
    };
    const unsubscribe = subscribeToPreferences(refresh);
    refresh();
    return unsubscribe;
  }, []);

  const updatePreferences = useCallback((patch: Partial<AppPreferences>) => {
    const preferences = { ...state.preferences, ...patch };
    const stored = savePreferences(preferences);
    setState({ preferences, storageAvailable: stored, recoveredFromMalformedData: false });
  }, [state.preferences]);

  return { ...state, isLoaded, updatePreferences };
}

'use client';

import { useEffect } from 'react';

import { usePreferences } from '@/hooks/use-preferences';

export function ThemeController() {
  const { preferences, isLoaded } = usePreferences();

  useEffect(() => {
    if (!isLoaded) return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      const resolved = preferences.theme === 'system' ? (media.matches ? 'dark' : 'light') : preferences.theme;
      document.documentElement.dataset.theme = resolved;
      document.documentElement.style.colorScheme = resolved;
    };
    applyTheme();
    media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [isLoaded, preferences.theme]);

  return null;
}

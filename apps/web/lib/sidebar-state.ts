const SIDEBAR_COLLAPSED_KEY = 'phishphage.sidebar.collapsed.v1';

export function readSidebarCollapsed(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === 'true';
  } catch {
    return false;
  }
}

export function writeSidebarCollapsed(collapsed: boolean): boolean {
  if (typeof window === 'undefined') return false;
  try {
    window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(collapsed));
    return true;
  } catch {
    return false;
  }
}

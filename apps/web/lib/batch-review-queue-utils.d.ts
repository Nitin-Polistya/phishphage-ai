declare module '@/lib/batch-review-queue-utils.mjs' {
  export function filterQueueItems(items: unknown[], filters: Record<string, string>): unknown[];
  export function pageItems(items: unknown[], page: number, pageSize: number): unknown[];
  export function shortcutAction(key: string, target?: Record<string, boolean>): string | null;
  export function toggleSelection(selected: Set<string>, itemId: string, checked: boolean): Set<string>;
}

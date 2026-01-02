// =============================================================================
// TEMPLATE UTILITIES - Generic helper functions
// =============================================================================

/**
 * Format byte count to human-readable string (B, KB, MB, GB, TB)
 */
export function formatBytes(value: number): string {
  if (!value || value === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const scaled = value / Math.pow(1024, i);
  return `${scaled.toFixed(scaled < 10 ? 2 : 1)} ${units[i]}`;
}

/**
 * Format large numbers with K, M, B suffixes
 */
export function formatCount(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toString();
}

/**
 * Normalize various error types to a string message
 */
export function normalizeError(err: unknown): string {
  if (!err) return "Unknown error";
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && "message" in err) {
    return String((err as { message: string }).message);
  }
  return JSON.stringify(err);
}

/**
 * Format timestamp for display (short date format)
 */
export function formatDate(timestamp: string | Date): string {
  try {
    const d = typeof timestamp === "string" ? new Date(timestamp) : timestamp;
    return d.toLocaleDateString(undefined, { 
      month: 'short', 
      day: 'numeric', 
      year: '2-digit' 
    });
  } catch {
    return typeof timestamp === "string" ? timestamp : "";
  }
}

/**
 * Format timestamp with time
 */
export function formatDateTime(timestamp: string | Date): string {
  try {
    const d = typeof timestamp === "string" ? new Date(timestamp) : timestamp;
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return typeof timestamp === "string" ? timestamp : "";
  }
}

/**
 * Format duration in seconds to human-readable string
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (mins < 60) return `${mins}m ${secs}s`;
  const hours = Math.floor(mins / 60);
  const remainingMins = mins % 60;
  return `${hours}h ${remainingMins}m`;
}

/**
 * Format percentage
 */
export function formatPercent(value: number, decimals: number = 1): string {
  return `${value.toFixed(decimals)}%`;
}

/**
 * Create a debounced function that delays execution
 */
export function debounce<T extends (...args: Parameters<T>) => void>(
  fn: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  return (...args: Parameters<T>) => {
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), delay);
  };
}

/**
 * Create a throttled function that limits execution rate
 */
export function throttle<T extends (...args: Parameters<T>) => void>(
  fn: T,
  limit: number
): (...args: Parameters<T>) => void {
  let lastCall = 0;
  return (...args: Parameters<T>) => {
    const now = Date.now();
    if (now - lastCall >= limit) {
      lastCall = now;
      fn(...args);
    }
  };
}

/**
 * Clamp a number between min and max
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Generate a simple unique ID
 */
export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

/**
 * Deep clone an object (simple implementation)
 */
export function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Check if two arrays have the same elements (order-independent)
 */
export function arraysEqual<T>(a: T[], b: T[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((val, idx) => val === sortedB[idx]);
}

/**
 * Group array items by a key function
 */
export function groupBy<T, K extends string | number>(
  items: T[],
  keyFn: (item: T) => K
): Record<K, T[]> {
  return items.reduce((acc, item) => {
    const key = keyFn(item);
    if (!acc[key]) acc[key] = [];
    acc[key].push(item);
    return acc;
  }, {} as Record<K, T[]>);
}

/**
 * Get file extension from path
 */
export function getExtension(path: string): string {
  const lastDot = path.lastIndexOf(".");
  if (lastDot === -1 || lastDot === path.length - 1) return "";
  return path.slice(lastDot + 1).toLowerCase();
}

/**
 * Get filename from path
 */
export function getFilename(path: string): string {
  const lastSlash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return path.slice(lastSlash + 1);
}

/**
 * Get directory from path
 */
export function getDirectory(path: string): string {
  const lastSlash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return lastSlash === -1 ? "" : path.slice(0, lastSlash);
}

/**
 * Truncate string with ellipsis
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + "...";
}

/**
 * Truncate string in the middle with ellipsis
 */
export function truncateMiddle(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  const half = Math.floor((maxLength - 3) / 2);
  return str.slice(0, half) + "..." + str.slice(-half);
}

/**
 * Sleep for a specified duration (for testing/debugging)
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if running in Tauri environment
 */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI__" in window;
}

// =============================================================================
// UI HELPER FUNCTIONS
// =============================================================================

import type { CategoryConfig } from "./template-types";

/**
 * Get icon for a category
 */
export function getCategoryIcon(
  category: string,
  categories: CategoryConfig[]
): string {
  const config = categories.find(c => c.id === category || c.label === category);
  return config?.icon ?? "📄";
}

/**
 * Get CSS class for a category
 */
export function getCategoryClass(
  category: string,
  categories: CategoryConfig[]
): string {
  const config = categories.find(c => c.id === category || c.label === category);
  return config?.colorClass ?? "type-default";
}

/**
 * Get status icon based on status kind
 */
export function getStatusIcon(status: "idle" | "working" | "ok" | "error"): string {
  switch (status) {
    case "working": return "⏳";
    case "ok": return "✓";
    case "error": return "✗";
    default: return "○";
  }
}

/**
 * Format CPU usage as cores or percentage
 */
export function formatCpuUsage(percent: number, cores: number): string {
  const coresUsed = percent / 100;
  if (coresUsed >= 1) {
    return `${coresUsed.toFixed(1)}/${cores}`;
  }
  return `${percent.toFixed(0)}%`;
}

/**
 * Calculate statistics for a collection of items
 */
export function calculateStats<T extends { category: string; size: number }>(
  items: T[]
): {
  totalCount: number;
  totalSize: number;
  byCategory: Record<string, number>;
} {
  const byCategory: Record<string, number> = {};
  let totalSize = 0;

  for (const item of items) {
    byCategory[item.category] = (byCategory[item.category] || 0) + 1;
    totalSize += item.size;
  }

  return {
    totalCount: items.length,
    totalSize,
    byCategory,
  };
}

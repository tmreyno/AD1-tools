// Shared utility functions for forensic container analysis

/**
 * Format byte count to human-readable string (B, KB, MB, GB, TB)
 */
export function formatBytes(value: number): string {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const scaled = value / Math.pow(1024, i);
  return `${scaled.toFixed(scaled < 10 ? 2 : 1)} ${units[i]}`;
}

/**
 * Normalize various error types to a string message
 */
export function normalizeError(err: unknown): string {
  if (!err) return "Unknown error";
  if (typeof err === "string") return err;
  if (typeof err === "object" && "message" in err) {
    return String((err as { message: string }).message);
  }
  return JSON.stringify(err);
}

/**
 * Get icon emoji for container type
 */
export function typeIcon(type: string): string {
  const t = type.toLowerCase();
  if (t.includes("ad1")) return "📦";
  if (t.includes("e01") || t.includes("encase")) return "💿";
  if (t.includes("l01")) return "📋";
  if (t.includes("raw") || t.includes("dd")) return "💾";
  if (t.includes("ufed") || t.includes("ufd")) return "📱";
  if (t.includes("tar")) return "📚";
  if (t.includes("7z") || t.includes("7-zip")) return "📚";
  if (t.includes("zip")) return "🗜️";
  if (t.includes("rar")) return "📚";
  if (t.includes("gz") || t.includes("gzip")) return "📚";
  return "📄";
}

/**
 * Get CSS class for container type styling
 */
export function typeClass(type: string): string {
  const t = type.toLowerCase();
  if (t.includes("ad1")) return "type-ad1";
  if (t.includes("e01") || t.includes("encase")) return "type-e01";
  if (t.includes("l01")) return "type-l01";
  if (t.includes("raw") || t.includes("dd")) return "type-raw";
  if (t.includes("ufed") || t.includes("ufd")) return "type-ufed";
  if (t.includes("tar") || t.includes("7z") || t.includes("zip") || t.includes("rar") || t.includes("gz")) return "type-archive";
  return "type-other";
}

/**
 * Format hash timestamp for display (short date format)
 */
export function formatHashDate(timestamp: string): string {
  try {
    const d = new Date(timestamp);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: '2-digit' });
  } catch {
    return timestamp;
  }
}

/**
 * Format duration in seconds to human-readable string
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

/**
 * Create a debounced function that delays execution until after 
 * `delay` milliseconds have elapsed since the last call.
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

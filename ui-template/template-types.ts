// =============================================================================
// TEMPLATE TYPES - Generic TypeScript definitions for a file explorer app
// Adapt these types for your specific domain
// =============================================================================

// --- Discovered Item (Generic File/Entry) ---

export type DiscoveredItem = {
  /** Unique identifier (usually file path) */
  id: string;
  /** Display name */
  name: string;
  /** Full path */
  path: string;
  /** Category/type for filtering and styling */
  category: string;
  /** Size in bytes */
  size: number;
  /** Optional: Number of related items (e.g., segments, children) */
  itemCount?: number;
  /** Optional: Creation timestamp */
  created?: string;
  /** Optional: Modified timestamp */
  modified?: string;
  /** Optional: Additional metadata */
  metadata?: Record<string, unknown>;
};

// --- Tree Entry (For hierarchical file display) ---

export type TreeEntry = {
  path: string;
  isDirectory: boolean;
  size: number;
  /** Optional: Item type identifier */
  itemType?: number;
  /** Optional: Children for nested structures */
  children?: TreeEntry[];
};

// --- Item Info (Detailed information after loading) ---

export type ItemInfo = {
  /** Unique identifier matching DiscoveredItem.id */
  id: string;
  /** Primary data object (domain-specific) */
  data?: Record<string, unknown>;
  /** Optional: Embedded tree structure */
  tree?: TreeEntry[];
  /** Optional: Note or warning message */
  note?: string;
  /** Optional: Stored verification hashes */
  storedHashes?: StoredHash[];
  /** Optional: Related/associated files */
  relatedItems?: RelatedItem[];
};

// --- Related Item ---

export type RelatedItem = {
  name: string;
  type: string;
  size: number;
  path?: string;
};

// --- Status Types ---

export type StatusKind = "idle" | "working" | "ok" | "error";

export type ItemStatus = {
  status: StatusKind;
  progress: number;
  message?: string;
  error?: string;
  /** Optional: Sub-progress (e.g., chunks processed) */
  subProgress?: {
    current: number;
    total: number;
    label?: string;
  };
};

// --- Hash/Verification Types ---

export type StoredHash = {
  algorithm: string;
  hash: string;
  verified?: boolean | null;
  timestamp?: string | null;
  source?: string | null;
};

export type ComputedHash = {
  algorithm: string;
  hash: string;
  verified?: boolean | null;
  computedAt: Date;
};

export type HashHistoryEntry = {
  algorithm: string;
  hash: string;
  timestamp: Date;
  source: "computed" | "stored" | "verified";
  verified?: boolean | null;
  verifiedAgainst?: string | null;
};

// --- Algorithm Selection ---

export type Algorithm = {
  value: string;
  label: string;
  speed: "fast" | "medium" | "slow";
  category: string;
  description?: string;
};

// --- System Stats ---

export type SystemStats = {
  cpuUsage: number;
  memoryUsed: number;
  memoryTotal: number;
  memoryPercent: number;
  appCpuUsage: number;
  appMemory: number;
  appThreads: number;
  cpuCores: number;
};

// --- Category Configuration ---

export type CategoryConfig = {
  /** Category identifier */
  id: string;
  /** Display label */
  label: string;
  /** Emoji icon */
  icon: string;
  /** CSS class suffix (e.g., "primary", "success") */
  colorClass: string;
};

// --- Filter State ---

export type FilterState = {
  searchText: string;
  selectedCategories: string[];
  sortBy?: string;
  sortDirection?: "asc" | "desc";
};

// --- Base File Item (for hooks) ---

export type FileItem = {
  id: string;
  name: string;
  path: string;
  size: number;
  category: string;
  status?: ItemStatus;
};

// --- Selection State ---

export type SelectionState = {
  selected: Set<string>;
  active: string | null;
  hovered: string | null;
  focusedIndex: number;
};

// --- Batch Operation Result ---

export type BatchResult<T> = {
  id: string;
  success: boolean;
  result?: T;
  error?: string;
};

// --- Event Payload Types (for Tauri events) ---

export type ProgressEvent = {
  id: string;
  status: string;
  percent: number;
  itemsCompleted: number;
  itemsTotal: number;
  result?: unknown;
  error?: string;
};

export type ItemFoundEvent = {
  item: DiscoveredItem;
};

// --- Component Props Patterns ---

/** Standard callback prop types */
export type Callbacks = {
  onSelect: (item: DiscoveredItem) => void;
  onToggleSelection: (id: string) => void;
  onAction: (item: DiscoveredItem) => void;
  onHover: (id: string | null) => void;
  onFocus: (index: number) => void;
};

/** Standard state prop types */
export type StateProps = {
  items: DiscoveredItem[];
  filteredItems: DiscoveredItem[];
  selectedIds: Set<string>;
  activeItem: DiscoveredItem | null;
  hoveredId: string | null;
  focusedIndex: number;
  busy: boolean;
};

// --- Constants ---

export const DEFAULT_ALGORITHMS: Algorithm[] = [
  { value: "sha1", label: "SHA-1", speed: "medium", category: "standard" },
  { value: "sha256", label: "SHA-256", speed: "medium", category: "standard" },
  { value: "md5", label: "MD5", speed: "medium", category: "standard" },
  { value: "blake3", label: "BLAKE3 ⚡", speed: "fast", category: "modern" },
  { value: "xxh3", label: "XXH3 ⚡⚡", speed: "fast", category: "checksum" },
];

export const DEFAULT_CATEGORIES: CategoryConfig[] = [
  { id: "type-a", label: "Type A", icon: "📦", colorClass: "type-primary" },
  { id: "type-b", label: "Type B", icon: "💿", colorClass: "type-success" },
  { id: "type-c", label: "Type C", icon: "📋", colorClass: "type-warning" },
  { id: "type-d", label: "Type D", icon: "💾", colorClass: "type-purple" },
];

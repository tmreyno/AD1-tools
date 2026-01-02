// =============================================================================
// TEMPLATE HOOKS - State management patterns for SolidJS
// =============================================================================

import { createSignal, createEffect, onCleanup, createMemo, batch } from "solid-js";
import type { Accessor, Setter } from "solid-js";
import type { FileItem, FilterState, SystemStats } from "./template-types";
import { normalizeError } from "./template-utils";

// =============================================================================
// SELECTION MANAGER HOOK
// =============================================================================

export interface SelectionManager<T> {
  selected: Accessor<T | null>;
  setSelected: Setter<T | null>;
  isSelected: (item: T) => boolean;
  clear: () => void;
}

/**
 * Manage single-item selection state
 */
export function createSelectionManager<T>(
  compareFn: (a: T, b: T) => boolean = (a, b) => a === b
): SelectionManager<T> {
  const [selected, setSelected] = createSignal<T | null>(null);

  const isSelected = (item: T): boolean => {
    const sel = selected();
    return sel !== null && compareFn(sel, item);
  };

  const clear = () => setSelected(null);

  return { selected, setSelected, isSelected, clear };
}

// =============================================================================
// FILTER MANAGER HOOK
// =============================================================================

export interface FilterManager {
  filter: Accessor<FilterState>;
  setSearchText: (text: string) => void;
  toggleCategory: (category: string) => void;
  clearFilters: () => void;
  isFiltering: Accessor<boolean>;
}

/**
 * Manage filter/search state
 */
export function createFilterManager(
  availableCategories: string[]
): FilterManager {
  const [filter, setFilter] = createSignal<FilterState>({
    searchText: "",
    selectedCategories: [],
  });

  const setSearchText = (text: string) => {
    setFilter(prev => ({ ...prev, searchText: text }));
  };

  const toggleCategory = (category: string) => {
    setFilter(prev => {
      const cats = prev.selectedCategories;
      const newCats = cats.includes(category)
        ? cats.filter(c => c !== category)
        : [...cats, category];
      return { ...prev, selectedCategories: newCats };
    });
  };

  const clearFilters = () => {
    setFilter({ searchText: "", selectedCategories: [] });
  };

  const isFiltering = createMemo(() => {
    const f = filter();
    return f.searchText.length > 0 || f.selectedCategories.length > 0;
  });

  return { filter, setSearchText, toggleCategory, clearFilters, isFiltering };
}

// =============================================================================
// ITEM MANAGER HOOK
// =============================================================================

export interface ItemManager<T extends FileItem> {
  items: Accessor<T[]>;
  setItems: Setter<T[]>;
  filteredItems: Accessor<T[]>;
  status: Accessor<string>;
  setStatus: Setter<string>;
  isLoading: Accessor<boolean>;
  loadItems: (loadFn: () => Promise<T[]>) => Promise<void>;
  updateItem: (id: string, updates: Partial<T>) => void;
  clearItems: () => void;
}

/**
 * Manage a collection of items with filtering and loading state
 */
export function createItemManager<T extends FileItem>(
  filterFn: (items: T[], filter: FilterState) => T[]
): ItemManager<T> {
  const [items, setItems] = createSignal<T[]>([]);
  const [status, setStatus] = createSignal<string>("Ready");
  const [isLoading, setIsLoading] = createSignal(false);

  // Initialize filter manager
  const filterManager = createFilterManager([]);

  // Computed filtered items
  const filteredItems = createMemo(() => {
    return filterFn(items(), filterManager.filter());
  });

  // Load items from an async source
  const loadItems = async (loadFn: () => Promise<T[]>): Promise<void> => {
    setIsLoading(true);
    setStatus("Loading...");
    try {
      const loaded = await loadFn();
      batch(() => {
        setItems(loaded);
        setStatus(`Loaded ${loaded.length} items`);
      });
    } catch (err) {
      setStatus(`Error: ${normalizeError(err)}`);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  // Update a single item by ID
  const updateItem = (id: string, updates: Partial<T>): void => {
    setItems(prev => prev.map(item =>
      item.id === id ? { ...item, ...updates } : item
    ));
  };

  // Clear all items
  const clearItems = (): void => {
    batch(() => {
      setItems([]);
      setStatus("Ready");
    });
  };

  return {
    items,
    setItems,
    filteredItems,
    status,
    setStatus,
    isLoading,
    loadItems,
    updateItem,
    clearItems,
  };
}

// =============================================================================
// SYSTEM STATS HOOK
// =============================================================================

export interface SystemStatsManager {
  stats: Accessor<SystemStats | null>;
  startPolling: (pollFn: () => Promise<SystemStats>, intervalMs?: number) => void;
  stopPolling: () => void;
}

/**
 * Poll for system statistics (CPU, memory, etc.)
 */
export function createSystemStats(): SystemStatsManager {
  const [stats, setStats] = createSignal<SystemStats | null>(null);
  let intervalId: ReturnType<typeof setInterval> | null = null;

  const startPolling = (
    pollFn: () => Promise<SystemStats>,
    intervalMs: number = 2000
  ): void => {
    // Initial fetch
    pollFn().then(setStats).catch(console.error);

    // Set up interval
    intervalId = setInterval(async () => {
      try {
        const newStats = await pollFn();
        setStats(newStats);
      } catch (err) {
        console.error("Stats poll error:", err);
      }
    }, intervalMs);
  };

  const stopPolling = (): void => {
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
  };

  // Cleanup on component unmount
  onCleanup(stopPolling);

  return { stats, startPolling, stopPolling };
}

// =============================================================================
// ASYNC OPERATION MANAGER
// =============================================================================

export interface AsyncOpManager {
  isRunning: Accessor<boolean>;
  error: Accessor<string | null>;
  progress: Accessor<number | null>;
  run: <T>(operation: () => Promise<T>) => Promise<T>;
  cancel: () => void;
}

/**
 * Manage async operations with loading/error/progress state
 */
export function createAsyncOpManager(): AsyncOpManager {
  const [isRunning, setIsRunning] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [progress, setProgress] = createSignal<number | null>(null);
  let abortController: AbortController | null = null;

  const run = async <T>(operation: () => Promise<T>): Promise<T> => {
    abortController = new AbortController();
    batch(() => {
      setIsRunning(true);
      setError(null);
      setProgress(null);
    });

    try {
      const result = await operation();
      return result;
    } catch (err) {
      const msg = normalizeError(err);
      setError(msg);
      throw err;
    } finally {
      batch(() => {
        setIsRunning(false);
        setProgress(null);
      });
      abortController = null;
    }
  };

  const cancel = (): void => {
    if (abortController) {
      abortController.abort();
    }
  };

  return { isRunning, error, progress, run, cancel };
}

// =============================================================================
// LOCAL STORAGE PERSISTENCE
// =============================================================================

export interface PersistentState<T> {
  value: Accessor<T>;
  setValue: Setter<T>;
  clear: () => void;
}

/**
 * Create a signal that persists to localStorage
 */
export function createPersistentState<T>(
  key: string,
  defaultValue: T
): PersistentState<T> {
  // Load initial value from storage
  const stored = localStorage.getItem(key);
  const initial = stored ? JSON.parse(stored) : defaultValue;

  const [value, setValue] = createSignal<T>(initial);

  // Save to storage on change
  createEffect(() => {
    const current = value();
    localStorage.setItem(key, JSON.stringify(current));
  });

  const clear = (): void => {
    localStorage.removeItem(key);
    setValue(() => defaultValue);
  };

  return { value, setValue, clear };
}

// =============================================================================
// KEYBOARD SHORTCUTS
// =============================================================================

export interface KeyboardHandler {
  register: (key: string, handler: () => void, modifiers?: string[]) => void;
  unregister: (key: string) => void;
}

/**
 * Manage keyboard shortcuts
 */
export function createKeyboardHandler(): KeyboardHandler {
  const handlers = new Map<string, { handler: () => void; modifiers: string[] }>();

  const makeKey = (key: string, modifiers: string[]): string => {
    return [...modifiers.sort(), key].join("+");
  };

  const handleKeyDown = (e: KeyboardEvent): void => {
    const modifiers: string[] = [];
    if (e.ctrlKey || e.metaKey) modifiers.push("cmd");
    if (e.shiftKey) modifiers.push("shift");
    if (e.altKey) modifiers.push("alt");

    const fullKey = makeKey(e.key.toLowerCase(), modifiers);
    const entry = handlers.get(fullKey);
    if (entry) {
      e.preventDefault();
      entry.handler();
    }
  };

  // Set up listener
  if (typeof window !== "undefined") {
    window.addEventListener("keydown", handleKeyDown);
    onCleanup(() => window.removeEventListener("keydown", handleKeyDown));
  }

  const register = (
    key: string,
    handler: () => void,
    modifiers: string[] = []
  ): void => {
    const fullKey = makeKey(key.toLowerCase(), modifiers);
    handlers.set(fullKey, { handler, modifiers });
  };

  const unregister = (key: string): void => {
    handlers.delete(key);
  };

  return { register, unregister };
}

// =============================================================================
// TOAST NOTIFICATIONS
// =============================================================================

export interface Toast {
  id: string;
  message: string;
  type: "info" | "success" | "warning" | "error";
  duration: number;
}

export interface ToastManager {
  toasts: Accessor<Toast[]>;
  show: (message: string, type?: Toast["type"], duration?: number) => void;
  dismiss: (id: string) => void;
  clear: () => void;
}

/**
 * Manage toast notifications
 */
export function createToastManager(): ToastManager {
  const [toasts, setToasts] = createSignal<Toast[]>([]);

  const show = (
    message: string,
    type: Toast["type"] = "info",
    duration: number = 3000
  ): void => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const toast: Toast = { id, message, type, duration };

    setToasts(prev => [...prev, toast]);

    if (duration > 0) {
      setTimeout(() => dismiss(id), duration);
    }
  };

  const dismiss = (id: string): void => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  const clear = (): void => {
    setToasts([]);
  };

  return { toasts, show, dismiss, clear };
}

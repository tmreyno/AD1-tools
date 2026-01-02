// =============================================================================
// TEMPLATE COMPONENTS - SolidJS UI Component Patterns
// =============================================================================

import { Component, For, Show, createMemo, JSX } from "solid-js";
import type {
  DiscoveredItem,
  StatusKind,
  CategoryConfig,
  SystemStats,
  Algorithm,
} from "./template-types";
import {
  formatBytes,
  getCategoryIcon,
  getCategoryClass,
  getStatusIcon,
  formatCpuUsage,
  formatPercent,
} from "./template-utils";

// =============================================================================
// TOOLBAR COMPONENT
// =============================================================================

export interface ToolbarProps {
  currentPath: string;
  algorithms: Algorithm[];
  selectedAlgorithm: string;
  isProcessing: boolean;
  onBrowse: () => void;
  onAlgorithmChange: (value: string) => void;
  onProcess: () => void;
  onCancel: () => void;
  /** Optional: Additional action buttons */
  extraActions?: JSX.Element;
}

export const Toolbar: Component<ToolbarProps> = (props) => {
  return (
    <div class="toolbar">
      <div class="toolbar-group">
        <button
          class="btn btn-default"
          onClick={props.onBrowse}
          disabled={props.isProcessing}
          title="Select directory"
        >
          📂 Browse
        </button>
        <span class="toolbar-path" title={props.currentPath}>
          {props.currentPath || "No directory selected"}
        </span>
      </div>

      <div class="toolbar-group">
        <select
          class="toolbar-select"
          value={props.selectedAlgorithm}
          onChange={(e) => props.onAlgorithmChange(e.currentTarget.value)}
          disabled={props.isProcessing}
        >
          <For each={props.algorithms}>
            {(algo) => (
              <option value={algo.value}>
                {algo.label}
              </option>
            )}
          </For>
        </select>

        <Show
          when={!props.isProcessing}
          fallback={
            <button class="btn btn-warning" onClick={props.onCancel}>
              ⏹ Cancel
            </button>
          }
        >
          <button class="btn btn-primary" onClick={props.onProcess}>
            ▶ Process
          </button>
        </Show>

        {props.extraActions}
      </div>
    </div>
  );
};

// =============================================================================
// STATUS BAR COMPONENT
// =============================================================================

export interface StatusBarProps {
  status: string;
  itemCount: number;
  filteredCount: number;
  totalSize: number;
  stats: SystemStats | null;
}

export const StatusBar: Component<StatusBarProps> = (props) => {
  return (
    <div class="status-bar">
      <div class="status-section status-message">
        {props.status}
      </div>

      <div class="status-section status-counts">
        <Show when={props.filteredCount !== props.itemCount}>
          <span class="count-badge">{props.filteredCount}/{props.itemCount}</span>
        </Show>
        <Show when={props.filteredCount === props.itemCount}>
          <span class="count-badge">{props.itemCount}</span>
        </Show>
        <span class="size-badge">{formatBytes(props.totalSize)}</span>
      </div>

      <Show when={props.stats}>
        {(stats) => (
          <div class="status-section status-system">
            <span title="CPU Usage">
              ⚡ {formatCpuUsage(stats().cpuUsage, stats().cpuCores)}
            </span>
            <span title="Memory Usage">
              💾 {formatBytes(stats().memoryUsed)}/{formatBytes(stats().memoryTotal)}
            </span>
            <span title="Threads">
              🔀 {stats().appThreads}
            </span>
          </div>
        )}
      </Show>
    </div>
  );
};

// =============================================================================
// FILE PANEL (LIST) COMPONENT
// =============================================================================

export interface FilePanelProps<T extends DiscoveredItem> {
  items: T[];
  categories: CategoryConfig[];
  selectedId: string | null;
  searchText: string;
  selectedCategories: string[];
  onSelect: (item: T) => void;
  onSearchChange: (text: string) => void;
  onCategoryToggle: (category: string) => void;
  /** Optional: Custom row renderer */
  renderRow?: (item: T, isSelected: boolean) => JSX.Element;
}

export function FilePanel<T extends DiscoveredItem>(
  props: FilePanelProps<T>
): JSX.Element {
  const uniqueCategories = createMemo(() => {
    const cats = new Set(props.items.map((item) => item.category));
    return props.categories.filter((c) => cats.has(c.id));
  });

  return (
    <div class="file-panel">
      {/* Search bar */}
      <div class="search-bar">
        <input
          type="text"
          class="search-input"
          placeholder="Search..."
          value={props.searchText}
          onInput={(e) => props.onSearchChange(e.currentTarget.value)}
        />
      </div>

      {/* Category filters */}
      <div class="category-filters">
        <For each={uniqueCategories()}>
          {(cat) => (
            <button
              class={`filter-badge ${
                props.selectedCategories.includes(cat.id) ? "active" : ""
              }`}
              onClick={() => props.onCategoryToggle(cat.id)}
            >
              {cat.icon} {cat.label}
            </button>
          )}
        </For>
      </div>

      {/* File list */}
      <div class="file-list">
        <For each={props.items} fallback={<div class="empty-state">No items</div>}>
          {(item) => {
            const isSelected = () => props.selectedId === item.id;
            return (
              <Show
                when={props.renderRow}
                fallback={
                  <FileRow
                    item={item}
                    categories={props.categories}
                    isSelected={isSelected()}
                    onClick={() => props.onSelect(item)}
                  />
                }
              >
                {props.renderRow!(item, isSelected())}
              </Show>
            );
          }}
        </For>
      </div>
    </div>
  );
}

// =============================================================================
// FILE ROW COMPONENT
// =============================================================================

export interface FileRowProps {
  item: DiscoveredItem;
  categories: CategoryConfig[];
  isSelected: boolean;
  onClick: () => void;
  /** Optional: Status indicator */
  status?: StatusKind;
}

export const FileRow: Component<FileRowProps> = (props) => {
  const icon = () => getCategoryIcon(props.item.category, props.categories);
  const typeClass = () => getCategoryClass(props.item.category, props.categories);
  const statusIcon = () => props.status ? getStatusIcon(props.status) : null;

  return (
    <div
      class={`file-row ${props.isSelected ? "selected" : ""}`}
      onClick={props.onClick}
    >
      <span class={`type-badge ${typeClass()}`}>{icon()}</span>
      <span class="file-name">{props.item.name}</span>
      <span class="file-size">{formatBytes(props.item.size)}</span>
      <Show when={statusIcon()}>
        <span class={`status-indicator status-${props.status}`}>
          {statusIcon()}
        </span>
      </Show>
    </div>
  );
};

// =============================================================================
// DETAIL PANEL COMPONENT
// =============================================================================

export interface DetailPanelProps {
  title: string;
  subtitle?: string;
  children: JSX.Element;
  /** Optional: Header actions */
  actions?: JSX.Element;
  /** Optional: Empty state when no content */
  emptyState?: JSX.Element;
  isEmpty?: boolean;
}

export const DetailPanel: Component<DetailPanelProps> = (props) => {
  return (
    <div class="detail-panel">
      <Show
        when={!props.isEmpty}
        fallback={
          props.emptyState || (
            <div class="empty-state">
              <span class="empty-icon">📄</span>
              <span>Select an item to view details</span>
            </div>
          )
        }
      >
        <div class="detail-header">
          <div class="detail-title">
            <h2>{props.title}</h2>
            <Show when={props.subtitle}>
              <span class="detail-subtitle">{props.subtitle}</span>
            </Show>
          </div>
          <Show when={props.actions}>
            <div class="detail-actions">{props.actions}</div>
          </Show>
        </div>
        <div class="detail-content">{props.children}</div>
      </Show>
    </div>
  );
};

// =============================================================================
// INFO SECTION COMPONENT
// =============================================================================

export interface InfoItem {
  label: string;
  value: string | number | JSX.Element;
  highlight?: boolean;
  copyable?: boolean;
}

export interface InfoSectionProps {
  title?: string;
  items: InfoItem[];
  columns?: 1 | 2 | 3;
}

export const InfoSection: Component<InfoSectionProps> = (props) => {
  const cols = () => props.columns || 2;

  const handleCopy = async (value: string | number) => {
    try {
      await navigator.clipboard.writeText(String(value));
    } catch {
      console.error("Failed to copy to clipboard");
    }
  };

  return (
    <div class="info-section">
      <Show when={props.title}>
        <h3 class="section-title">{props.title}</h3>
      </Show>
      <div class={`info-grid cols-${cols()}`}>
        <For each={props.items}>
          {(item) => (
            <div class={`info-item ${item.highlight ? "highlight" : ""}`}>
              <span class="info-label">{item.label}</span>
              <span class="info-value">
                {typeof item.value === "object" ? item.value : String(item.value)}
                <Show when={item.copyable && typeof item.value !== "object"}>
                  <button
                    class="copy-btn"
                    onClick={() => handleCopy(item.value as string | number)}
                    title="Copy to clipboard"
                  >
                    📋
                  </button>
                </Show>
              </span>
            </div>
          )}
        </For>
      </div>
    </div>
  );
};

// =============================================================================
// PROGRESS BAR COMPONENT
// =============================================================================

export interface ProgressBarProps {
  progress: number;
  label?: string;
  variant?: "default" | "success" | "warning" | "error";
  showPercent?: boolean;
}

export const ProgressBar: Component<ProgressBarProps> = (props) => {
  const variant = () => props.variant || "default";
  const percent = () => Math.min(100, Math.max(0, props.progress));

  return (
    <div class={`progress-container progress-${variant()}`}>
      <Show when={props.label}>
        <span class="progress-label">{props.label}</span>
      </Show>
      <div class="progress-track">
        <div
          class="progress-fill"
          style={{ width: `${percent()}%` }}
        />
      </div>
      <Show when={props.showPercent !== false}>
        <span class="progress-percent">{percent().toFixed(0)}%</span>
      </Show>
    </div>
  );
};

// =============================================================================
// TOAST CONTAINER COMPONENT
// =============================================================================

export interface Toast {
  id: string;
  message: string;
  type: "info" | "success" | "warning" | "error";
}

export interface ToastContainerProps {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: Component<ToastContainerProps> = (props) => {
  return (
    <div class="toast-container">
      <For each={props.toasts}>
        {(toast) => (
          <div class={`toast toast-${toast.type}`}>
            <span class="toast-message">{toast.message}</span>
            <button
              class="toast-close"
              onClick={() => props.onDismiss(toast.id)}
            >
              ✕
            </button>
          </div>
        )}
      </For>
    </div>
  );
};

// =============================================================================
// MODAL COMPONENT
// =============================================================================

export interface ModalProps {
  isOpen: boolean;
  title: string;
  onClose: () => void;
  children: JSX.Element;
  actions?: JSX.Element;
  size?: "small" | "medium" | "large";
}

export const Modal: Component<ModalProps> = (props) => {
  const size = () => props.size || "medium";

  return (
    <Show when={props.isOpen}>
      <div class="modal-backdrop" onClick={props.onClose}>
        <div
          class={`modal modal-${size()}`}
          onClick={(e) => e.stopPropagation()}
        >
          <div class="modal-header">
            <h2 class="modal-title">{props.title}</h2>
            <button class="modal-close" onClick={props.onClose}>
              ✕
            </button>
          </div>
          <div class="modal-content">{props.children}</div>
          <Show when={props.actions}>
            <div class="modal-actions">{props.actions}</div>
          </Show>
        </div>
      </div>
    </Show>
  );
};

import { For, Show } from "solid-js";
import type { DiscoveredFile, ContainerInfo, HashHistoryEntry } from "../types";
import type { FileStatus, FileHashInfo } from "../hooks";
import { formatBytes, typeClass } from "../utils";
import { FileRow } from "./FileRow";

interface FilePanelProps {
  discoveredFiles: DiscoveredFile[];
  filteredFiles: DiscoveredFile[];
  selectedFiles: Set<string>;
  activeFile: DiscoveredFile | null;
  hoveredFile: string | null;
  focusedFileIndex: number;
  typeFilter: string | null;
  containerStats: Record<string, number>;
  totalSize: number;
  fileInfoMap: Map<string, ContainerInfo>;
  fileStatusMap: Map<string, FileStatus>;
  fileHashMap: Map<string, FileHashInfo>;
  hashHistory: Map<string, HashHistoryEntry[]>;
  busy: boolean;
  allFilesSelected: boolean;
  onToggleTypeFilter: (type: string) => void;
  onClearTypeFilter: () => void;
  onToggleSelectAll: () => void;
  onSelectFile: (file: DiscoveredFile) => void;
  onToggleFileSelection: (path: string) => void;
  onHashFile: (file: DiscoveredFile) => void;
  onHover: (path: string | null) => void;
  onFocus: (index: number) => void;
  onKeyDown: (e: KeyboardEvent) => void;
}

export function FilePanel(props: FilePanelProps) {
  return (
    <aside class="file-panel">
      <div class="panel-header">
        <h3>Evidence Files</h3>
        <Show when={props.discoveredFiles.length > 0}>
          <div class="panel-stats">
            <span class="stat">
              {props.filteredFiles.length}
              {props.typeFilter ? ` of ${props.discoveredFiles.length}` : ""} files
            </span>
            <span class="stat">{formatBytes(props.totalSize)}</span>
          </div>
        </Show>
      </div>
      
      {/* Type filter badges */}
      <Show when={Object.keys(props.containerStats).length > 0}>
        <div class="type-summary">
          {/* View All button - always shown first */}
          <button 
            class={`type-badge all ${!props.typeFilter ? "active" : ""}`} 
            title={`View all ${props.discoveredFiles.length} files`}
            onClick={props.onClearTypeFilter}
          >
            All: {props.discoveredFiles.length}
          </button>
          <For each={Object.entries(props.containerStats)}>
            {([type, count]) => (
              <button 
                class={`type-badge ${typeClass(type)} ${props.typeFilter === type ? "active" : ""}`} 
                title={`${count} ${type} file(s) - Click to filter${props.typeFilter === type ? " (click again to show all)" : ""}`}
                onClick={() => props.onToggleTypeFilter(type)}
              >
                {type}: {count}
              </button>
            )}
          </For>
        </div>
      </Show>
      
      {/* Select all row */}
      <Show when={props.filteredFiles.length > 0}>
        <div class="select-all-row">
          <label class="check-label">
            <input 
              type="checkbox" 
              checked={props.allFilesSelected} 
              onChange={props.onToggleSelectAll} 
            />
            <span>
              {props.allFilesSelected ? "Deselect All" : "Select All"}
              {props.typeFilter ? ` (${props.filteredFiles.length} shown)` : ""}
            </span>
          </label>
        </div>
      </Show>
      
      {/* File list */}
      <div class="file-list" tabIndex={0} onKeyDown={props.onKeyDown}>
        {/* Empty state - no files */}
        <Show when={props.discoveredFiles.length === 0}>
          <div class="empty-state">
            <span class="empty-icon">📂</span>
            <p>Open a directory to scan for evidence files</p>
            <p class="empty-hint">Supports AD1, E01, L01, Raw images</p>
          </div>
        </Show>
        
        {/* Empty state - filter has no results */}
        <Show when={props.discoveredFiles.length > 0 && props.filteredFiles.length === 0}>
          <div class="empty-state">
            <span class="empty-icon">🔍</span>
            <p>No {props.typeFilter} files found</p>
            <button class="clear-filter-btn" onClick={props.onClearTypeFilter}>
              Show all files
            </button>
          </div>
        </Show>
        
        {/* File rows */}
        <For each={props.filteredFiles}>
          {(file, index) => (
            <FileRow
              file={file}
              index={index()}
              isSelected={props.selectedFiles.has(file.path)}
              isActive={props.activeFile?.path === file.path}
              isFocused={props.focusedFileIndex === index()}
              isHovered={props.hoveredFile === file.path}
              fileStatus={props.fileStatusMap.get(file.path)}
              fileInfo={props.fileInfoMap.get(file.path)}
              fileHash={props.fileHashMap.get(file.path)}
              hashHistory={props.hashHistory.get(file.path) ?? []}
              busy={props.busy}
              onSelect={() => props.onSelectFile(file)}
              onToggleSelection={() => props.onToggleFileSelection(file.path)}
              onHash={() => props.onHashFile(file)}
              onMouseEnter={() => { props.onHover(file.path); props.onFocus(index()); }}
              onMouseLeave={() => props.onHover(null)}
            />
          )}
        </For>
      </div>
    </aside>
  );
}

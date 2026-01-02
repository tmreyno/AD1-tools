import { For, Show, createSignal, createEffect, onCleanup } from "solid-js";
import type { DiscoveredFile, ContainerInfo, TreeEntry, SegmentHashResult, HashHistoryEntry, HashAlgorithm, StoredHash } from "../types";
import type { FileStatus, FileHashInfo } from "../hooks";
import { DetailPanel } from "./DetailPanel";
import { HexViewer } from "./HexViewer";
import type { ParsedMetadata } from "./HexViewer";
import { TextViewer } from "./TextViewer";
import { typeIcon, typeClass } from "../utils";

export type TabViewMode = "info" | "hex" | "text";

export interface OpenTab {
  file: DiscoveredFile;
  id: string; // Use path as unique ID
  viewMode?: TabViewMode; // Default to "info"
}

interface TabbedDetailPanelProps {
  // Current active file from file manager
  activeFile: DiscoveredFile | null;
  // Maps to get info for any file
  fileInfoMap: Map<string, ContainerInfo>;
  fileStatusMap: Map<string, FileStatus>;
  fileHashMap: Map<string, FileHashInfo>;
  hashHistory: Map<string, HashHistoryEntry[]>;
  segmentResults: Map<string, SegmentHashResult[]>;
  // Tree data for active tab
  tree: TreeEntry[];
  filteredTree: TreeEntry[];
  treeFilter: string;
  onTreeFilterChange: (filter: string) => void;
  // Other props
  selectedHashAlgorithm: HashAlgorithm;
  segmentVerifyProgress: { segment: string; percent: number; completed: number; total: number } | null;
  storedHashesGetter: (info: ContainerInfo | undefined) => StoredHash[];
  busy: boolean;
  onVerifySegments: (file: DiscoveredFile) => void;
  onLoadInfo: (file: DiscoveredFile) => void;
  formatHashDate: (timestamp: string) => string;
  // Tab switching callback (to update file manager's active file, null = all tabs closed)
  onTabSelect: (file: DiscoveredFile | null) => void;
  // Callback to notify parent of tab changes (for project save)
  onTabsChange?: (tabs: OpenTab[]) => void;
  // Callback when metadata is loaded from hex viewer (for right panel)
  onMetadataLoaded?: (metadata: ParsedMetadata | null) => void;
}

export function TabbedDetailPanel(props: TabbedDetailPanelProps) {
  // Tab state
  const [openTabs, setOpenTabs] = createSignal<OpenTab[]>([]);
  const [activeTabId, setActiveTabId] = createSignal<string | null>(null);
  // Track recently closed tabs to prevent immediate re-opening
  const [recentlyClosed, setRecentlyClosed] = createSignal<Set<string>>(new Set());
  // Track view mode per tab (default to "info")
  const [tabViewModes, setTabViewModes] = createSignal<Map<string, TabViewMode>>(new Map());
  
  // Load tabs from localStorage on mount
  createEffect(() => {
    const savedTabs = localStorage.getItem('ffx-open-tabs');
    const savedActiveTab = localStorage.getItem('ffx-active-tab');
    if (savedTabs) {
      try {
        const parsed = JSON.parse(savedTabs) as OpenTab[];
        // Only restore tabs that have valid file structure
        if (Array.isArray(parsed) && parsed.every(t => t.file && t.id)) {
          setOpenTabs(parsed);
          if (savedActiveTab && parsed.some(t => t.id === savedActiveTab)) {
            setActiveTabId(savedActiveTab);
          }
        }
      } catch (e) {
        console.warn('Failed to restore tabs:', e);
      }
    }
  });
  
  // Save tabs to localStorage when they change
  createEffect(() => {
    const tabs = openTabs();
    const activeId = activeTabId();
    localStorage.setItem('ffx-open-tabs', JSON.stringify(tabs));
    if (activeId) {
      localStorage.setItem('ffx-active-tab', activeId);
    } else {
      // Clear active tab from storage when none selected
      localStorage.removeItem('ffx-active-tab');
    }
  });
  
  // Notify parent of tab changes (for project save)
  createEffect(() => {
    const tabs = openTabs();
    if (props.onTabsChange) {
      props.onTabsChange(tabs);
    }
  });
  
  // When activeFile changes from file manager, open it as a tab
  createEffect(() => {
    const file = props.activeFile;
    if (!file) return;
    
    // Don't re-open recently closed tabs (prevents immediate re-opening)
    if (recentlyClosed().has(file.path)) {
      return;
    }
    
    // Clear recently closed when opening a new/different file
    // This allows previously closed files to be re-opened on explicit click
    if (recentlyClosed().size > 0) {
      setRecentlyClosed(new Set<string>());
    }
    
    const tabs = openTabs();
    const existingTab = tabs.find(t => t.id === file.path);
    
    if (existingTab) {
      // Tab already exists, just activate it
      setActiveTabId(file.path);
    } else {
      // Add new tab
      const newTab: OpenTab = { file, id: file.path };
      setOpenTabs([...tabs, newTab]);
      setActiveTabId(file.path);
    }
  });
  
  // Get the currently active tab's file
  const activeTab = () => {
    const id = activeTabId();
    if (!id) return null;
    return openTabs().find(t => t.id === id) ?? null;
  };
  
  // Close a tab
  const closeTab = (tabId: string, e?: MouseEvent) => {
    e?.stopPropagation();
    e?.preventDefault();
    
    const tabs = openTabs();
    const tabIndex = tabs.findIndex(t => t.id === tabId);
    if (tabIndex === -1) return;
    
    // Mark as recently closed to prevent re-opening from activeFile prop
    setRecentlyClosed(prev => new Set([...prev, tabId]));
    
    const newTabs = tabs.filter(t => t.id !== tabId);
    setOpenTabs(newTabs);
    
    // If we closed the active tab, activate another
    if (activeTabId() === tabId) {
      if (newTabs.length > 0) {
        // Activate the tab to the left, or the first tab
        const newActiveIndex = Math.min(tabIndex, newTabs.length - 1);
        const newActiveTab = newTabs[newActiveIndex];
        setActiveTabId(newActiveTab.id);
        props.onTabSelect(newActiveTab.file);
      } else {
        setActiveTabId(null);
        // Notify parent that no tabs are open
        props.onTabSelect(null);
      }
    }
  };
  
  // Close all tabs except the given one
  const closeOtherTabs = (keepTabId: string) => {
    const tabs = openTabs();
    const keepTab = tabs.find(t => t.id === keepTabId);
    if (keepTab) {
      // Mark closed tabs as recently closed
      const closedIds = tabs.filter(t => t.id !== keepTabId).map(t => t.id);
      setRecentlyClosed(prev => new Set([...prev, ...closedIds]));
      
      setOpenTabs([keepTab]);
      setActiveTabId(keepTabId);
      props.onTabSelect(keepTab.file);
    }
  };
  
  // Close all tabs
  const closeAllTabs = () => {
    // Mark all tabs as recently closed
    const closedIds = openTabs().map(t => t.id);
    setRecentlyClosed(prev => new Set([...prev, ...closedIds]));
    
    setOpenTabs([]);
    setActiveTabId(null);
    // Notify parent that no tabs are open
    props.onTabSelect(null);
  };
  
  // Select a tab
  const selectTab = (tab: OpenTab) => {
    setActiveTabId(tab.id);
    props.onTabSelect(tab.file);
  };
  
  // Move tab to a new position
  const moveTab = (fromIndex: number, toIndex: number) => {
    if (fromIndex === toIndex) return;
    const tabs = [...openTabs()];
    const [movedTab] = tabs.splice(fromIndex, 1);
    tabs.splice(toIndex, 0, movedTab);
    setOpenTabs(tabs);
  };
  
  // Drag and drop state
  const [, setDraggedTabId] = createSignal<string | null>(null);
  const [dragOverTabId, setDragOverTabId] = createSignal<string | null>(null);
  
  // Store tab element refs for mouse-based drag detection
  const tabRefs = new Map<string, HTMLDivElement>();
  
  // Mouse-based drag and drop (more reliable in Tauri than native HTML5 drag)
  const setupDragHandlers = (el: HTMLDivElement, tabId: string) => {
    tabRefs.set(tabId, el);
    
    let isDragging = false;
    let startX = 0;
    let startY = 0;
    let currentTargetId: string | null = null; // Track target locally
    const DRAG_THRESHOLD = 5; // Pixels before drag starts
    
    // Prevent native drag behavior
    el.addEventListener('dragstart', (e) => e.preventDefault());
    
    const onMouseDown = (e: MouseEvent) => {
      // Middle click to close tab
      if (e.button === 1) {
        e.preventDefault();
        closeTab(tabId);
        return;
      }
      
      // Only left mouse button for drag, and not on buttons
      if (e.button !== 0) return;
      const target = e.target as HTMLElement;
      if (target.closest('.detail-tab-close') || target.closest('.tab-move-btn')) return;
      
      e.preventDefault(); // Prevent text selection
      startX = e.clientX;
      startY = e.clientY;
      
      const onMouseMove = (moveEvent: MouseEvent) => {
        moveEvent.preventDefault();
        const dx = Math.abs(moveEvent.clientX - startX);
        const dy = Math.abs(moveEvent.clientY - startY);
        
        if (!isDragging && (dx > DRAG_THRESHOLD || dy > DRAG_THRESHOLD)) {
          // Start dragging
          isDragging = true;
          setDraggedTabId(tabId);
          el.classList.add('dragging');
          document.body.style.cursor = 'grabbing';
        }
        
        if (isDragging) {
          // Find which tab we're over
          const tabs = openTabs();
          let foundTarget: string | null = null;
          
          for (const tab of tabs) {
            if (tab.id === tabId) continue;
            const tabEl = tabRefs.get(tab.id);
            if (tabEl) {
              const rect = tabEl.getBoundingClientRect();
              if (moveEvent.clientX >= rect.left && moveEvent.clientX <= rect.right &&
                  moveEvent.clientY >= rect.top && moveEvent.clientY <= rect.bottom) {
                foundTarget = tab.id;
                break;
              }
            }
          }
          
          currentTargetId = foundTarget;
          setDragOverTabId(foundTarget);
        }
      };
      
      const onMouseUp = (upEvent: MouseEvent) => {
        upEvent.preventDefault();
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
        
        if (isDragging) {
          if (currentTargetId && currentTargetId !== tabId) {
            const tabs = openTabs();
            const sourceIndex = tabs.findIndex(t => t.id === tabId);
            const targetIndex = tabs.findIndex(t => t.id === currentTargetId);
            
            if (sourceIndex !== -1 && targetIndex !== -1) {
              moveTab(sourceIndex, targetIndex);
            }
          }
          
          el.classList.remove('dragging');
          document.body.style.cursor = '';
          setDraggedTabId(null);
          setDragOverTabId(null);
          currentTargetId = null;
          isDragging = false;
        }
      };
      
      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
    };
    
    el.addEventListener('mousedown', onMouseDown);
    
    onCleanup(() => {
      el.removeEventListener('mousedown', onMouseDown);
      tabRefs.delete(tabId);
    });
  };
  
  // Simple button-based tab reordering (move left/right)
  const moveTabLeft = (tabId: string) => {
    const tabs = openTabs();
    const index = tabs.findIndex(t => t.id === tabId);
    if (index > 0) {
      moveTab(index, index - 1);
    }
  };
  
  const moveTabRight = (tabId: string) => {
    const tabs = openTabs();
    const index = tabs.findIndex(t => t.id === tabId);
    if (index < tabs.length - 1) {
      moveTab(index, index + 1);
    }
  };
  
  // Context menu for tab actions
  const [contextMenu, setContextMenu] = createSignal<{ x: number; y: number; tabId: string } | null>(null);
  
  const handleContextMenu = (tabId: string, e: MouseEvent) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, tabId });
  };
  
  // Close context menu when clicking elsewhere
  const handleDocumentClick = () => {
    setContextMenu(null);
  };
  
  createEffect(() => {
    if (contextMenu()) {
      document.addEventListener('click', handleDocumentClick);
      onCleanup(() => document.removeEventListener('click', handleDocumentClick));
    }
  });
  
  // Get data for active tab
  const activeTabFile = () => activeTab()?.file ?? null;
  const activeFileInfo = () => {
    const file = activeTabFile();
    return file ? props.fileInfoMap.get(file.path) : undefined;
  };
  const activeFileHash = () => {
    const file = activeTabFile();
    return file ? props.fileHashMap.get(file.path) : undefined;
  };
  const activeFileStatus = () => {
    const file = activeTabFile();
    return file ? props.fileStatusMap.get(file.path) : undefined;
  };
  const activeFileSegmentResults = () => {
    const file = activeTabFile();
    return file ? props.segmentResults.get(file.path) ?? [] : [];
  };
  const activeFileHashHistory = () => {
    const file = activeTabFile();
    return file ? props.hashHistory.get(file.path) ?? [] : [];
  };
  
  // Get current view mode for active tab
  const getActiveViewMode = (): TabViewMode => {
    const id = activeTabId();
    if (!id) return "info";
    return tabViewModes().get(id) ?? "info";
  };
  
  // Set view mode for active tab
  const setActiveViewMode = (mode: TabViewMode) => {
    const id = activeTabId();
    if (!id) return;
    setTabViewModes(prev => {
      const next = new Map(prev);
      next.set(id, mode);
      return next;
    });
  };
  
  return (
    <div class="tabbed-detail-panel">
      {/* Tab bar */}
      <Show when={openTabs().length > 0}>
        <div class="detail-tab-bar">
          <div class="detail-tabs">
            <For each={openTabs()}>
              {(tab, index) => (
                <div
                  ref={(el) => setupDragHandlers(el, tab.id)}
                  class={`detail-tab ${activeTabId() === tab.id ? 'active' : ''} ${dragOverTabId() === tab.id ? 'drag-over' : ''}`}
                  onClick={() => selectTab(tab)}
                  onContextMenu={(e) => handleContextMenu(tab.id, e)}
                  title={tab.file.path}
                >
                  <Show when={index() > 0}>
                    <button
                      class="tab-move-btn"
                      onClick={(e) => { e.stopPropagation(); moveTabLeft(tab.id); }}
                      title="Move tab left"
                    >
                      ◀
                    </button>
                  </Show>
                  <span class={`tab-icon ${typeClass(tab.file.container_type)}`}>
                    {typeIcon(tab.file.container_type)}
                  </span>
                  <span class="tab-label">{tab.file.filename}</span>
                  <Show when={index() < openTabs().length - 1}>
                    <button
                      class="tab-move-btn"
                      onClick={(e) => { e.stopPropagation(); moveTabRight(tab.id); }}
                      title="Move tab right"
                    >
                      ▶
                    </button>
                  </Show>
                  <button
                    class="detail-tab-close"
                    onClick={(e) => closeTab(tab.id, e)}
                    title="Close tab"
                  >
                    ×
                  </button>
                </div>
              )}
            </For>
          </div>
          <div class="tab-bar-actions">
            {/* View mode selector */}
            <div class="view-mode-selector">
              <button
                class={`view-mode-btn ${getActiveViewMode() === "info" ? "active" : ""}`}
                onClick={() => setActiveViewMode("info")}
                title="Container Info"
              >
                📋 Info
              </button>
              <button
                class={`view-mode-btn ${getActiveViewMode() === "hex" ? "active" : ""}`}
                onClick={() => setActiveViewMode("hex")}
                title="Hex Viewer"
              >
                🔢 Hex
              </button>
              <button
                class={`view-mode-btn ${getActiveViewMode() === "text" ? "active" : ""}`}
                onClick={() => setActiveViewMode("text")}
                title="Text Viewer"
              >
                📝 Text
              </button>
            </div>
            <button
              class="tab-action-btn"
              onClick={closeAllTabs}
              title="Close all tabs"
              disabled={openTabs().length === 0}
            >
              ✕ All
            </button>
          </div>
        </div>
      </Show>
      
      {/* Context menu */}
      <Show when={contextMenu()}>
        {(menu) => (
          <div 
            class="tab-context-menu"
            style={{ left: `${menu().x}px`, top: `${menu().y}px` }}
          >
            <button onClick={() => { moveTabLeft(menu().tabId); setContextMenu(null); }}>
              ← Move Left
            </button>
            <button onClick={() => { moveTabRight(menu().tabId); setContextMenu(null); }}>
              Move Right →
            </button>
            <hr />
            <button onClick={() => { closeTab(menu().tabId); setContextMenu(null); }}>
              Close
            </button>
            <button onClick={() => { closeOtherTabs(menu().tabId); setContextMenu(null); }}>
              Close Others
            </button>
            <button onClick={() => { closeAllTabs(); setContextMenu(null); }}>
              Close All
            </button>
          </div>
        )}
      </Show>
      
      {/* Content area - switches based on view mode */}
      <div class="detail-content-area">
        {/* Info view (default) */}
        <Show when={getActiveViewMode() === "info"}>
          <DetailPanel
            activeFile={activeTabFile()}
            fileInfo={activeFileInfo()}
            fileHash={activeFileHash()}
            fileStatus={activeFileStatus()}
            tree={props.tree}
            filteredTree={props.filteredTree}
            treeFilter={props.treeFilter}
            onTreeFilterChange={props.onTreeFilterChange}
            selectedHashAlgorithm={props.selectedHashAlgorithm}
            segmentResults={activeFileSegmentResults()}
            segmentVerifyProgress={props.segmentVerifyProgress}
            hashHistory={activeFileHashHistory()}
            storedHashes={props.storedHashesGetter(activeFileInfo())}
            busy={props.busy}
            onVerifySegments={() => activeTabFile() && props.onVerifySegments(activeTabFile()!)}
            onLoadInfo={() => activeTabFile() && props.onLoadInfo(activeTabFile()!)}
            formatHashDate={props.formatHashDate}
          />
        </Show>
        
        {/* Hex view */}
        <Show when={getActiveViewMode() === "hex" && activeTabFile()}>
          <HexViewer
            file={activeTabFile()!}
            onMetadataLoaded={props.onMetadataLoaded}
          />
        </Show>
        
        {/* Text view */}
        <Show when={getActiveViewMode() === "text" && activeTabFile()}>
          <TextViewer
            file={activeTabFile()!}
          />
        </Show>
      </div>
    </div>
  );
}

import { For, Show, createSignal, createEffect, onCleanup } from "solid-js";
import type { DiscoveredFile } from "../types";
import { typeIcon, typeClass } from "../utils";

export type TabViewMode = "info" | "hex" | "text";

export interface OpenTab {
  file: DiscoveredFile;
  id: string;
  viewMode?: TabViewMode;
}

interface TabBarProps {
  tabs: OpenTab[];
  activeTabId: string | null;
  viewMode: TabViewMode;
  onTabSelect: (tab: OpenTab) => void;
  onTabClose: (tabId: string, e?: MouseEvent) => void;
  onCloseOthers: (tabId: string) => void;
  onCloseAll: () => void;
  onTabMove: (fromIndex: number, toIndex: number) => void;
  onViewModeChange: (mode: TabViewMode) => void;
}

export function TabBar(props: TabBarProps) {
  // Drag and drop state
  const [dragOverTabId, setDragOverTabId] = createSignal<string | null>(null);
  
  // Context menu state
  const [contextMenu, setContextMenu] = createSignal<{ x: number; y: number; tabId: string } | null>(null);
  
  // Store tab element refs for mouse-based drag detection
  const tabRefs = new Map<string, HTMLDivElement>();
  
  // Mouse-based drag and drop (more reliable in Tauri than native HTML5 drag)
  const setupDragHandlers = (el: HTMLDivElement, tabId: string) => {
    tabRefs.set(tabId, el);
    
    let isDragging = false;
    let startX = 0;
    let startY = 0;
    let currentTargetId: string | null = null;
    const DRAG_THRESHOLD = 5;
    
    // Prevent native drag behavior
    el.addEventListener('dragstart', (e) => e.preventDefault());
    
    const onMouseDown = (e: MouseEvent) => {
      // Middle click to close tab
      if (e.button === 1) {
        e.preventDefault();
        props.onTabClose(tabId);
        return;
      }
      
      // Only left mouse button for drag, and not on buttons
      if (e.button !== 0) return;
      const target = e.target as HTMLElement;
      if (target.closest('.detail-tab-close') || target.closest('.tab-move-btn')) return;
      
      e.preventDefault();
      startX = e.clientX;
      startY = e.clientY;
      
      const onMouseMove = (moveEvent: MouseEvent) => {
        moveEvent.preventDefault();
        const dx = Math.abs(moveEvent.clientX - startX);
        const dy = Math.abs(moveEvent.clientY - startY);
        
        if (!isDragging && (dx > DRAG_THRESHOLD || dy > DRAG_THRESHOLD)) {
          isDragging = true;
          el.classList.add('dragging');
          document.body.style.cursor = 'grabbing';
        }
        
        if (isDragging) {
          // Find which tab we're over
          let foundTarget: string | null = null;
          
          for (const tab of props.tabs) {
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
            const sourceIndex = props.tabs.findIndex(t => t.id === tabId);
            const targetIndex = props.tabs.findIndex(t => t.id === currentTargetId);
            
            if (sourceIndex !== -1 && targetIndex !== -1) {
              props.onTabMove(sourceIndex, targetIndex);
            }
          }
          
          el.classList.remove('dragging');
          document.body.style.cursor = '';
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
  
  // Button-based tab reordering
  const moveTabLeft = (tabId: string) => {
    const index = props.tabs.findIndex(t => t.id === tabId);
    if (index > 0) {
      props.onTabMove(index, index - 1);
    }
  };
  
  const moveTabRight = (tabId: string) => {
    const index = props.tabs.findIndex(t => t.id === tabId);
    if (index < props.tabs.length - 1) {
      props.onTabMove(index, index + 1);
    }
  };
  
  // Context menu handlers
  const handleContextMenu = (tabId: string, e: MouseEvent) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, tabId });
  };
  
  const handleDocumentClick = () => {
    setContextMenu(null);
  };
  
  createEffect(() => {
    if (contextMenu()) {
      document.addEventListener('click', handleDocumentClick);
      onCleanup(() => document.removeEventListener('click', handleDocumentClick));
    }
  });
  
  return (
    <>
      <div class="detail-tab-bar">
        <div class="detail-tabs">
          <For each={props.tabs}>
            {(tab, index) => (
              <div
                ref={(el) => setupDragHandlers(el, tab.id)}
                class={`detail-tab ${props.activeTabId === tab.id ? 'active' : ''} ${dragOverTabId() === tab.id ? 'drag-over' : ''}`}
                onClick={() => props.onTabSelect(tab)}
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
                <Show when={index() < props.tabs.length - 1}>
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
                  onClick={(e) => { e.stopPropagation(); props.onTabClose(tab.id); }}
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
              class={`view-mode-btn ${props.viewMode === "info" ? "active" : ""}`}
              onClick={() => props.onViewModeChange("info")}
              title="Container Info"
            >
              📋 Info
            </button>
            <button
              class={`view-mode-btn ${props.viewMode === "hex" ? "active" : ""}`}
              onClick={() => props.onViewModeChange("hex")}
              title="Hex Viewer"
            >
              🔢 Hex
            </button>
            <button
              class={`view-mode-btn ${props.viewMode === "text" ? "active" : ""}`}
              onClick={() => props.onViewModeChange("text")}
              title="Text Viewer"
            >
              📝 Text
            </button>
          </div>
          <button
            class="tab-action-btn"
            onClick={props.onCloseAll}
            title="Close all tabs"
            disabled={props.tabs.length === 0}
          >
            ✕ All
          </button>
        </div>
      </div>
      
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
            <button onClick={() => { props.onTabClose(menu().tabId); setContextMenu(null); }}>
              Close
            </button>
            <button onClick={() => { props.onCloseOthers(menu().tabId); setContextMenu(null); }}>
              Close Others
            </button>
            <button onClick={() => { props.onCloseAll(); setContextMenu(null); }}>
              Close All
            </button>
          </div>
        )}
      </Show>
    </>
  );
}

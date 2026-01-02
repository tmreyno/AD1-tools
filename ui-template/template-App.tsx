// =============================================================================
// TEMPLATE APP - Main Application Shell Pattern
// =============================================================================

import { Component, createMemo, onMount, batch } from "solid-js";
import type { DiscoveredItem, CategoryConfig, Algorithm } from "./template-types";
import {
  createSelectionManager,
  createFilterManager,
  createItemManager,
  createSystemStats,
  createToastManager,
  createKeyboardHandler,
} from "./template-hooks";
import { calculateStats } from "./template-utils";
import {
  Toolbar,
  StatusBar,
  FilePanel,
  DetailPanel,
  ToastContainer,
} from "./template-components";
import "./template.css";

// =============================================================================
// APP CONFIGURATION
// =============================================================================

// Define your item categories
const CATEGORIES: CategoryConfig[] = [
  { id: "document", label: "Documents", icon: "📄", colorClass: "type-document" },
  { id: "image", label: "Images", icon: "🖼️", colorClass: "type-image" },
  { id: "video", label: "Videos", icon: "🎬", colorClass: "type-video" },
  { id: "audio", label: "Audio", icon: "🎵", colorClass: "type-audio" },
  { id: "archive", label: "Archives", icon: "📦", colorClass: "type-archive" },
  { id: "data", label: "Data", icon: "📊", colorClass: "type-data" },
  { id: "other", label: "Other", icon: "📁", colorClass: "type-other" },
];

// Define available processing algorithms
const ALGORITHMS: Algorithm[] = [
  { value: "md5", label: "MD5", speed: "fast", category: "hash" },
  { value: "sha1", label: "SHA-1", speed: "fast", category: "hash" },
  { value: "sha256", label: "SHA-256", speed: "medium", category: "hash" },
  { value: "sha512", label: "SHA-512", speed: "slow", category: "hash" },
];

// =============================================================================
// MAIN APP COMPONENT
// =============================================================================

const App: Component = () => {
  // --- State Management ---
  
  // Selection manager for single item selection
  const selection = createSelectionManager<DiscoveredItem>(
    (a, b) => a.id === b.id
  );
  
  // Filter manager for search and category filtering
  const filterManager = createFilterManager(CATEGORIES.map(c => c.id));
  
  // Item manager for the main list
  const itemManager = createItemManager<DiscoveredItem>((items, filter) => {
    return items.filter(item => {
      // Search text filter
      if (filter.searchText) {
        const search = filter.searchText.toLowerCase();
        if (!item.name.toLowerCase().includes(search)) {
          return false;
        }
      }
      // Category filter
      if (filter.selectedCategories.length > 0) {
        if (!filter.selectedCategories.includes(item.category)) {
          return false;
        }
      }
      return true;
    });
  });
  
  // System stats for status bar
  const systemStats = createSystemStats();
  
  // Toast notifications
  const toasts = createToastManager();
  
  // Keyboard shortcuts
  const keyboard = createKeyboardHandler();

  // --- Derived State ---
  
  const stats = createMemo(() => calculateStats(itemManager.items()));
  const selectedAlgorithm = () => ALGORITHMS[0].value;
  const currentPath = () => "/path/to/directory"; // Replace with actual state

  // --- Lifecycle ---
  
  onMount(() => {
    // Register keyboard shortcuts
    keyboard.register("escape", () => selection.clear());
    keyboard.register("f", () => {
      // Focus search input
      document.querySelector<HTMLInputElement>(".search-input")?.focus();
    }, ["cmd"]);
    
    // Start system stats polling (implement your own fetch function)
    // systemStats.startPolling(async () => {
    //   return await invoke("get_system_stats");
    // });
    
    // Initialize with demo data (replace with actual data loading)
    itemManager.setItems([
      { id: "1", name: "Document.pdf", category: "document", size: 1024000 },
      { id: "2", name: "Photo.jpg", category: "image", size: 2048000 },
      { id: "3", name: "Video.mp4", category: "video", size: 10240000 },
    ]);
  });

  // --- Event Handlers ---
  
  const handleBrowse = async () => {
    // Implement directory selection
    // const path = await open({ directory: true });
    // if (path) loadItems(path);
    toasts.show("Browse not implemented", "info");
  };

  const handleProcess = async () => {
    const selected = selection.selected();
    if (!selected) {
      toasts.show("No item selected", "warning");
      return;
    }
    // Implement processing logic
    toasts.show(`Processing ${selected.name}...`, "info");
  };

  const handleCancel = () => {
    // Implement cancel logic
    toasts.show("Operation cancelled", "info");
  };

  const handleSelect = (item: DiscoveredItem) => {
    selection.setSelected(item);
    itemManager.setStatus(`Selected: ${item.name}`);
  };

  // --- Render ---
  
  return (
    <div class="app">
      {/* Header */}
      <header class="header">
        <div class="logo">
          <span class="logo-icon">🔧</span>
          <span class="logo-text">Template App</span>
        </div>
        <div class="header-meta">
          <span class="version">v1.0.0</span>
        </div>
      </header>

      {/* Toolbar */}
      <Toolbar
        currentPath={currentPath()}
        algorithms={ALGORITHMS}
        selectedAlgorithm={selectedAlgorithm()}
        isProcessing={itemManager.isLoading()}
        onBrowse={handleBrowse}
        onAlgorithmChange={() => {}}
        onProcess={handleProcess}
        onCancel={handleCancel}
      />

      {/* Main Content */}
      <main class="main">
        {/* Left Panel - File List */}
        <FilePanel
          items={itemManager.filteredItems()}
          categories={CATEGORIES}
          selectedId={selection.selected()?.id ?? null}
          searchText={filterManager.filter().searchText}
          selectedCategories={filterManager.filter().selectedCategories}
          onSelect={handleSelect}
          onSearchChange={filterManager.setSearchText}
          onCategoryToggle={filterManager.toggleCategory}
        />

        {/* Right Panel - Details */}
        <DetailPanel
          title={selection.selected()?.name ?? "Details"}
          subtitle={selection.selected()?.category}
          isEmpty={!selection.selected()}
        >
          <div class="detail-content">
            {/* Add your detail content here */}
            <p>Selected item details would appear here.</p>
          </div>
        </DetailPanel>
      </main>

      {/* Status Bar */}
      <StatusBar
        status={itemManager.status()}
        itemCount={itemManager.items().length}
        filteredCount={itemManager.filteredItems().length}
        totalSize={stats().totalSize}
        stats={systemStats.stats()}
      />

      {/* Toast Notifications */}
      <ToastContainer
        toasts={toasts.toasts()}
        onDismiss={toasts.dismiss}
      />
    </div>
  );
};

export default App;

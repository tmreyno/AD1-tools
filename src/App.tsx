import { onMount, onCleanup, createSignal, createEffect, Show } from "solid-js";
import { useFileManager, useHashManager, useDatabase, useProject, useProcessedDatabases } from "./hooks";
import { Toolbar, StatusBar, FilePanel, DetailPanel, TreePanel, ProgressModal, MetadataPanel, ReportWizard } from "./components";
import ProcessedDatabasePanel from "./components/ProcessedDatabasePanel";
import ProcessedDetailPanel from "./components/ProcessedDetailPanel";
import type { ParsedMetadata, TabViewMode } from "./components";
import ffxLogo from "./assets/branding/ffx-logo-48.png";
import "./App.css";

function App() {
  // Initialize database hook
  const db = useDatabase();
  
  // Initialize file manager hook
  const fileManager = useFileManager();
  
  // Initialize hash manager hook (depends on file manager)
  const hashManager = useHashManager(fileManager);
  
  // Initialize project management hook
  const projectManager = useProject();
  
  // Initialize processed databases hook (for AXIOM, Cellebrite, etc.)
  const processedDbManager = useProcessedDatabases();
  
  // Track open tabs (from DetailPanel) for project save
  const [openTabs, setOpenTabs] = createSignal<Array<{ file: any; id: string }>>([]);
  
  // Track current view mode for right panel switching
  const [currentViewMode, setCurrentViewMode] = createSignal<TabViewMode>("info");
  
  // Track hex viewer metadata for MetadataPanel
  const [hexMetadata, setHexMetadata] = createSignal<ParsedMetadata | null>(null);
  
  // Clear metadata when active file changes
  createEffect(() => {
    const _file = fileManager.activeFile(); // Track active file
    // Clear hex metadata when file changes - new file needs fresh parsing
    setHexMetadata(null);
    // Also reset view mode to info when switching files
    setCurrentViewMode("info");
  });
  
  // Store hex viewer navigation function
  const [hexNavigator, setHexNavigator] = createSignal<((offset: number, size?: number) => void) | null>(null);
  
  // Wrapper to set navigator
  const handleHexNavigatorReady = (nav: (offset: number, size?: number) => void) => {
    setHexNavigator(() => nav);
  };
  
  // Request view mode change (for MetadataPanel navigation)
  const [requestViewMode, setRequestViewMode] = createSignal<"info" | "hex" | "text" | null>(null);
  
  // Report wizard state
  const [showReportWizard, setShowReportWizard] = createSignal(false);
  
  // Left panel tab state: "evidence" or "processed"
  const [leftPanelTab, setLeftPanelTab] = createSignal<"evidence" | "processed">("evidence");
  
  // Resizable panel state
  const [leftWidth, setLeftWidth] = createSignal(320);
  const [rightWidth, setRightWidth] = createSignal(280);
  const [leftCollapsed, setLeftCollapsed] = createSignal(false);
  const [rightCollapsed, setRightCollapsed] = createSignal(true); // Start collapsed
  const [dragging, setDragging] = createSignal<'left' | 'right' | null>(null);
  
  // Responsive: track window width for compact toolbar
  const [windowWidth, setWindowWidth] = createSignal(window.innerWidth);
  const isCompact = () => windowWidth() < 900;
  
  // Initialize/update database session when scan directory changes (debounced)
  let sessionInitTimer: ReturnType<typeof setTimeout> | null = null;
  createEffect(() => {
    const scanDir = fileManager.scanDir();
    if (scanDir && scanDir.length > 0) {
      // Debounce to avoid multiple rapid inits
      if (sessionInitTimer) clearTimeout(sessionInitTimer);
      sessionInitTimer = setTimeout(() => {
        db.initSession(scanDir)
          .then(() => console.log(`Database session initialized for: ${scanDir}`))
          .catch((e) => console.warn("Failed to initialize database session:", e));
      }, 500);
    }
  });
  
  // Save discovered files to database when they change (batched, debounced)
  let fileSaveTimer: ReturnType<typeof setTimeout> | null = null;
  createEffect(() => {
    const files = fileManager.discoveredFiles();
    const session = db.session();
    if (!session || files.length === 0) return;
    
    // Debounce to batch multiple rapid file additions
    if (fileSaveTimer) clearTimeout(fileSaveTimer);
    fileSaveTimer = setTimeout(() => {
      // Save files in background - don't await in effect
      Promise.all(
        files.map(file => 
          db.saveFile(file).catch(e => 
            console.warn(`Failed to save file: ${file.path}`, e)
          )
        )
      ).then(() => {
        console.log(`Saved ${files.length} files to database`);
      });
    }, 1000); // Wait 1 second after last file change
  });

  // Mouse handlers for resizing
  const handleMouseMove = (e: MouseEvent) => {
    const drag = dragging();
    if (!drag) return;
    
    if (drag === 'left') {
      const rawWidth = e.clientX;
      if (rawWidth < 150) {
        setLeftCollapsed(true);
      } else {
        setLeftCollapsed(false);
        setLeftWidth(Math.min(600, rawWidth));
      }
    } else if (drag === 'right') {
      const rawWidth = window.innerWidth - e.clientX;
      if (rawWidth < 150) {
        setRightCollapsed(true);
      } else {
        setRightCollapsed(false);
        setRightWidth(Math.min(500, rawWidth));
      }
    }
  };

  const handleMouseUp = () => {
    setDragging(null);
  };

  // Store cleanup function reference
  let cleanupSystemStats: (() => void) | undefined;
  
  // Handle window resize for responsive toolbar
  const handleResize = () => setWindowWidth(window.innerWidth);

  onMount(async () => {
    const unlisten = await fileManager.setupSystemStatsListener();
    cleanupSystemStats = unlisten;
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    window.addEventListener('resize', handleResize);
    
    // Set up auto-save callback with current state
    projectManager.setAutoSaveCallback(async () => {
      const scanDir = fileManager.scanDir();
      if (!scanDir) return;
      
      await projectManager.saveProject({
        rootPath: scanDir,
        openTabs: openTabs(),
        activeTabPath: fileManager.activeFile()?.path || null,
        hashHistory: hashManager.hashHistory(),
        processedDatabases: processedDbManager.databases(),
        selectedProcessedDb: processedDbManager.selectedDatabase(),
        uiState: {
          left_panel_width: leftWidth(),
          right_panel_width: rightWidth(),
          left_panel_collapsed: leftCollapsed(),
          right_panel_collapsed: rightCollapsed(),
          left_panel_tab: leftPanelTab(),
          detail_view_mode: currentViewMode(),
        },
      });
    });
    
    // Try to restore last session (non-blocking)
    db.restoreLastSession()
      .then((lastSession) => {
        if (lastSession) {
          // Only restore scan directory, don't trigger a scan
          fileManager.setScanDir(lastSession.root_path);
          console.log(`Restored session: ${lastSession.name} (${lastSession.root_path})`);
        }
      })
      .catch((e) => console.warn("Failed to restore last session:", e));
  });

  onCleanup(() => {
    cleanupSystemStats?.();
    if (sessionInitTimer) clearTimeout(sessionInitTimer);
    if (fileSaveTimer) clearTimeout(fileSaveTimer);
    window.removeEventListener('mousemove', handleMouseMove);
    window.removeEventListener('mouseup', handleMouseUp);
    window.removeEventListener('resize', handleResize);
    
    // Stop auto-save on cleanup
    projectManager.stopAutoSave();
  });

  // Helper for TreePanel - gets info for active file
  const activeFileInfo = () => {
    const active = fileManager.activeFile();
    if (!active) return undefined;
    return fileManager.fileInfoMap().get(active.path);
  };

  return (
    <div class="app-root" classList={{ 'is-resizing': dragging() !== null }}>
      {/* Header */}
      <header class="app-header">
        <div class="brand">
          <img src={ffxLogo} alt="CORE-FFX Logo" class="brand-logo" />
          <span class="brand-name">CORE</span>
          <span class="brand-tag">Forensic File Xplorer</span>
        </div>
        <div class="header-status">
          <span class={`status-dot ${fileManager.statusKind()}`} />
          <span class="status-text">{fileManager.statusMessage()}</span>
        </div>
      </header>

      {/* Toolbar */}
      <Toolbar
        scanDir={fileManager.scanDir()}
        onScanDirChange={(dir) => fileManager.setScanDir(dir)}
        recursiveScan={fileManager.recursiveScan()}
        onRecursiveScanChange={(recursive) => fileManager.setRecursiveScan(recursive)}
        selectedHashAlgorithm={hashManager.selectedHashAlgorithm()}
        onHashAlgorithmChange={(alg) => hashManager.setSelectedHashAlgorithm(alg)}
        selectedCount={fileManager.selectedCount()}
        discoveredCount={fileManager.discoveredFiles().length}
        busy={fileManager.busy()}
        onBrowse={() => fileManager.browseScanDir()}
        onScan={() => fileManager.scanForFiles()}
        onHashSelected={() => hashManager.hashSelectedFiles()}
        onLoadAll={() => fileManager.loadAllInfo()}
        // Project management
        projectPath={projectManager.projectPath()}
        projectModified={projectManager.modified()}
        onSaveProject={() => {
          const scanDir = fileManager.scanDir();
          if (scanDir) {
            const activeTabPath = fileManager.activeFile()?.path || null;
            projectManager.saveProject({
              rootPath: scanDir,
              openTabs: openTabs(),
              activeTabPath,
              hashHistory: hashManager.hashHistory(),
              processedDatabases: processedDbManager.databases(),
              selectedProcessedDb: processedDbManager.selectedDatabase(),
              uiState: {
                left_panel_width: leftWidth(),
                right_panel_width: rightWidth(),
                left_panel_collapsed: leftCollapsed(),
                right_panel_collapsed: rightCollapsed(),
                left_panel_tab: leftPanelTab(),
                detail_view_mode: currentViewMode(),
              },
            });
          }
        }}
        onLoadProject={async () => {
          const result = await projectManager.loadProject();
          if (result.project) {
            // Restore scan directory
            fileManager.setScanDir(result.project.root_path);
            
            // Restore UI state
            if (result.project.ui_state) {
              const ui = result.project.ui_state;
              if (ui.left_panel_width) setLeftWidth(ui.left_panel_width);
              if (ui.right_panel_width) setRightWidth(ui.right_panel_width);
              if (ui.left_panel_collapsed !== undefined) setLeftCollapsed(ui.left_panel_collapsed);
              if (ui.right_panel_collapsed !== undefined) setRightCollapsed(ui.right_panel_collapsed);
              if (ui.left_panel_tab) setLeftPanelTab(ui.left_panel_tab);
              if (ui.detail_view_mode) setCurrentViewMode(ui.detail_view_mode as TabViewMode);
            }
            
            // Log activity
            projectManager.logActivity('project', 'open', `Opened project: ${result.project.name}`);
            
            console.log("Project loaded:", result.project.name);
          }
        }}
        // Report generation
        onGenerateReport={() => setShowReportWizard(true)}
        // Responsive mode
        compact={isCompact()}
      />

      {/* Main Content Area */}
      <main class="app-main">
        {/* Left Panel */}
        <Show when={!leftCollapsed()}>
          <aside class="left-panel" style={{ width: `${leftWidth()}px` }}>
            {/* Panel Tab Switcher */}
            <div class="left-panel-tabs">
              <button 
                class="panel-tab" 
                classList={{ active: leftPanelTab() === "evidence" }}
                onClick={() => setLeftPanelTab("evidence")}
                title="Evidence Containers (E01, AD1, L01, etc.)"
              >
                📦 Evidence
              </button>
              <button 
                class="panel-tab" 
                classList={{ active: leftPanelTab() === "processed" }}
                onClick={() => setLeftPanelTab("processed")}
                title="Processed Databases (AXIOM, Cellebrite PA, etc.)"
              >
                📊 Processed
              </button>
            </div>
            
            {/* Tab Content */}
            <Show when={leftPanelTab() === "evidence"} fallback={
              <ProcessedDatabasePanel 
                manager={processedDbManager}
                onSelectDatabase={(db) => {
                  processedDbManager.selectDatabase(db);
                  // Clear active forensic file when switching to processed view
                  fileManager.setActiveFile(null);
                }}
                onSelectArtifact={(db, artifact) => console.log('Selected artifact:', artifact.name, 'from', db.path)}
              />
            }>
              <FilePanel
              discoveredFiles={fileManager.discoveredFiles()}
              filteredFiles={fileManager.filteredFiles()}
              selectedFiles={fileManager.selectedFiles()}
              activeFile={fileManager.activeFile()}
              hoveredFile={fileManager.hoveredFile()}
              focusedFileIndex={fileManager.focusedFileIndex()}
              typeFilter={fileManager.typeFilter()}
              containerStats={fileManager.containerStats()}
              totalSize={fileManager.totalSize()}
              fileInfoMap={fileManager.fileInfoMap()}
              fileStatusMap={fileManager.fileStatusMap()}
              fileHashMap={hashManager.fileHashMap()}
              hashHistory={hashManager.hashHistory()}
              busy={fileManager.busy()}
              allFilesSelected={fileManager.allFilesSelected()}
              onToggleTypeFilter={(type) => fileManager.toggleTypeFilter(type)}
              onClearTypeFilter={() => fileManager.setTypeFilter(null)}
              onToggleSelectAll={() => fileManager.toggleSelectAll()}
              onSelectFile={(file) => fileManager.selectAndViewFile(file)}
              onToggleFileSelection={(path) => fileManager.toggleFileSelection(path)}
              onHashFile={(file) => hashManager.hashSingleFile(file)}
              onHover={(path) => fileManager.setHoveredFile(path)}
              onFocus={(index) => fileManager.setFocusedFileIndex(index)}
              onKeyDown={(e) => fileManager.handleFileListKeyDown(
                e,
                (file) => fileManager.selectAndViewFile(file),
                (path) => fileManager.toggleFileSelection(path)
              )}
            />
            </Show>
          </aside>
        </Show>

        {/* Left Resize Handle */}
        <div 
          class="resize-handle" 
          classList={{ collapsed: leftCollapsed() }}
          onMouseDown={() => !leftCollapsed() && setDragging('left')}
          onClick={() => leftCollapsed() && setLeftCollapsed(false)}
          onDblClick={() => setLeftCollapsed(!leftCollapsed())}
        >
          <Show when={leftCollapsed()}>
            <span class="expand-icon">›</span>
          </Show>
        </div>

        {/* Center Panel */}
        <section class="center-panel">
          {/* Show ProcessedDetailPanel when viewing processed databases */}
          <Show when={leftPanelTab() === "processed" && processedDbManager.selectedDatabase()} fallback={
            <DetailPanel
              activeFile={fileManager.activeFile()}
              fileInfoMap={fileManager.fileInfoMap}
              fileStatusMap={fileManager.fileStatusMap}
              fileHashMap={hashManager.fileHashMap}
              hashHistory={hashManager.hashHistory}
              segmentResults={hashManager.segmentResults}
              tree={fileManager.tree()}
              filteredTree={fileManager.filteredTree()}
              treeFilter={fileManager.treeFilter()}
              onTreeFilterChange={(filter: string) => fileManager.setTreeFilter(filter)}
              selectedHashAlgorithm={hashManager.selectedHashAlgorithm()}
              segmentVerifyProgress={hashManager.segmentVerifyProgress()}
              storedHashesGetter={hashManager.getAllStoredHashesSorted}
              busy={fileManager.busy()}
              onVerifySegments={(file) => hashManager.verifySegments(file)}
              onLoadInfo={(file) => fileManager.loadFileInfo(file, true)}
              formatHashDate={hashManager.formatHashDate}
              onTabSelect={(file) => fileManager.setActiveFile(file)}
              onTabsChange={(tabs) => setOpenTabs(tabs)}
              onMetadataLoaded={setHexMetadata}
              onViewModeChange={setCurrentViewMode}
              onHexNavigatorReady={handleHexNavigatorReady}
              requestViewMode={requestViewMode()}
              onViewModeRequestHandled={() => setRequestViewMode(null)}
            />
          }>
            <ProcessedDetailPanel
              database={processedDbManager.selectedDatabase()}
              caseInfo={processedDbManager.selectedCaseInfo()}
              categories={processedDbManager.selectedCategories()}
              loading={processedDbManager.isSelectedLoading()}
              detailView={processedDbManager.detailView()}
              onDetailViewChange={(view) => processedDbManager.setDetailView(view)}
            />
          </Show>
        </section>

        {/* Right Resize Handle */}
        <div 
          class="resize-handle" 
          classList={{ collapsed: rightCollapsed() }}
          onMouseDown={() => !rightCollapsed() && setDragging('right')}
          onClick={() => rightCollapsed() && setRightCollapsed(false)}
          onDblClick={() => setRightCollapsed(!rightCollapsed())}
        >
          <Show when={rightCollapsed()}>
            <span class="expand-icon">‹</span>
          </Show>
        </div>

        {/* Right Panel - switches based on view mode */}
        <Show when={!rightCollapsed()}>
          <aside class="right-panel" style={{ width: `${rightWidth()}px` }}>
            <Show when={currentViewMode() === "hex"} fallback={<TreePanel info={activeFileInfo()} />}>
              <MetadataPanel 
                metadata={hexMetadata()}
                containerInfo={activeFileInfo()}
                fileInfo={fileManager.activeFile() ? {
                  path: fileManager.activeFile()!.path,
                  filename: fileManager.activeFile()!.filename,
                  size: fileManager.activeFile()!.size,
                  created: fileManager.activeFile()!.created,
                  modified: fileManager.activeFile()!.modified,
                  container_type: fileManager.activeFile()!.container_type,
                  segment_count: fileManager.activeFile()!.segment_count
                } : null}
                onRegionClick={(offset) => {
                  // Request DetailPanel to switch to hex view mode
                  setRequestViewMode("hex");
                  
                  // Retry function to wait for HexViewer to mount
                  const tryNavigate = (attempts: number) => {
                    const nav = hexNavigator();
                    if (nav) {
                      nav(offset);
                    } else if (attempts > 0) {
                      // HexViewer not mounted yet, retry
                      setTimeout(() => tryNavigate(attempts - 1), 100);
                    }
                  };
                  
                  // Start retrying after a small delay for view mode to switch
                  setTimeout(() => tryNavigate(5), 100);
                }}
              />
            </Show>
          </aside>
        </Show>
      </main>

      {/* Status bar */}
      <StatusBar
        statusKind={fileManager.statusKind()}
        statusMessage={fileManager.statusMessage()}
        discoveredCount={fileManager.discoveredFiles().length}
        totalSize={fileManager.totalSize()}
        selectedCount={fileManager.selectedCount()}
        systemStats={fileManager.systemStats()}
      />
      
      {/* Progress Modal */}
      <ProgressModal
        show={fileManager.loadProgress().show}
        title={fileManager.loadProgress().title}
        message={fileManager.loadProgress().message}
        current={fileManager.loadProgress().current}
        total={fileManager.loadProgress().total}
        onCancel={fileManager.cancelLoading}
      />
      
      {/* Report Wizard Modal */}
      <Show when={showReportWizard()}>
        <ReportWizard
          files={fileManager.discoveredFiles()}
          fileInfoMap={fileManager.fileInfoMap()}
          fileHashMap={hashManager.fileHashMap()}
          onClose={() => setShowReportWizard(false)}
          onGenerated={(path, format) => {
            console.log(`Report generated: ${path} (${format})`);
            fileManager.setOk(`Report saved to ${path}`);
          }}
        />
      </Show>
    </div>
  );
}

export default App;

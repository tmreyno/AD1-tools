import { onMount, onCleanup, createSignal, createEffect, Show } from "solid-js";
import { useFileManager, useHashManager, useDatabase, useProject } from "./hooks";
import { Toolbar, StatusBar, FilePanel, TabbedDetailPanel, TreePanel, ProgressModal } from "./components";
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
  
  // Track open tabs (from TabbedDetailPanel) for project save
  const [openTabs, setOpenTabs] = createSignal<Array<{ file: any; id: string }>>([]);
  
  // Resizable panel state
  const [leftWidth, setLeftWidth] = createSignal(
    parseInt(localStorage.getItem('ffx-left-width') ?? '320', 10)
  );
  const [rightWidth, setRightWidth] = createSignal(
    parseInt(localStorage.getItem('ffx-right-width') ?? '280', 10)
  );
  const [leftCollapsed, setLeftCollapsed] = createSignal(false);
  const [rightCollapsed, setRightCollapsed] = createSignal(false);
  const [dragging, setDragging] = createSignal<'left' | 'right' | null>(null);
  
  // Save widths to localStorage
  createEffect(() => {
    if (!leftCollapsed()) localStorage.setItem('ffx-left-width', leftWidth().toString());
  });
  createEffect(() => {
    if (!rightCollapsed()) localStorage.setItem('ffx-right-width', rightWidth().toString());
  });
  
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

  onMount(async () => {
    const unlisten = await fileManager.setupSystemStatsListener();
    cleanupSystemStats = unlisten;
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    
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
  });

  // Helper for TreePanel - gets info for active file
  const activeFileInfo = () => fileManager.activeFile() ? fileManager.fileInfoMap().get(fileManager.activeFile()!.path) : undefined;

  return (
    <div class="app-root" classList={{ 'is-resizing': dragging() !== null }}>
      {/* Header */}
      <header class="app-header">
        <div class="brand">
          <span class="brand-icon">🔬</span>
          <span class="brand-name">FFX</span>
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
        onHashAll={() => hashManager.hashAllFiles()}
        onLoadAll={() => fileManager.loadAllInfo()}
        // Project management
        projectPath={projectManager.projectPath()}
        projectModified={projectManager.modified()}
        onSaveProject={() => {
          const scanDir = fileManager.scanDir();
          if (scanDir) {
            const activeTabPath = fileManager.activeFile()?.path || null;
            projectManager.saveProject(
              scanDir,
              openTabs(),
              activeTabPath,
              hashManager.hashHistory()
            );
          }
        }}
        onLoadProject={async () => {
          const result = await projectManager.loadProject();
          if (result.project) {
            // Restore scan directory
            fileManager.setScanDir(result.project.root_path);
            // Could also restore tabs, but that requires more wiring
            console.log("Project loaded:", result.project.name);
          }
        }}
      />

      {/* Main Content Area */}
      <main class="app-main">
        {/* Left Panel */}
        <Show when={!leftCollapsed()}>
          <aside class="left-panel" style={{ width: `${leftWidth()}px` }}>
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
          <TabbedDetailPanel
            activeFile={fileManager.activeFile()}
            fileInfoMap={fileManager.fileInfoMap()}
            fileStatusMap={fileManager.fileStatusMap()}
            fileHashMap={hashManager.fileHashMap()}
            hashHistory={hashManager.hashHistory()}
            segmentResults={hashManager.segmentResults()}
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
          />
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

        {/* Right Panel */}
        <Show when={!rightCollapsed()}>
          <aside class="right-panel" style={{ width: `${rightWidth()}px` }}>
            <TreePanel info={activeFileInfo()} />
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
    </div>
  );
}

export default App;

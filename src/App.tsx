import { onMount, onCleanup } from "solid-js";
import { useFileManager, useHashManager } from "./hooks";
import { Toolbar, StatusBar, FilePanel, DetailPanel } from "./components";
import "./App.css";

function App() {
  // Initialize file manager hook
  const fileManager = useFileManager();
  
  // Initialize hash manager hook (depends on file manager)
  const hashManager = useHashManager(fileManager);

  // Setup system stats listener on mount
  onMount(async () => {
    const unlisten = await fileManager.setupSystemStatsListener();
    onCleanup(() => {
      unlisten();
    });
  });

  // Get active file's info, hash, status, etc.
  const activeFileInfo = () => fileManager.activeFile() ? fileManager.fileInfoMap().get(fileManager.activeFile()!.path) : undefined;
  const activeFileHash = () => fileManager.activeFile() ? hashManager.fileHashMap().get(fileManager.activeFile()!.path) : undefined;
  const activeFileStatus = () => fileManager.activeFile() ? fileManager.fileStatusMap().get(fileManager.activeFile()!.path) : undefined;
  const activeFileSegmentResults = () => fileManager.activeFile() ? hashManager.segmentResults().get(fileManager.activeFile()!.path) ?? [] : [];
  const activeFileHashHistory = () => fileManager.activeFile() ? hashManager.hashHistory().get(fileManager.activeFile()!.path) ?? [] : [];
  const activeFileStoredHashes = () => hashManager.getAllStoredHashesSorted(activeFileInfo());

  return (
    <div class="app compact">
      {/* Header */}
      <header class="header-bar">
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
      />

      {/* Main layout */}
      <div class="main-layout">
        {/* File panel (sidebar) */}
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

        {/* Detail panel (main content) */}
        <DetailPanel
          activeFile={fileManager.activeFile()}
          fileInfo={activeFileInfo()}
          fileHash={activeFileHash()}
          fileStatus={activeFileStatus()}
          tree={fileManager.tree()}
          filteredTree={fileManager.filteredTree()}
          treeFilter={fileManager.treeFilter()}
          onTreeFilterChange={(filter) => fileManager.setTreeFilter(filter)}
          selectedHashAlgorithm={hashManager.selectedHashAlgorithm()}
          segmentResults={activeFileSegmentResults()}
          segmentVerifyProgress={hashManager.segmentVerifyProgress()}
          hashHistory={activeFileHashHistory()}
          storedHashes={activeFileStoredHashes()}
          busy={fileManager.busy()}
          onVerifySegments={() => fileManager.activeFile() && hashManager.verifySegments(fileManager.activeFile()!)}
          onLoadInfo={() => fileManager.activeFile() && fileManager.loadFileInfo(fileManager.activeFile()!, true)}
          formatHashDate={hashManager.formatHashDate}
        />
      </div>

      {/* Status bar */}
      <StatusBar
        statusKind={fileManager.statusKind()}
        statusMessage={fileManager.statusMessage()}
        discoveredCount={fileManager.discoveredFiles().length}
        totalSize={fileManager.totalSize()}
        selectedCount={fileManager.selectedCount()}
        systemStats={fileManager.systemStats()}
      />
    </div>
  );
}

export default App;

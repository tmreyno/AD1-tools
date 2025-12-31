import { createSignal, createMemo } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import type { DiscoveredFile, TreeEntry, ContainerInfo } from "../types";
import { normalizeError, formatBytes } from "../utils";

// System stats interface
export interface SystemStats {
  cpu_usage: number;
  memory_used: number;
  memory_total: number;
  memory_percent: number;
  app_cpu_usage: number;
  app_memory: number;
  app_threads: number;
  cpu_cores: number;
}

export interface FileStatus {
  status: string;
  progress: number;
  error?: string;
  // Decompression progress (for E01/compressed containers)
  chunksProcessed?: number;
  chunksTotal?: number;
}

export function useFileManager() {
  // Directory state
  const [scanDir, setScanDir] = createSignal("");
  const [recursiveScan, setRecursiveScan] = createSignal(true);
  
  // File discovery state
  const [discoveredFiles, setDiscoveredFiles] = createSignal<DiscoveredFile[]>([]);
  const [selectedFiles, setSelectedFiles] = createSignal<Set<string>>(new Set());
  const [activeFile, setActiveFile] = createSignal<DiscoveredFile | null>(null);
  const [hoveredFile, setHoveredFile] = createSignal<string | null>(null);
  
  // File info and status maps
  const [fileInfoMap, setFileInfoMap] = createSignal<Map<string, ContainerInfo>>(new Map());
  const [fileStatusMap, setFileStatusMap] = createSignal<Map<string, FileStatus>>(new Map());
  
  // Tree state for AD1 files
  const [tree, setTree] = createSignal<TreeEntry[]>([]);
  const [treeFilter, setTreeFilter] = createSignal("");
  
  // File type filter - null means show all
  const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
  
  // Keyboard navigation - index of focused file in filtered list
  const [focusedFileIndex, setFocusedFileIndex] = createSignal<number>(-1);
  
  // Status state
  const [busy, setBusy] = createSignal(false);
  const [statusMessage, setStatusMessage] = createSignal("Ready");
  const [statusKind, setStatusKind] = createSignal<"idle" | "working" | "ok" | "error">("idle");
  
  // System stats
  const [systemStats, setSystemStats] = createSignal<SystemStats | null>(null);
  
  // Setup system stats listener
  const setupSystemStatsListener = async () => {
    try {
      const stats = await invoke<SystemStats>("get_system_stats");
      setSystemStats(stats);
    } catch (e) {
      console.error("Failed to get initial system stats:", e);
    }
    
    const unlisten = await listen<SystemStats>("system-stats", (event) => {
      setSystemStats(event.payload);
    });
    
    return unlisten;
  };

  // Computed values
  const filteredFiles = createMemo(() => {
    const filter = typeFilter();
    if (!filter) return discoveredFiles();
    return discoveredFiles().filter(f => f.container_type === filter);
  });
  
  const allFilesSelected = createMemo(() => {
    const files = filteredFiles();
    return files.length > 0 && files.every(f => selectedFiles().has(f.path));
  });
  
  const selectedCount = createMemo(() => selectedFiles().size);
  
  const filteredTree = createMemo(() => {
    const f = treeFilter().trim().toLowerCase();
    return (f ? tree().filter(e => e.path.toLowerCase().includes(f)) : tree()).slice(0, 500);
  });
  
  const totalSize = createMemo(() => discoveredFiles().reduce((s, f) => s + f.size, 0));
  
  const containerStats = createMemo(() => {
    const stats: Record<string, number> = {};
    discoveredFiles().forEach(f => stats[f.container_type] = (stats[f.container_type] || 0) + 1);
    return stats;
  });

  // Status helpers
  const setWorking = (msg: string) => {
    setBusy(true);
    setStatusKind("working");
    setStatusMessage(msg);
  };
  
  const setOk = (msg: string) => {
    setBusy(false);
    setStatusKind("ok");
    setStatusMessage(msg);
  };
  
  const setError = (msg: string) => {
    setBusy(false);
    setStatusKind("error");
    setStatusMessage(msg);
  };
  
  const updateFileStatus = (path: string, status: string, progress: number, error?: string, chunksProcessed?: number, chunksTotal?: number) => {
    const m = new Map(fileStatusMap());
    m.set(path, { status, progress, error, chunksProcessed, chunksTotal });
    setFileStatusMap(m);
  };

  // Toggle type filter
  const toggleTypeFilter = (type: string) => {
    setTypeFilter(prev => prev === type ? null : type);
    setFocusedFileIndex(-1);
  };
  
  // Keyboard navigation handler for file list
  const handleFileListKeyDown = (e: KeyboardEvent, onSelect: (file: DiscoveredFile) => void, onToggle: (path: string) => void) => {
    const files = filteredFiles();
    if (files.length === 0) return;
    
    const currentIndex = focusedFileIndex();
    let newIndex = currentIndex;
    
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        if (currentIndex < files.length - 1) {
          newIndex = currentIndex + 1;
        } else if (currentIndex === -1 && files.length > 0) {
          newIndex = 0;
        }
        break;
      case "ArrowUp":
        e.preventDefault();
        if (currentIndex > 0) {
          newIndex = currentIndex - 1;
        }
        break;
      case "Enter":
        e.preventDefault();
        if (currentIndex >= 0 && currentIndex < files.length) {
          onSelect(files[currentIndex]);
        }
        return;
      case " ":
        e.preventDefault();
        if (currentIndex >= 0 && currentIndex < files.length) {
          onToggle(files[currentIndex].path);
        }
        return;
      case "Home":
        e.preventDefault();
        if (files.length > 0) newIndex = 0;
        break;
      case "End":
        e.preventDefault();
        if (files.length > 0) newIndex = files.length - 1;
        break;
      case "Escape":
        e.preventDefault();
        setTypeFilter(null);
        setFocusedFileIndex(-1);
        return;
      default:
        return;
    }
    
    if (newIndex !== currentIndex && newIndex >= 0) {
      setFocusedFileIndex(newIndex);
      setTimeout(() => {
        const fileList = document.querySelector('.file-list');
        const focusedRow = fileList?.querySelector(`[data-index="${newIndex}"]`);
        focusedRow?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }, 0);
    }
  };

  // File selection
  const toggleFileSelection = (path: string) => {
    const c = new Set(selectedFiles());
    c.has(path) ? c.delete(path) : c.add(path);
    setSelectedFiles(c);
  };
  
  const toggleSelectAll = () => {
    const files = filteredFiles();
    const current = new Set(selectedFiles());
    
    if (allFilesSelected()) {
      // Deselect only the filtered files (keep other selections)
      files.forEach(f => current.delete(f.path));
    } else {
      // Add filtered files to current selection (accumulate)
      files.forEach(f => current.add(f.path));
    }
    
    setSelectedFiles(current);
  };

  // Browse for directory
  const browseScanDir = async () => {
    try {
      const selected = await open({ title: "Select Evidence Directory", multiple: false, directory: true });
      if (selected) {
        setScanDir(selected);
        await scanForFiles(selected);
      }
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  // Scan for files
  const scanForFiles = async (dir?: string) => {
    const targetDir = dir || scanDir();
    if (!targetDir.trim()) {
      setError("Select a directory first");
      return;
    }
    
    // Clear previous results
    setDiscoveredFiles([]);
    setSelectedFiles(new Set<string>());
    setFileInfoMap(new Map());
    setFileStatusMap(new Map());
    setActiveFile(null);
    setTree([]);
    setWorking("Scanning for evidence files...");
    
    // Use streaming scan
    const unlisten = await listen<DiscoveredFile>("scan-file-found", (e) => {
      const file = e.payload;
      setDiscoveredFiles(prev => [...prev, file]);
    });
    
    try {
      const count = await invoke<number>("scan_directory_streaming", { dirPath: targetDir, recursive: recursiveScan() });
      setOk(`Found ${count} evidence file(s) • ${formatBytes(discoveredFiles().reduce((s, f) => s + f.size, 0))}`);
      loadInfoInBackground();
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      unlisten();
    }
  };
  
  // Load file info in background
  const loadInfoInBackground = async () => {
    const files = discoveredFiles();
    if (files.length === 0) return;
    
    let loaded = 0;
    const total = files.length;
    
    for (const file of files) {
      if (fileInfoMap().has(file.path)) continue;
      
      try {
        const result = await invoke<ContainerInfo>("logical_info_fast", { inputPath: file.path });
        setFileInfoMap(prev => {
          const m = new Map(prev);
          m.set(file.path, result);
          return m;
        });
        loaded++;
        setStatusMessage(`Found ${total} file(s) • Loading info: ${loaded}/${total}`);
      } catch {
        // Silently skip
      }
    }
    
    if (loaded > 0) {
      setOk(`Found ${total} file(s) • Info loaded for ${loaded}`);
    }
  };

  // Load file info for a single file
  const loadFileInfo = async (file: DiscoveredFile, includeTree = false) => {
    updateFileStatus(file.path, "loading", 0);
    try {
      const result = await invoke<ContainerInfo>("logical_info", { inputPath: file.path, includeTree });
      const m = new Map(fileInfoMap());
      m.set(file.path, result);
      setFileInfoMap(m);
      updateFileStatus(file.path, "loaded", 100);
      if (includeTree && result.ad1?.tree) {
        setTree(result.ad1.tree);
        setActiveFile(file);
      }
      return result;
    } catch (err) {
      updateFileStatus(file.path, "error", 0, normalizeError(err));
      throw err;
    }
  };

  // Load all file info
  const loadAllInfo = async () => {
    setWorking(`Loading info for ${discoveredFiles().length} files...`);
    let loaded = 0;
    for (const file of discoveredFiles()) {
      if (!fileInfoMap().has(file.path)) {
        try {
          const result = await invoke<ContainerInfo>("logical_info_fast", { inputPath: file.path });
          setFileInfoMap(prev => {
            const m = new Map(prev);
            m.set(file.path, result);
            return m;
          });
          loaded++;
        } catch { }
      }
    }
    setOk(`Loaded info for ${loaded} files`);
  };

  // Select and view file
  const selectAndViewFile = async (file: DiscoveredFile) => {
    setActiveFile(file);
    if (!fileInfoMap().has(file.path)) {
      try {
        await loadFileInfo(file, true);
      } catch { }
    } else {
      const info = fileInfoMap().get(file.path);
      if (info?.ad1?.tree) setTree(info.ad1.tree);
    }
  };

  return {
    // State
    scanDir,
    setScanDir,
    recursiveScan,
    setRecursiveScan,
    discoveredFiles,
    selectedFiles,
    setSelectedFiles,
    activeFile,
    setActiveFile,
    hoveredFile,
    setHoveredFile,
    fileInfoMap,
    setFileInfoMap,
    fileStatusMap,
    tree,
    treeFilter,
    setTreeFilter,
    typeFilter,
    setTypeFilter,
    focusedFileIndex,
    setFocusedFileIndex,
    busy,
    statusMessage,
    statusKind,
    systemStats,
    
    // Computed
    filteredFiles,
    allFilesSelected,
    selectedCount,
    filteredTree,
    totalSize,
    containerStats,
    
    // Actions
    setWorking,
    setOk,
    setError,
    updateFileStatus,
    toggleTypeFilter,
    handleFileListKeyDown,
    toggleFileSelection,
    toggleSelectAll,
    browseScanDir,
    scanForFiles,
    loadFileInfo,
    loadAllInfo,
    selectAndViewFile,
    setupSystemStatsListener,
  };
}

export type FileManager = ReturnType<typeof useFileManager>;

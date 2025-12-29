import { For, Show, createMemo, createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

// Types
type SegmentHeader = { signature: string; segment_index: number; segment_number: number; fragments_size: number; header_size: number; };
type LogicalHeader = { signature: string; image_version: number; zlib_chunk_size: number; logical_metadata_addr: number; first_item_addr: number; data_source_name_length: number; ad_signature: string; data_source_name_addr: number; attrguid_footer_addr: number; locsguid_footer_addr: number; data_source_name: string; };
type TreeEntry = { path: string; is_dir: boolean; size: number; item_type: number; };
type VerifyEntry = { path: string; status: string; message?: string; };
type DiscoveredFile = { path: string; filename: string; container_type: string; size: number; segment_count?: number; created?: string; modified?: string };
type Ad1Info = { segment: SegmentHeader; logical: LogicalHeader; item_count: number; tree?: TreeEntry[]; };
type E01Info = { format_version: string; segment_count: number; sector_count: number; bytes_per_sector: number; chunk_count: number; sectors_per_chunk: number; total_size: number; compression: string; case_number?: string; description?: string; examiner_name?: string; evidence_number?: string; notes?: string; acquiry_date?: string; system_date?: string; model?: string; serial_number?: string; stored_hashes?: StoredHash[]; };
type L01Info = { format_version: number; case_info: string; examiner?: string; description?: string; file_count: number; total_size: number; };
type RawInfo = { segment_count: number; total_size: number; segment_sizes: number[]; segment_names: string[]; first_segment: string; last_segment: string; };
type StoredHash = { algorithm: string; hash: string; verified?: boolean | null; timestamp?: string | null; source?: string | null; };
type SegmentHash = { segment_name: string; segment_number: number; algorithm: string; hash: string; offset_from?: number | null; offset_to?: number | null; size?: number | null; verified?: boolean | null; };
type CompanionLogInfo = { log_path: string; created_by?: string; case_number?: string; evidence_number?: string; unique_description?: string; examiner?: string; notes?: string; acquisition_started?: string; acquisition_finished?: string; verification_started?: string; verification_finished?: string; stored_hashes: StoredHash[]; segment_list: string[]; segment_hashes: SegmentHash[]; };
type ContainerInfo = { container: string; ad1?: Ad1Info | null; e01?: E01Info | null; l01?: L01Info | null; raw?: RawInfo | null; note?: string | null; companion_log?: CompanionLogInfo | null; };
type HashAlgorithm = "md5" | "sha1" | "sha256" | "sha512" | "blake3" | "blake2" | "xxh3" | "xxh64" | "crc32";
type SegmentHashResult = { segment_name: string; segment_number: number; segment_path: string; algorithm: string; computed_hash: string; expected_hash?: string | null; verified?: boolean | null; size: number; duration_secs: number; };
type HashHistoryEntry = { algorithm: string; hash: string; timestamp: Date; source: "computed" | "stored" | "verified"; verified?: boolean | null; verified_against?: string | null; };

const HASH_ALGORITHMS: { value: HashAlgorithm; label: string }[] = [
  { value: "md5", label: "MD5" }, { value: "sha1", label: "SHA-1" }, { value: "sha256", label: "SHA-256" },
  { value: "sha512", label: "SHA-512" }, { value: "blake3", label: "BLAKE3" }, { value: "blake2", label: "BLAKE2b" },
  { value: "xxh3", label: "XXH3" }, { value: "xxh64", label: "XXH64" }, { value: "crc32", label: "CRC32" },
];

function App() {
  const [scanDir, setScanDir] = createSignal("");
  const [recursiveScan, setRecursiveScan] = createSignal(true);
  const [discoveredFiles, setDiscoveredFiles] = createSignal<DiscoveredFile[]>([]);
  const [busy, setBusy] = createSignal(false);
  const [statusMessage, setStatusMessage] = createSignal("Ready");
  const [statusKind, setStatusKind] = createSignal<"idle" | "working" | "ok" | "error">("idle");
  const [selectedFiles, setSelectedFiles] = createSignal<Set<string>>(new Set());
  const [fileInfoMap, setFileInfoMap] = createSignal<Map<string, ContainerInfo>>(new Map());
  const [fileHashMap, setFileHashMap] = createSignal<Map<string, { algorithm: string; hash: string; verified?: boolean | null }>>(new Map());
  const [fileStatusMap, setFileStatusMap] = createSignal<Map<string, { status: string; progress: number; error?: string }>>(new Map());
  const [selectedHashAlgorithm, setSelectedHashAlgorithm] = createSignal<HashAlgorithm>("sha256");
  const [hoveredFile, setHoveredFile] = createSignal<string | null>(null);
  const [activeFile, setActiveFile] = createSignal<DiscoveredFile | null>(null);
  const [tree, setTree] = createSignal<TreeEntry[]>([]);
  const [treeFilter, setTreeFilter] = createSignal("");
  // Segment verification state
  const [segmentResults, setSegmentResults] = createSignal<Map<string, SegmentHashResult[]>>(new Map());
  const [segmentVerifyProgress, setSegmentVerifyProgress] = createSignal<{ segment: string; percent: number; completed: number; total: number } | null>(null);
  // Hash history state (per file)
  const [hashHistory, setHashHistory] = createSignal<Map<string, HashHistoryEntry[]>>(new Map());

  const allFilesSelected = createMemo(() => { const files = discoveredFiles(); return files.length > 0 && files.every(f => selectedFiles().has(f.path)); });
  const selectedCount = createMemo(() => selectedFiles().size);
  const filteredTree = createMemo(() => { const f = treeFilter().trim().toLowerCase(); return (f ? tree().filter(e => e.path.toLowerCase().includes(f)) : tree()).slice(0, 500); });
  const totalSize = createMemo(() => discoveredFiles().reduce((s, f) => s + f.size, 0));
  const containerStats = createMemo(() => { const stats: Record<string, number> = {}; discoveredFiles().forEach(f => stats[f.container_type] = (stats[f.container_type] || 0) + 1); return stats; });

  const setWorking = (msg: string) => { setBusy(true); setStatusKind("working"); setStatusMessage(msg); };
  const setOk = (msg: string) => { setBusy(false); setStatusKind("ok"); setStatusMessage(msg); };
  const setError = (msg: string) => { setBusy(false); setStatusKind("error"); setStatusMessage(msg); };
  const updateFileStatus = (path: string, status: string, progress: number, error?: string) => { const m = new Map(fileStatusMap()); m.set(path, { status, progress, error }); setFileStatusMap(m); };
  
  // Format hash timestamp for display (short date format)
  const formatHashDate = (timestamp: string): string => {
    try {
      const d = new Date(timestamp);
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: '2-digit' });
    } catch { return timestamp; }
  };
  
  // Get all stored hashes from container and companion files, sorted by timestamp (newest first)
  const getAllStoredHashesSorted = (info: ContainerInfo | undefined): StoredHash[] => {
    if (!info) return [];
    
    // Collect all hashes with source info
    const allHashes: StoredHash[] = [];
    
    // E01 container hashes - use acquiry_date as timestamp
    if (info.e01?.stored_hashes) {
      const containerDate = info.e01.acquiry_date;
      info.e01.stored_hashes.forEach(h => {
        allHashes.push({
          ...h,
          timestamp: h.timestamp || containerDate || null,
          source: h.source || 'container',
        });
      });
    }
    
    // Companion log hashes - use verification_finished or acquisition_finished as timestamp
    if (info.companion_log?.stored_hashes) {
      const logDate = info.companion_log.verification_finished 
        || info.companion_log.acquisition_finished;
      info.companion_log.stored_hashes.forEach(h => {
        allHashes.push({
          ...h,
          timestamp: h.timestamp || logDate || null,
          source: h.source || 'companion',
        });
      });
    }
    
    // Sort by: 1) source (container first, then companion), 2) algorithm, 3) timestamp
    return allHashes.sort((a, b) => {
      // Container hashes first
      if (a.source === 'container' && b.source !== 'container') return -1;
      if (b.source === 'container' && a.source !== 'container') return 1;
      // Then by algorithm
      if (a.algorithm !== b.algorithm) return a.algorithm.localeCompare(b.algorithm);
      // Then by timestamp (newest first)
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
  };

  const browseScanDir = async () => {
    try {
      const selected = await open({ title: "Select Evidence Directory", multiple: false, directory: true });
      if (selected) { setScanDir(selected); await scanForFiles(selected); }
    } catch (err) { setError(normalizeError(err)); }
  };

  const scanForFiles = async (dir?: string) => {
    const targetDir = dir || scanDir();
    if (!targetDir.trim()) { setError("Select a directory first"); return; }
    
    // Clear previous results immediately
    setDiscoveredFiles([]); setSelectedFiles(new Set<string>()); setFileInfoMap(new Map()); setFileHashMap(new Map()); setFileStatusMap(new Map()); setActiveFile(null); setTree([]);
    setWorking("Scanning for evidence files...");
    
    // Use streaming scan - files appear as they're found
    const unlisten = await listen<DiscoveredFile>("scan-file-found", (e) => {
      const file = e.payload;
      setDiscoveredFiles(prev => [...prev, file]);
      // Load file info immediately in background
      loadSingleFileInfo(file);
    });
    
    try {
      const count = await invoke<number>("scan_directory_streaming", { dirPath: targetDir, recursive: recursiveScan() });
      setOk(`Found ${count} evidence file(s) • ${formatBytes(discoveredFiles().reduce((s, f) => s + f.size, 0))}`);
    } catch (err) { 
      setError(normalizeError(err)); 
    } finally {
      unlisten();
    }
  };
  
  // Load file info for a single file in background
  const loadSingleFileInfo = (file: DiscoveredFile) => {
    invoke<ContainerInfo>("logical_info", { inputPath: file.path, includeTree: false })
      .then(info => {
        setFileInfoMap(prev => { const m = new Map(prev); m.set(file.path, info); return m; });
      })
      .catch(() => { /* ignore load errors */ });
  };

  const toggleFileSelection = (path: string) => { const c = new Set(selectedFiles()); c.has(path) ? c.delete(path) : c.add(path); setSelectedFiles(c); };
  const toggleSelectAll = () => { allFilesSelected() ? setSelectedFiles(new Set<string>()) : setSelectedFiles(new Set(discoveredFiles().map(f => f.path))); };

  const loadFileInfo = async (file: DiscoveredFile, includeTree = false) => {
    updateFileStatus(file.path, "loading", 0);
    try {
      const result = await invoke<ContainerInfo>("logical_info", { inputPath: file.path, includeTree });
      const m = new Map(fileInfoMap()); m.set(file.path, result); setFileInfoMap(m);
      updateFileStatus(file.path, "loaded", 100);
      if (includeTree && result.ad1?.tree) { setTree(result.ad1.tree); setActiveFile(file); }
      return result;
    } catch (err) { updateFileStatus(file.path, "error", 0, normalizeError(err)); throw err; }
  };

  const loadAllInfo = async () => {
    setWorking(`Loading info for ${discoveredFiles().length} files...`);
    let loaded = 0;
    for (const file of discoveredFiles()) { if (!fileInfoMap().has(file.path)) { try { await loadFileInfo(file, false); loaded++; } catch { } } }
    setOk(`Loaded info for ${loaded} files`);
  };

  const hashSingleFile = async (file: DiscoveredFile) => {
    const algorithm = selectedHashAlgorithm();
    updateFileStatus(file.path, "hashing", 0);
    const unlisten = await listen<{ percent: number }>("verify-progress", (e) => updateFileStatus(file.path, "hashing", e.payload.percent));
    try {
      let hash: string;
      const ctype = file.container_type.toLowerCase();
      if (ctype.includes("e01") || ctype.includes("encase") || ctype.includes("ex01")) hash = await invoke<string>("e01_v3_verify", { inputPath: file.path, algorithm });
      else if (ctype.includes("raw") || ctype.includes("dd")) hash = await invoke<string>("raw_verify", { inputPath: file.path, algorithm });
      else { const r = await invoke<VerifyEntry[]>("logical_verify", { inputPath: file.path, algorithm }); hash = r.length > 0 && r[0].message ? r[0].message : "Complete"; }
      
      // Check if there's a stored hash to compare against
      const info = fileInfoMap().get(file.path);
      const storedHashes = [...(info?.e01?.stored_hashes ?? []), ...(info?.companion_log?.stored_hashes ?? [])];
      const matchingStored = storedHashes.find(sh => sh.algorithm.toLowerCase() === algorithm.toLowerCase());
      const verified = matchingStored ? hash.toLowerCase() === matchingStored.hash.toLowerCase() : null;
      
      const m = new Map(fileHashMap()); m.set(file.path, { algorithm: algorithm.toUpperCase(), hash, verified }); setFileHashMap(m);
      updateFileStatus(file.path, "hashed", 100);
      
      recordHashToHistory(file, algorithm.toUpperCase(), hash, verified ?? undefined, matchingStored?.hash);
      
      return hash;
    } catch (err) { updateFileStatus(file.path, "error", 0, normalizeError(err)); throw err; } finally { unlisten(); }
  };

  const hashSelectedFiles = async () => {
    const files = discoveredFiles().filter(f => selectedFiles().has(f.path));
    if (!files.length) { setError("No files selected"); return; }
    
    const numCores = navigator.hardwareConcurrency || 4;
    setWorking(`Loading file info for ${files.length} file(s)...`);
    
    // First, load file info for all files that don't have it yet (needed for stored hash comparison)
    const filesToLoad = files.filter(f => !fileInfoMap().has(f.path));
    for (const file of filesToLoad) {
      try { await loadFileInfo(file, false); } catch { /* ignore load errors */ }
    }
    
    setWorking(`Hashing ${files.length} file(s) in parallel (${numCores} cores)...`);
    
    // Set all selected files to hashing status
    files.forEach(f => updateFileStatus(f.path, "hashing", 0));
    
    // Listen for batch progress events
    const unlisten = await listen<{ path: string; status: string; percent: number; files_completed: number; files_total: number }>(
      "batch-progress",
      (e) => {
        const { path, status, percent, files_completed, files_total } = e.payload;
        if (status === "progress" || status === "started") {
          updateFileStatus(path, "hashing", percent);
        }
        setWorking(`Hashing ${files_total} files... (${files_completed}/${files_total} complete)`);
      }
    );
    
    try {
      // Call batch hash with all files
      const results = await invoke<{ path: string; algorithm: string; hash?: string; error?: string }[]>(
        "batch_hash",
        { files: files.map(f => ({ path: f.path, container_type: f.container_type })), algorithm: selectedHashAlgorithm() }
      );
      
      // Process results
      let completed = 0;
      let verifiedCount = 0;
      let failedCount = 0;
      let noStoredCount = 0;
      const hashMap = new Map(fileHashMap());
      for (const result of results) {
        if (result.hash) {
          // Check if there's a stored hash to compare against
          const file = files.find(f => f.path === result.path);
          const info = fileInfoMap().get(result.path);
          const storedHashes = [...(info?.e01?.stored_hashes ?? []), ...(info?.companion_log?.stored_hashes ?? [])];
          const matchingStored = storedHashes.find(sh => sh.algorithm.toLowerCase() === result.algorithm.toLowerCase());
          const verified = matchingStored ? result.hash.toLowerCase() === matchingStored.hash.toLowerCase() : null;
          
          // Track verification stats
          if (verified === true) verifiedCount++;
          else if (verified === false) failedCount++;
          else noStoredCount++;
          
          hashMap.set(result.path, { algorithm: result.algorithm, hash: result.hash, verified });
          updateFileStatus(result.path, "hashed", 100);
          
          if (file) {
            recordHashToHistory(file, result.algorithm, result.hash, verified ?? undefined, matchingStored?.hash);
          }
          completed++;
        } else {
          updateFileStatus(result.path, "error", 0, result.error || "Unknown error");
        }
      }
      setFileHashMap(hashMap);
      
      // Build status message with verification summary
      let statusMsg = `Hashed ${completed}/${files.length} files`;
      if (verifiedCount > 0 || failedCount > 0) {
        const parts = [];
        if (verifiedCount > 0) parts.push(`✓ ${verifiedCount} verified`);
        if (failedCount > 0) parts.push(`✗ ${failedCount} FAILED`);
        if (noStoredCount > 0) parts.push(`${noStoredCount} no stored hash`);
        statusMsg += ` • ${parts.join(", ")}`;
      }
      if (failedCount > 0) {
        setError(statusMsg);
      } else {
        setOk(statusMsg);
      }
    } catch (err) {
      setError(normalizeError(err));
      files.forEach(f => updateFileStatus(f.path, "error", 0, normalizeError(err)));
    } finally {
      unlisten();
    }
  };

  const hashAllFiles = async () => {
    const files = discoveredFiles();
    if (!files.length) { setError("No files discovered"); return; }
    // Select all files first
    setSelectedFiles(new Set(files.map(f => f.path)));
    await hashSelectedFiles();
  };

  // Verify individual segments of a multi-segment image (raw or E01)
  const verifySegments = async (file: DiscoveredFile) => {
    const info = fileInfoMap().get(file.path);
    const isE01 = file.container_type.toLowerCase().includes("e01") || file.container_type.toLowerCase().includes("encase");
    
    // Get expected hashes from companion log if available
    const expectedHashes = info?.companion_log?.segment_hashes ?? [];
    const algorithm = expectedHashes.length > 0 ? expectedHashes[0].algorithm.toLowerCase() : selectedHashAlgorithm();
    
    setWorking(`Verifying segments with ${algorithm.toUpperCase()}...`);
    updateFileStatus(file.path, "verifying-segments", 0);
    setSegmentVerifyProgress({ segment: "", percent: 0, completed: 0, total: 0 });
    
    // Listen for progress events
    const unlisten = await listen<{ segment_name: string; segment_number: number; percent: number; segments_completed: number; segments_total: number }>(
      "segment-verify-progress",
      (e) => {
        setSegmentVerifyProgress({
          segment: e.payload.segment_name,
          percent: e.payload.percent,
          completed: e.payload.segments_completed,
          total: e.payload.segments_total
        });
        setWorking(`Verifying segment ${e.payload.segment_name} (${e.payload.segments_completed}/${e.payload.segments_total})...`);
      }
    );
    
    try {
      // Use different commands based on container type
      const command = isE01 ? "e01_verify_segments" : "raw_verify_segments";
      const results = await invoke<SegmentHashResult[]>(command, {
        inputPath: file.path,
        algorithm,
        expectedHashes
      });
      
      // Store segment results
      const resultsMap = new Map(segmentResults());
      resultsMap.set(file.path, results);
      setSegmentResults(resultsMap);
      
      // Update hash history with segment results
      const history = new Map(hashHistory());
      const fileHistory = history.get(file.path) ?? [];
      const timestamp = new Date();
      
      for (const seg of results) {
        fileHistory.push({
          algorithm: seg.algorithm,
          hash: seg.computed_hash,
          timestamp,
          source: seg.expected_hash ? "verified" : "computed",
          verified: seg.verified,
          verified_against: seg.expected_hash
        });
      }
      history.set(file.path, fileHistory);
      setHashHistory(history);
      
      // Count verification results
      const verified = results.filter(r => r.verified === true).length;
      const failed = results.filter(r => r.verified === false).length;
      const noExpected = results.filter(r => r.verified === null || r.verified === undefined).length;
      
      updateFileStatus(file.path, "segments-verified", 100);
      setSegmentVerifyProgress(null);
      
      if (failed > 0) {
        setError(`⚠️ ${failed} segment(s) FAILED verification!`);
      } else if (verified > 0) {
        setOk(`✓ All ${verified} segments verified • ${noExpected > 0 ? `${noExpected} no expected hash` : ""}`);
      } else {
        setOk(`Computed ${results.length} segment hashes (no stored hashes to verify against)`);
      }
      
    } catch (err) {
      updateFileStatus(file.path, "error", 0, normalizeError(err));
      setError(normalizeError(err));
      setSegmentVerifyProgress(null);
    } finally {
      unlisten();
    }
  };

  // Add hash to history when computed
  const recordHashToHistory = (file: DiscoveredFile, algorithm: string, hash: string, verified?: boolean, verifiedAgainst?: string) => {
    const history = new Map(hashHistory());
    const fileHistory = history.get(file.path) ?? [];
    fileHistory.push({
      algorithm,
      hash,
      timestamp: new Date(),
      source: verified !== undefined ? "verified" : "computed",
      verified,
      verified_against: verifiedAgainst
    });
    history.set(file.path, fileHistory);
    setHashHistory(history);
  };

  const selectAndViewFile = async (file: DiscoveredFile) => {
    setActiveFile(file);
    if (!fileInfoMap().has(file.path)) { try { await loadFileInfo(file, true); } catch { } }
    else { const info = fileInfoMap().get(file.path); if (info?.ad1?.tree) setTree(info.ad1.tree); }
  };

  return (
    <div class="app compact">
      <header class="header-bar">
        <div class="brand"><span class="brand-icon">🔬</span><span class="brand-name">liblfx</span><span class="brand-tag">Forensic Container Explorer</span></div>
        <div class="header-status"><span class={`status-dot ${statusKind()}`} /><span class="status-text">{statusMessage()}</span></div>
      </header>

      <div class="toolbar">
        <button class="tool-btn primary" onClick={browseScanDir} disabled={busy()}>📁 Open Directory</button>
        <div class="tool-input">
          <input type="text" value={scanDir()} onInput={(e) => setScanDir(e.currentTarget.value)} placeholder="Evidence directory path..." onKeyDown={(e) => e.key === "Enter" && scanForFiles()} />
          <button class="tool-btn" onClick={() => scanForFiles()} disabled={busy() || !scanDir()}>🔍</button>
        </div>
        <label class="tool-toggle" title="Scan subdirectories"><input type="checkbox" checked={recursiveScan()} onChange={(e) => setRecursiveScan(e.currentTarget.checked)} /><span>Recursive</span></label>
        <div class="tool-sep" />
        <select class="tool-select" value={selectedHashAlgorithm()} onChange={(e) => setSelectedHashAlgorithm(e.currentTarget.value as HashAlgorithm)} title="Hash algorithm">
          <For each={HASH_ALGORITHMS}>{(alg) => <option value={alg.value}>{alg.label}</option>}</For>
        </select>
        <button class="tool-btn" onClick={hashSelectedFiles} disabled={busy() || selectedCount() === 0} title={`Hash ${selectedCount()} selected files in parallel`}>🔐 Hash ({selectedCount()})</button>
        <button class="tool-btn" onClick={hashAllFiles} disabled={busy() || discoveredFiles().length === 0} title={`Hash all ${discoveredFiles().length} files in parallel using all CPU cores`}>⚡ Hash All</button>
        <button class="tool-btn" onClick={loadAllInfo} disabled={busy() || discoveredFiles().length === 0} title="Load metadata for all files">ℹ️ Load All</button>
      </div>

      <div class="main-layout">
        <aside class="file-panel">
          <div class="panel-header"><h3>Evidence Files</h3><Show when={discoveredFiles().length > 0}><div class="panel-stats"><span class="stat">{discoveredFiles().length} files</span><span class="stat">{formatBytes(totalSize())}</span></div></Show></div>
          <Show when={Object.keys(containerStats()).length > 0}><div class="type-summary"><For each={Object.entries(containerStats())}>{([type, count]) => <span class={`type-badge ${typeClass(type)}`} title={`${count} ${type} file(s)`}>{type}: {count}</span>}</For></div></Show>
          <Show when={discoveredFiles().length > 0}><div class="select-all-row"><label class="check-label"><input type="checkbox" checked={allFilesSelected()} onChange={toggleSelectAll} /><span>{allFilesSelected() ? "Deselect All" : "Select All"}</span></label></div></Show>
          <div class="file-list">
            <Show when={discoveredFiles().length === 0}><div class="empty-state"><span class="empty-icon">📂</span><p>Open a directory to scan for evidence files</p><p class="empty-hint">Supports AD1, E01, L01, Raw images</p></div></Show>
            <For each={discoveredFiles()}>{(file) => {
              const isSelected = () => selectedFiles().has(file.path);
              const isHovered = () => hoveredFile() === file.path;
              const isActive = () => activeFile()?.path === file.path;
              const fileStatus = () => fileStatusMap().get(file.path);
              const fileInfo = () => fileInfoMap().get(file.path);
              const fileHash = () => fileHashMap().get(file.path);
              return (
                <div class={`file-row ${isSelected() ? "selected" : ""} ${isActive() ? "active" : ""}`} onMouseEnter={() => setHoveredFile(file.path)} onMouseLeave={() => setHoveredFile(null)} onClick={() => selectAndViewFile(file)}>
                  <input type="checkbox" checked={isSelected()} onChange={(e) => { e.stopPropagation(); toggleFileSelection(file.path); }} onClick={(e) => e.stopPropagation()} />
                  <span class={`type-icon ${typeClass(file.container_type)}`} title={file.container_type}>{typeIcon(file.container_type)}</span>
                  <div class="file-info"><span class="file-name" title={file.path}>{file.filename}</span><span class="file-meta">{formatBytes(file.size)}<Show when={file.segment_count && file.segment_count > 1}><span class="seg-count">• {file.segment_count} segs</span></Show></span></div>
                  <div class="file-actions">
                    <Show when={fileStatus()?.status === "hashing"}><span class="progress-mini">{fileStatus()!.progress.toFixed(0)}%</span></Show>
                    <Show when={fileHash()?.verified === true}><span class="hash-verified" title={`Verified: ${fileHash()!.algorithm} matches stored hash`}>✓</span></Show>
                    <Show when={fileHash()?.verified === false}><span class="hash-failed" title={`FAILED: ${fileHash()!.algorithm} does NOT match stored hash`}>✗</span></Show>
                    <Show when={fileHash() && fileHash()?.verified === null}><span class="hash-done" title={`Computed: ${fileHash()!.algorithm}`}>✓</span></Show>
                    <Show when={(fileInfo()?.companion_log?.stored_hashes?.length ?? 0) > 0 || (fileInfo()?.e01?.stored_hashes?.length ?? 0) > 0}><span class="stored-badge" title="Has stored hashes">📜</span></Show>
                    <button class="action-btn" onClick={(e) => { e.stopPropagation(); hashSingleFile(file); }} disabled={busy()} title="Hash this file">#</button>
                  </div>
                  <Show when={isHovered() && !isActive()}>
                    <div class="file-tooltip">
                      <div class="tooltip-header">{file.container_type}</div>
                      <div class="tooltip-path">{file.path}</div>
                      <div class="tooltip-row"><span>Size:</span><span>{formatBytes(file.size)}</span></div>
                      <Show when={file.segment_count}><div class="tooltip-row"><span>Segments:</span><span>{file.segment_count}</span></div></Show>
                      <Show when={fileInfo()}><div class="tooltip-divider" />
                        <Show when={fileInfo()!.ad1}><div class="tooltip-row"><span>Items:</span><span>{fileInfo()!.ad1!.item_count}</span></div><div class="tooltip-row"><span>Source:</span><span>{fileInfo()!.ad1!.logical.data_source_name}</span></div></Show>
                        <Show when={fileInfo()!.e01}><div class="tooltip-row"><span>Format:</span><span>{fileInfo()!.e01!.format_version}</span></div><div class="tooltip-row"><span>Compression:</span><span>{fileInfo()!.e01!.compression}</span></div><Show when={fileInfo()!.e01!.case_number}><div class="tooltip-row"><span>Case:</span><span>{fileInfo()!.e01!.case_number}</span></div></Show></Show>
                        <Show when={fileInfo()!.raw}><div class="tooltip-row"><span>Segments:</span><span>{fileInfo()!.raw!.segment_count}</span></div></Show>
                        <Show when={(fileInfo()?.e01?.stored_hashes?.length ?? 0) > 0 || (fileInfo()?.companion_log?.stored_hashes?.length ?? 0) > 0}>
                          <div class="tooltip-divider" />
                          <div class="tooltip-section-title">📜 Stored Hashes</div>
                          <Show when={(fileInfo()?.e01?.stored_hashes?.length ?? 0) > 0}>
                            <For each={fileInfo()!.e01!.stored_hashes!}>{(sh) => (
                              <div class="tooltip-hash-row">
                                <span class="tooltip-hash-algo">{sh.algorithm}</span>
                                <code class="tooltip-hash-val">{sh.hash.substring(0, 16)}...</code>
                                <Show when={sh.verified === true}><span class="tooltip-verified">✓</span></Show>
                              </div>
                            )}</For>
                          </Show>
                          <Show when={(fileInfo()?.companion_log?.stored_hashes?.length ?? 0) > 0}>
                            <For each={fileInfo()!.companion_log!.stored_hashes}>{(sh) => (
                              <div class="tooltip-hash-row">
                                <span class="tooltip-hash-algo">{sh.algorithm}</span>
                                <code class="tooltip-hash-val">{sh.hash.substring(0, 16)}...</code>
                                <Show when={sh.verified === true}><span class="tooltip-verified">✓</span></Show>
                              </div>
                            )}</For>
                          </Show>
                        </Show>
                      </Show>
                      <Show when={fileHash()}><div class="tooltip-divider" /><div class="tooltip-hash"><span class="hash-algo">🔐 {fileHash()!.algorithm}</span><code>{fileHash()!.hash}</code></div></Show>
                    </div>
                  </Show>
                </div>
              );
            }}</For>
          </div>
        </aside>

        <main class="detail-panel">
          <Show when={activeFile()} fallback={<div class="empty-detail"><span class="empty-icon">📋</span><p>Select a file to view details</p></div>}>
            {(file) => {
              const info = () => fileInfoMap().get(file().path);
              const hash = () => fileHashMap().get(file().path);
              const status = () => fileStatusMap().get(file().path);
              const isHashing = () => status()?.status === "hashing";
              return (
                <div class="detail-content">
                  <div class="detail-header"><span class={`detail-type ${typeClass(file().container_type)}`}>{typeIcon(file().container_type)} {file().container_type}</span><h2>{file().filename}</h2><p class="detail-path">{file().path}</p></div>
                  <div class="stat-row">
                    <div class="stat-item"><span class="stat-label">Size</span><span class="stat-value">{formatBytes(file().size)}</span></div>
                    <Show when={file().segment_count}><div class="stat-item"><span class="stat-label">Segments</span><span class="stat-value">{file().segment_count}</span></div></Show>
                    <Show when={file().created}><div class="stat-item"><span class="stat-label">Created</span><span class="stat-value">{file().created}</span></div></Show>
                    <Show when={file().modified}><div class="stat-item"><span class="stat-label">Modified</span><span class="stat-value">{file().modified}</span></div></Show>
                    <Show when={info()?.ad1}><div class="stat-item"><span class="stat-label">Items</span><span class="stat-value">{info()!.ad1!.item_count}</span></div></Show>
                    <Show when={info()?.e01}><div class="stat-item"><span class="stat-label">Chunks</span><span class="stat-value">{info()!.e01!.chunk_count.toLocaleString()}</span></div><div class="stat-item"><span class="stat-label">Sectors</span><span class="stat-value">{info()!.e01!.sector_count.toLocaleString()}</span></div></Show>
                  </div>
                  <Show when={isHashing()}>
                    <div class="hash-progress-section">
                      <div class="hash-progress-header"><span>🔐 Hashing with {selectedHashAlgorithm().toUpperCase()}...</span><span class="hash-progress-percent">{status()!.progress.toFixed(1)}%</span></div>
                      <div class="hash-progress-bar"><div class="hash-progress-fill" style={{ width: `${status()!.progress}%` }} /></div>
                    </div>
                  </Show>
                  <Show when={hash() && !isHashing()}>
                    <div class={`hash-card computed ${hash()!.verified === true ? 'verified' : hash()!.verified === false ? 'failed' : ''}`}>
                      <div class="hash-header">
                        <span class="hash-algo-label">🔐 {hash()!.algorithm}</span>
                        <Show when={hash()!.verified === true}><span class="verify-status verified">✓ Verified</span></Show>
                        <Show when={hash()!.verified === false}><span class="verify-status failed">✗ FAILED</span></Show>
                        <Show when={hash()!.verified === null}><span class="verify-status neutral">Computed</span></Show>
                        <button class="copy-btn" onClick={() => navigator.clipboard.writeText(hash()!.hash)} title="Copy hash">📋</button>
                      </div>
                      <code class="hash-full">{hash()!.hash}</code>
                    </div>
                  </Show>
                  <Show when={(info()?.companion_log?.stored_hashes?.length ?? 0) > 0 || (info()?.e01?.stored_hashes?.length ?? 0) > 0}>
                    <div class="compact-section stored-hashes-compact">
                      <div class="section-header-compact">
                        <span class="section-title">📜 Stored Hashes</span>
                      </div>
                      <div class="stored-hash-list">
                        {/* Combine and sort all hashes by timestamp, newest first */}
                        <For each={getAllStoredHashesSorted(info())}>{(sh) => (
                          <div class={`stored-hash-row ${sh.verified === true ? 'verified' : sh.verified === false ? 'failed' : ''}`}>
                            <span class="sh-algo">{sh.algorithm}</span>
                            <code class="sh-value">{sh.hash}</code>
                            <Show when={sh.verified === true}><span class="sh-badge ok">✓</span></Show>
                            <Show when={sh.verified === false}><span class="sh-badge fail">✗</span></Show>
                            {sh.timestamp && <span class="sh-date" title={sh.timestamp}>{formatHashDate(sh.timestamp)}</span>}
                            <span class={`sh-source ${sh.source || 'unknown'}`} title={`Source: ${sh.source || 'unknown'}`}>
                              {sh.source === 'container' ? '📦' : sh.source === 'companion' ? '📄' : '💻'}
                            </span>
                            <button class="sh-copy" onClick={() => navigator.clipboard.writeText(sh.hash)} title="Copy">📋</button>
                          </div>
                        )}</For>
                      </div>
                    </div>
                  </Show>
                  {/* Segment Hashes from companion log */}
                  <Show when={(info()?.companion_log?.segment_hashes?.length ?? 0) > 0}>
                    <div class="compact-section segment-hashes-section">
                      <div class="section-header-compact">
                        <span class="section-title">📊 Per-Segment Hashes ({info()!.companion_log!.segment_hashes.length})</span>
                        <button 
                          class="verify-segments-btn" 
                          onClick={() => verifySegments(file())} 
                          disabled={busy() || fileStatusMap().get(file().path)?.status === "verifying-segments"}
                          title="Verify each segment against stored hash"
                        >
                          🔍 Verify Segments
                        </button>
                      </div>
                      <div class="segment-hash-list">
                        <For each={info()!.companion_log!.segment_hashes}>{(sh) => {
                          // Find computed result if exists
                          const computed = () => segmentResults().get(file().path)?.find(r => r.segment_name.toLowerCase() === sh.segment_name.toLowerCase());
                          return (
                            <div class={`segment-hash-row ${computed()?.verified === true ? 'verified' : computed()?.verified === false ? 'failed' : ''}`}>
                              <span class="seg-name">{sh.segment_name}</span>
                              <span class="seg-algo">{sh.algorithm}</span>
                              <code class="seg-hash" title={sh.hash}>{sh.hash.substring(0, 16)}...</code>
                              <Show when={sh.size}><span class="seg-size">{formatBytes(sh.size!)}</span></Show>
                              <Show when={computed()?.verified === true}><span class="seg-badge ok">✓</span></Show>
                              <Show when={computed()?.verified === false}><span class="seg-badge fail">✗</span></Show>
                              <button class="seg-copy" onClick={() => navigator.clipboard.writeText(sh.hash)} title="Copy">📋</button>
                            </div>
                          );
                        }}</For>
                      </div>
                    </div>
                  </Show>
                  {/* Computed Segment Results */}
                  <Show when={(segmentResults().get(file().path)?.length ?? 0) > 0 && !(info()?.companion_log?.segment_hashes?.length)}>
                    <div class="compact-section computed-segments-section">
                      <div class="section-title">📊 Computed Segment Hashes</div>
                      <div class="segment-hash-list">
                        <For each={segmentResults().get(file().path)}>{(sr) => (
                          <div class={`segment-hash-row ${sr.verified === true ? 'verified' : sr.verified === false ? 'failed' : ''}`}>
                            <span class="seg-name">{sr.segment_name}</span>
                            <span class="seg-algo">{sr.algorithm}</span>
                            <code class="seg-hash" title={sr.computed_hash}>{sr.computed_hash.substring(0, 16)}...</code>
                            <span class="seg-size">{formatBytes(sr.size)}</span>
                            <span class="seg-time">{sr.duration_secs.toFixed(1)}s</span>
                            <Show when={sr.verified === true}><span class="seg-badge ok">✓</span></Show>
                            <Show when={sr.verified === false}><span class="seg-badge fail">✗</span></Show>
                            <button class="seg-copy" onClick={() => navigator.clipboard.writeText(sr.computed_hash)} title="Copy">📋</button>
                          </div>
                        )}</For>
                      </div>
                    </div>
                  </Show>
                  {/* Segment verification progress */}
                  <Show when={segmentVerifyProgress() && fileStatusMap().get(file().path)?.status === "verifying-segments"}>
                    <div class="segment-progress-section">
                      <div class="segment-progress-header">
                        <span>🔍 Verifying {segmentVerifyProgress()!.segment}...</span>
                        <span>{segmentVerifyProgress()!.completed}/{segmentVerifyProgress()!.total}</span>
                      </div>
                      <div class="segment-progress-bar">
                        <div class="segment-progress-fill" style={{ width: `${segmentVerifyProgress()!.percent}%` }} />
                      </div>
                    </div>
                  </Show>
                  {/* Hash History */}
                  <Show when={(hashHistory().get(file().path)?.length ?? 0) > 0}>
                    <div class="compact-section hash-history-section">
                      <div class="section-title">🕒 Hash History</div>
                      <div class="hash-history-list">
                        <For each={hashHistory().get(file().path)?.slice().reverse()}>{(entry) => (
                          <div class={`history-row ${entry.verified === true ? 'verified' : entry.verified === false ? 'failed' : ''}`}>
                            <span class="hist-time">{entry.timestamp.toLocaleTimeString()}</span>
                            <span class="hist-algo">{entry.algorithm}</span>
                            <span class="hist-source">{entry.source}</span>
                            <code class="hist-hash" title={entry.hash}>{entry.hash.substring(0, 16)}...</code>
                            <Show when={entry.verified === true}><span class="hist-badge ok">✓</span></Show>
                            <Show when={entry.verified === false}><span class="hist-badge fail">✗</span></Show>
                          </div>
                        )}</For>
                      </div>
                    </div>
                  </Show>
                  <Show when={info()}><div class="compact-section"><div class="section-title">📋 Container Details</div>
                    <Show when={info()!.ad1}>{(ad1) => <div class="info-compact"><div class="info-row"><span class="info-label">Source</span><span class="info-value">{ad1().logical.data_source_name}</span></div><div class="info-row"><span class="info-label">Version</span><span class="info-value">{ad1().logical.image_version}</span></div><div class="info-row"><span class="info-label">Signature</span><span class="info-value">{ad1().logical.signature}</span></div><div class="info-row"><span class="info-label">Chunk Size</span><span class="info-value">{formatBytes(ad1().logical.zlib_chunk_size)}</span></div></div>}</Show>
                    <Show when={info()!.e01}>{(e01) => <div class="info-compact">
                      <div class="info-row"><span class="info-label">Format</span><span class="info-value">{e01().format_version}</span></div>
                      <div class="info-row"><span class="info-label">Segments</span><span class="info-value">{e01().segment_count}</span></div>
                      <div class="info-row"><span class="info-label">Total Size</span><span class="info-value">{formatBytes(e01().total_size)}</span></div>
                      <div class="info-row"><span class="info-label">Compression</span><span class="info-value">{e01().compression}</span></div>
                      <div class="info-row"><span class="info-label">Bytes/Sector</span><span class="info-value">{e01().bytes_per_sector}</span></div>
                      <div class="info-row"><span class="info-label">Sectors/Chunk</span><span class="info-value">{e01().sectors_per_chunk}</span></div>
                      <Show when={e01().case_number}><div class="info-row highlight"><span class="info-label">Case #</span><span class="info-value">{e01().case_number}</span></div></Show>
                      <Show when={e01().evidence_number}><div class="info-row highlight"><span class="info-label">Evidence #</span><span class="info-value">{e01().evidence_number}</span></div></Show>
                      <Show when={e01().examiner_name}><div class="info-row"><span class="info-label">Examiner</span><span class="info-value">{e01().examiner_name}</span></div></Show>
                      <Show when={e01().acquiry_date}><div class="info-row"><span class="info-label">Acquired</span><span class="info-value">{e01().acquiry_date}</span></div></Show>
                      <Show when={e01().system_date}><div class="info-row"><span class="info-label">System Date</span><span class="info-value">{e01().system_date}</span></div></Show>
                      <Show when={e01().model}><div class="info-row device"><span class="info-label">Model</span><span class="info-value">{e01().model}</span></div></Show>
                      <Show when={e01().serial_number}><div class="info-row device"><span class="info-label">Serial #</span><span class="info-value">{e01().serial_number}</span></div></Show>
                      <Show when={e01().description}><div class="info-row full-width"><span class="info-label">Description</span><span class="info-value">{e01().description}</span></div></Show>
                      <Show when={e01().notes}><div class="info-row full-width"><span class="info-label">Notes</span><span class="info-value notes">{e01().notes}</span></div></Show>
                    </div>}</Show>
                    <Show when={info()!.l01}>{(l01) => <div class="info-compact"><div class="info-row"><span class="info-label">Format</span><span class="info-value">{l01().format_version}</span></div><div class="info-row"><span class="info-label">File Count</span><span class="info-value">{l01().file_count}</span></div><div class="info-row"><span class="info-label">Total Size</span><span class="info-value">{formatBytes(l01().total_size)}</span></div><div class="info-row"><span class="info-label">Case</span><span class="info-value">{l01().case_info}</span></div><Show when={l01().examiner}><div class="info-row"><span class="info-label">Examiner</span><span class="info-value">{l01().examiner}</span></div></Show><Show when={l01().description}><div class="info-row full-width"><span class="info-label">Description</span><span class="info-value">{l01().description}</span></div></Show></div>}</Show>
                    <Show when={info()!.raw}>{(raw) => <div class="info-compact"><div class="info-row"><span class="info-label">Segments</span><span class="info-value">{raw().segment_count} ({raw().first_segment} → {raw().last_segment})</span></div><div class="info-row"><span class="info-label">Total Size</span><span class="info-value">{formatBytes(raw().total_size)}</span></div><Show when={raw().segment_count > 1}><div class="info-row full-width"><span class="info-label">Segment Files</span><span class="info-value seg-list">{raw().segment_names.slice(0, 5).join(", ")}{raw().segment_count > 5 ? ` (+${raw().segment_count - 5} more)` : ""}</span></div></Show></div>}</Show>
                    <Show when={info()!.companion_log}>{(log) => <div class="info-compact companion-meta"><Show when={log().created_by}><div class="info-row"><span class="info-label">Created By</span><span class="info-value">{log().created_by}</span></div></Show><Show when={log().case_number}><div class="info-row highlight"><span class="info-label">Case #</span><span class="info-value">{log().case_number}</span></div></Show><Show when={log().evidence_number}><div class="info-row highlight"><span class="info-label">Evidence #</span><span class="info-value">{log().evidence_number}</span></div></Show><Show when={log().examiner}><div class="info-row"><span class="info-label">Examiner</span><span class="info-value">{log().examiner}</span></div></Show><Show when={log().unique_description}><div class="info-row full-width"><span class="info-label">Source</span><span class="info-value">{log().unique_description}</span></div></Show><Show when={log().acquisition_started}><div class="info-row"><span class="info-label">Acquired</span><span class="info-value">{log().acquisition_started}</span></div></Show><Show when={log().notes}><div class="info-row full-width"><span class="info-label">Notes</span><span class="info-value notes">{log().notes}</span></div></Show></div>}</Show>
                  </div></Show>
                  <Show when={tree().length > 0}><div class="compact-section"><div class="section-header-compact"><span class="section-title">📁 File Tree ({tree().length})</span><input type="text" class="tree-filter-sm" placeholder="Filter..." value={treeFilter()} onInput={(e) => setTreeFilter(e.currentTarget.value)} /></div><div class="tree-list-compact"><For each={filteredTree()}>{(entry) => <div class={`tree-row ${entry.is_dir ? "dir" : "file"}`}><span class="tree-icon">{entry.is_dir ? "📁" : "📄"}</span><span class="tree-path">{entry.path}</span><span class="tree-size">{entry.is_dir ? "" : formatBytes(entry.size)}</span></div>}</For><Show when={tree().length > 500}><div class="tree-truncated">Showing first 500 of {tree().length} items</div></Show></div></div></Show>
                  <div class="detail-actions-compact">
                    <button class="action-btn-primary" onClick={() => hashSingleFile(file())} disabled={busy() || fileStatusMap().get(file().path)?.status === "hashing"}>🔐 Hash {selectedHashAlgorithm().toUpperCase()}</button>
                    <Show when={info()?.raw && (info()!.raw!.segment_count > 1 || (info()?.companion_log?.segment_hashes?.length ?? 0) > 0)}>
                      <button class="action-btn-secondary" onClick={() => verifySegments(file())} disabled={busy() || fileStatusMap().get(file().path)?.status === "verifying-segments"} title="Hash and verify each segment individually">📊 Verify Segments</button>
                    </Show>
                    <Show when={!info()}><button class="action-btn-secondary" onClick={() => loadFileInfo(file(), true)} disabled={busy()}>ℹ️ Load Info</button></Show>
                  </div>
                </div>
              );
            }}
          </Show>
        </main>
      </div>
    </div>
  );
}

function formatBytes(value: number): string { if (!value) return "0 B"; const units = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1); return `${(value / Math.pow(1024, i)).toFixed(value / Math.pow(1024, i) < 10 ? 2 : 1)} ${units[i]}`; }
function normalizeError(err: unknown): string { if (!err) return "Unknown error"; if (typeof err === "string") return err; if (typeof err === "object" && "message" in err) return String((err as { message: string }).message); return JSON.stringify(err); }
function typeIcon(type: string): string { const t = type.toLowerCase(); if (t.includes("ad1")) return "📦"; if (t.includes("e01") || t.includes("encase")) return "💿"; if (t.includes("l01")) return "📋"; if (t.includes("raw") || t.includes("dd")) return "💾"; if (t.includes("tar")) return "📚"; return "📄"; }
function typeClass(type: string): string { const t = type.toLowerCase(); if (t.includes("ad1")) return "type-ad1"; if (t.includes("e01") || t.includes("encase")) return "type-e01"; if (t.includes("l01")) return "type-l01"; if (t.includes("raw") || t.includes("dd")) return "type-raw"; if (t.includes("tar")) return "type-tar"; return "type-other"; }

export default App;

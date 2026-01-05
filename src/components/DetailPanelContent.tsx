import { For, Show, createSignal, createEffect } from "solid-js";
import type { DiscoveredFile, ContainerInfo, TreeEntry, SegmentHashResult, HashHistoryEntry, HashAlgorithm, StoredHash } from "../types";
import type { FileStatus, FileHashInfo } from "../hooks";
import { formatBytes, typeIcon, typeClass, debounce, formatOffsetLabel } from "../utils";

interface DetailPanelContentProps {
  activeFile: DiscoveredFile | null;
  fileInfo: ContainerInfo | undefined;
  fileHash: FileHashInfo | undefined;
  fileStatus: FileStatus | undefined;
  tree: TreeEntry[];
  filteredTree: TreeEntry[];
  treeFilter: string;
  onTreeFilterChange: (filter: string) => void;
  selectedHashAlgorithm: HashAlgorithm;
  segmentResults: SegmentHashResult[];
  segmentVerifyProgress: { segment: string; percent: number; completed: number; total: number } | null;
  hashHistory: HashHistoryEntry[];
  storedHashes: StoredHash[];
  busy: boolean;
  onVerifySegments: () => void;
  onLoadInfo: () => void;
  formatHashDate: (timestamp: string) => string;
}

export function DetailPanelContent(props: DetailPanelContentProps) {
  // Local state for immediate input feedback, with debounced propagation
  const [localTreeFilter, setLocalTreeFilter] = createSignal(props.treeFilter);
  
  // Debounced filter update (150ms delay)
  const debouncedFilterChange = debounce((value: string) => {
    props.onTreeFilterChange(value);
  }, 150);
  
  // Sync local filter when prop changes (e.g., from external clear)
  createEffect(() => {
    setLocalTreeFilter(props.treeFilter);
  });
  
  const handleTreeFilterInput = (value: string) => {
    setLocalTreeFilter(value);
    debouncedFilterChange(value);
  };
  
  // Reactive helpers that properly track props changes
  const isHashing = () => props.fileStatus?.status === "hashing";
  const isVerifyingSegments = () => props.fileStatus?.status === "verifying-segments";
  const isIncomplete = () => (props.fileInfo?.ad1?.missing_segments?.length ?? 0) > 0;
  const currentProgress = () => props.fileStatus?.progress ?? 0;
  
  return (
    <main class="detail-panel">
      <Show 
        when={props.activeFile} 
        keyed
        fallback={
          <div class="empty-detail">
            <span class="empty-icon">📋</span>
            <p>Select a file to view details</p>
          </div>
        }
      >
        {(file) => {
          return (
            <div class="detail-content">
              {/* Header */}
              <div class="detail-header">
                <span class={`detail-type ${typeClass(file.container_type)}`}>
                  {typeIcon(file.container_type)} {file.container_type}
                </span>
                <h2 title={file.filename}>{file.filename}</h2>
                <p class="detail-path" title={file.path}>{file.path}</p>
              </div>
              
              {/* Stats row - prioritize acquisition dates over filesystem dates */}
              <div class="stat-row">
                <div class="stat-item">
                  <span class="stat-label">Size</span>
                  <span class="stat-value" title={`${file.size.toLocaleString()} bytes`}>{formatBytes(file.size)}</span>
                </div>
                <Show when={file.segment_count}>
                  <div class="stat-item">
                    <span class="stat-label">Segments</span>
                    <span class="stat-value" title={`${file.segment_count} segments`}>{file.segment_count}</span>
                  </div>
                </Show>
                
                {/* E01: Show acquisition date from header */}
                <Show when={props.fileInfo?.e01?.acquiry_date}>
                  <div class="stat-item">
                    <span class="stat-label">Acquired</span>
                    <span class="stat-value" title={`Acquisition date from E01 header: ${props.fileInfo!.e01!.acquiry_date}`}>{props.fileInfo!.e01!.acquiry_date}</span>
                  </div>
                </Show>
                
                {/* AD1: Show acquisition date from companion log */}
                <Show when={props.fileInfo?.ad1?.companion_log?.acquisition_date}>
                  <div class="stat-item">
                    <span class="stat-label">Acquired</span>
                    <span class="stat-value" title={`Acquisition date from AD1 companion log: ${props.fileInfo!.ad1!.companion_log!.acquisition_date}`}>{props.fileInfo!.ad1!.companion_log!.acquisition_date}</span>
                  </div>
                </Show>
                
                {/* UFED: Show extraction date */}
                <Show when={props.fileInfo?.ufed?.extraction_info?.start_time}>
                  <div class="stat-item">
                    <span class="stat-label">Extracted</span>
                    <span class="stat-value" title={`Extraction date from UFED metadata: ${props.fileInfo!.ufed!.extraction_info!.start_time}`}>{props.fileInfo!.ufed!.extraction_info!.start_time}</span>
                  </div>
                </Show>
                
                {/* Fallback to filesystem dates only if no container date */}
                <Show when={!props.fileInfo?.e01?.acquiry_date && !props.fileInfo?.ad1?.companion_log?.acquisition_date && !props.fileInfo?.ufed?.extraction_info?.start_time}>
                  <Show when={file.created}>
                    <div class="stat-item">
                      <span class="stat-label">File Created</span>
                      <span class="stat-value" title={`Filesystem date (when file was created on disk): ${file.created}`}>{file.created}</span>
                    </div>
                  </Show>
                  <Show when={file.modified}>
                    <div class="stat-item">
                      <span class="stat-label">File Modified</span>
                      <span class="stat-value" title={`Filesystem date (when file was last modified): ${file.modified}`}>{file.modified}</span>
                    </div>
                  </Show>
                </Show>
                
                <Show when={props.fileInfo?.ad1}>
                  <div class="stat-item">
                    <span class="stat-label">Items</span>
                    <span class="stat-value" title={`${props.fileInfo!.ad1!.item_count.toLocaleString()} items in AD1 container`}>{props.fileInfo!.ad1!.item_count.toLocaleString()}</span>
                  </div>
                </Show>
                <Show when={props.fileInfo?.e01}>
                  <div class="stat-item">
                    <span class="stat-label">Chunks</span>
                    <span class="stat-value" title={`${props.fileInfo!.e01!.chunk_count.toLocaleString()} compressed chunks`}>{props.fileInfo!.e01!.chunk_count.toLocaleString()}</span>
                  </div>
                  <div class="stat-item">
                    <span class="stat-label">Sectors</span>
                    <span class="stat-value" title={`${props.fileInfo!.e01!.sector_count.toLocaleString()} sectors`}>{props.fileInfo!.e01!.sector_count.toLocaleString()}</span>
                  </div>
                </Show>
              </div>
              
              {/* Hash progress */}
              <Show when={isHashing()}>
                <div class="hash-progress-section">
                  <div class="hash-progress-header">
                    <span>🔐 Hashing with {props.selectedHashAlgorithm.toUpperCase()}...</span>
                    <span class="hash-progress-percent">{currentProgress().toFixed(1)}%</span>
                  </div>
                  <div class="hash-progress-bar">
                    <div class="hash-progress-fill" style={{ width: `${currentProgress()}%` }} />
                  </div>
                </div>
              </Show>
              
              {/* Computed hash card */}
              <Show when={props.fileHash && !isHashing()}>
                <div class={`hash-card computed ${props.fileHash!.verified === true ? 'verified' : props.fileHash!.verified === false ? 'failed' : 'no-stored'}`}>
                  <div class="hash-header">
                    <span class="hash-algo-label">🔐 {props.fileHash!.algorithm}</span>
                    <Show when={props.fileHash!.verified === true}>
                      <span class="verify-status verified">
                        <span class="verify-icon-stacked"><span>✓</span><span>✓</span></span>
                        VERIFIED
                      </span>
                    </Show>
                    <Show when={props.fileHash!.verified === false}>
                      <span class="verify-status failed">✗ MISMATCH</span>
                    </Show>
                    <Show when={props.fileHash!.verified === null}>
                      <span class="verify-status neutral">✓ Computed</span>
                    </Show>
                    <button class="copy-btn" onClick={() => navigator.clipboard.writeText(props.fileHash!.hash)} title="Copy hash">📋</button>
                  </div>
                  <code class="hash-full">{props.fileHash!.hash}</code>
                  <Show when={props.fileHash!.verified === true && props.storedHashes.some(sh => sh.algorithm.toLowerCase() === props.fileHash!.algorithm.toLowerCase())}>
                    <div class="verification-detail">✓✓ Hash matches stored value from container/companion</div>
                  </Show>
                  <Show when={props.fileHash!.verified === true && !props.storedHashes.some(sh => sh.algorithm.toLowerCase() === props.fileHash!.algorithm.toLowerCase())}>
                    <div class="verification-detail">✓✓ Hash matches previous computation (self-verified)</div>
                  </Show>
                  <Show when={props.fileHash!.verified === false}>
                    <div class="verification-detail error">⚠️ Computed hash does NOT match stored hash!</div>
                  </Show>
                  <Show when={props.fileHash!.verified === null && props.hashHistory.length === 0}>
                    <div class="verification-detail neutral">No stored hash or history to verify against</div>
                  </Show>
                </div>
              </Show>
              
              {/* Hash history - shows all computed hashes for this session */}
              <Show when={props.hashHistory.length > 0}>
                <div class="compact-section hash-history-section">
                  <div class="section-header-compact">
                    <span class="section-title">🕒 Hash History ({props.hashHistory.length})</span>
                  </div>
                  <div class="hash-history-list">
                    <For each={props.hashHistory.slice().reverse()}>
                      {(entry) => (
                        <div class={`history-row ${entry.verified === true ? 'verified' : entry.verified === false ? 'failed' : ''}`}>
                          <span class="hist-time">{entry.timestamp.toLocaleTimeString()}</span>
                          <span class="hist-algo">{entry.algorithm}</span>
                          <span class="hist-source">{entry.source}</span>
                          <code class="hist-hash">{entry.hash}</code>
                          <Show when={entry.verified === true}><span class="hist-badge ok">✓</span></Show>
                          <Show when={entry.verified === false}><span class="hist-badge fail">✗</span></Show>
                          <button class="hist-copy" onClick={() => navigator.clipboard.writeText(entry.hash)} title="Copy">📋</button>
                        </div>
                      )}
                    </For>
                  </div>
                </div>
              </Show>
              
              {/* Segment hashes from companion log */}
              <Show when={(props.fileInfo?.companion_log?.segment_hashes?.length ?? 0) > 0}>
                <div class="compact-section segment-hashes-section">
                  <div class="section-header-compact">
                    <span class="section-title">📊 Per-Segment Hashes ({props.fileInfo!.companion_log!.segment_hashes.length})</span>
                    <button 
                      class="verify-segments-btn" 
                      onClick={props.onVerifySegments} 
                      disabled={props.busy || isVerifyingSegments() || isIncomplete()}
                      title={isIncomplete() ? "Cannot verify: missing segments" : "Verify each segment against stored hash"}
                    >
                      {isIncomplete() ? '⚠️ Incomplete' : '🔍 Verify Segments'}
                    </button>
                  </div>
                  <div class="segment-hash-list">
                    <For each={props.fileInfo!.companion_log!.segment_hashes}>
                      {(sh) => {
                        const computed = () => props.segmentResults.find(r => r.segment_name.toLowerCase() === sh.segment_name.toLowerCase());
                        return (
                          <div class={`segment-hash-row ${computed()?.verified === true ? 'verified' : computed()?.verified === false ? 'failed' : ''}`}>
                            <span class="seg-name" title={sh.segment_name}>{sh.segment_name}</span>
                            <span class="seg-algo">{sh.algorithm}</span>
                            <code class="seg-hash" title={sh.hash}>{sh.hash.substring(0, 16)}...</code>
                            <Show when={sh.size}><span class="seg-size">{formatBytes(sh.size!)}</span></Show>
                            <Show when={computed()?.verified === true}><span class="seg-badge ok">✓</span></Show>
                            <Show when={computed()?.verified === false}><span class="seg-badge fail">✗</span></Show>
                            <button class="seg-copy" onClick={() => navigator.clipboard.writeText(sh.hash)} title="Copy">📋</button>
                          </div>
                        );
                      }}
                    </For>
                  </div>
                </div>
              </Show>
              
              {/* Computed segment results (when no companion log) */}
              <Show when={props.segmentResults.length > 0 && !(props.fileInfo?.companion_log?.segment_hashes?.length)}>
                <div class="compact-section computed-segments-section">
                  <div class="section-title">📊 Computed Segment Hashes</div>
                  <div class="segment-hash-list">
                    <For each={props.segmentResults}>
                      {(sr) => (
                        <div class={`segment-hash-row ${sr.verified === true ? 'verified' : sr.verified === false ? 'failed' : ''}`}>
                          <span class="seg-name" title={sr.segment_name}>{sr.segment_name}</span>
                          <span class="seg-algo">{sr.algorithm}</span>
                          <code class="seg-hash" title={sr.computed_hash}>{sr.computed_hash.substring(0, 16)}...</code>
                          <span class="seg-size">{formatBytes(sr.size)}</span>
                          <span class="seg-time">{sr.duration_secs.toFixed(1)}s</span>
                          <Show when={sr.verified === true}><span class="seg-badge ok">✓</span></Show>
                          <Show when={sr.verified === false}><span class="seg-badge fail">✗</span></Show>
                          <button class="seg-copy" onClick={() => navigator.clipboard.writeText(sr.computed_hash)} title="Copy">📋</button>
                        </div>
                      )}
                    </For>
                  </div>
                </div>
              </Show>
              
              {/* Segment verification progress */}
              <Show when={props.segmentVerifyProgress && isVerifyingSegments()}>
                <div class="segment-progress-section">
                  <div class="segment-progress-header">
                    <span>🔍 Verifying {props.segmentVerifyProgress!.segment}...</span>
                    <span>{props.segmentVerifyProgress!.completed}/{props.segmentVerifyProgress!.total}</span>
                  </div>
                  <div class="segment-progress-bar">
                    <div class="segment-progress-fill" style={{ width: `${props.segmentVerifyProgress!.percent}%` }} />
                  </div>
                </div>
              </Show>
              
              {/* Container details - includes stored hashes */}
              <Show when={props.fileInfo}>
                <ContainerDetails info={props.fileInfo!} storedHashes={props.storedHashes} />
              </Show>
              
              {/* File tree */}
              <Show when={props.tree.length > 0}>
                <div class="compact-section">
                  <div class="section-header-compact">
                    <span class="section-title">📁 File Tree ({props.tree.length})</span>
                    <input 
                      type="text" 
                      class="tree-filter-sm" 
                      placeholder="Filter..." 
                      value={localTreeFilter()} 
                      onInput={(e) => handleTreeFilterInput(e.currentTarget.value)} 
                    />
                  </div>
                  <div class="tree-list-compact">
                    <For each={props.filteredTree}>
                      {(entry) => (
                        <div class={`tree-row ${entry.is_dir ? "dir" : "file"}`} title={entry.path}>
                          <span class="tree-icon">{entry.is_dir ? "📁" : "📄"}</span>
                          <span class="tree-path" title={entry.path}>{entry.path}</span>
                          <span class="tree-size">{entry.is_dir ? "" : formatBytes(entry.size)}</span>
                        </div>
                      )}
                    </For>
                    <Show when={props.tree.length > 500}>
                      <div class="tree-truncated">Showing first 500 of {props.tree.length} items</div>
                    </Show>
                  </div>
                </div>
              </Show>
              
              {/* Action buttons */}
              <div class="detail-actions-compact">
                <Show when={props.fileInfo?.raw && (props.fileInfo!.raw!.segment_count > 1 || (props.fileInfo?.companion_log?.segment_hashes?.length ?? 0) > 0)}>
                  <button 
                    class="action-btn-secondary" 
                    onClick={props.onVerifySegments} 
                    disabled={props.busy || isVerifyingSegments()} 
                    title="Hash and verify each segment individually"
                  >
                    📊 Verify Segments
                  </button>
                </Show>
                <Show when={!props.fileInfo}>
                  <button 
                    class="action-btn-secondary" 
                    onClick={props.onLoadInfo} 
                    disabled={props.busy}
                  >
                    ℹ️ Load Info
                  </button>
                </Show>
              </div>
            </div>
          );
        }}
      </Show>
    </main>
  );
}

// Container details sub-component
// ============================================================================
// Common Info Row Component - Single source of truth for rendering detail rows
// ============================================================================

type RowType = 'normal' | 'highlight' | 'device' | 'full-width' | 'hash' | 'warning';
type RowFormat = 'text' | 'bytes' | 'mono' | 'notes' | 'list' | 'warning';

interface InfoField {
  label: string;
  value: string | number | undefined | null;
  type?: RowType;
  format?: RowFormat;
  condition?: boolean; // Override automatic truthy check
}

// Renders a single info row with consistent styling
function InfoRow(props: InfoField) {
  // Skip if no value (unless condition explicitly set)
  const shouldShow = () => {
    if (props.condition !== undefined) return props.condition;
    return props.value !== undefined && props.value !== null && props.value !== '';
  };
  
  const formatValue = () => {
    const val = props.value;
    if (val === undefined || val === null) return '';
    if (props.format === 'bytes' && typeof val === 'number') return formatBytes(val);
    return String(val);
  };
  
  const rowClass = () => {
    const classes = ['info-row'];
    if (props.type === 'highlight') classes.push('highlight');
    if (props.type === 'device') classes.push('device');
    if (props.type === 'full-width') classes.push('full-width');
    if (props.type === 'hash') classes.push('hash-row');
    if (props.type === 'warning' || props.format === 'warning') classes.push('warning-row');
    return classes.join(' ');
  };
  
  const valueClass = () => {
    const classes = ['info-value'];
    if (props.format === 'mono') classes.push('mono', 'small');
    if (props.format === 'notes') classes.push('notes');
    if (props.format === 'list') classes.push('seg-list');
    if (props.type === 'hash') classes.push('mono', 'hash-value');
    if (props.format === 'warning') classes.push('warning-text');
    return classes.join(' ');
  };
  
  return (
    <Show when={shouldShow()}>
      <div class={rowClass()}>
        <span class="info-label">{props.label}</span>
        <span class={valueClass()}>{formatValue()}</span>
      </div>
    </Show>
  );
}

// Renders multiple info rows from a field array
function InfoRows(props: { fields: InfoField[] }) {
  return (
    <For each={props.fields}>
      {(field) => <InfoRow {...field} />}
    </For>
  );
}

// ============================================================================
// Normalize container info to common field structure
// ============================================================================

function normalizeContainerFields(info: ContainerInfo, storedHashes: StoredHash[]): InfoField[] {
  const fields: InfoField[] = [];
  
  // AD1
  if (info.ad1) {
    const ad1 = info.ad1;
    const log = ad1.companion_log;
    const vol = ad1.volume;
    
    // Show warning if segments are missing
    if (ad1.missing_segments && ad1.missing_segments.length > 0) {
      fields.push({
        label: '⚠️ Incomplete',
        value: `Missing ${ad1.missing_segments.length} segment(s): ${ad1.missing_segments.join(', ')}`,
        type: 'full-width',
        format: 'warning'
      });
    }
    
    fields.push(
      { label: 'Format', value: `AD1 (${ad1.logical.signature})` },
      { label: 'Version', value: ad1.logical.image_version },
      { label: 'Segments', value: `${ad1.segment_files?.length ?? 0} / ${ad1.segment.segment_number}${ad1.missing_segments?.length ? ' (incomplete)' : ''}` },
      { label: 'Total Size', value: ad1.total_size, format: 'bytes' },
      { label: 'Items', value: ad1.item_count },
      // Case metadata from companion log
      { label: 'Case #', value: log?.case_number, type: 'highlight' },
      { label: 'Evidence #', value: log?.evidence_number, type: 'highlight' },
      { label: 'Examiner', value: log?.examiner },
      { label: 'Acquired', value: log?.acquisition_date },
      // Volume/system info from header
      { label: 'Volume', value: vol?.volume_label },
      { label: 'Filesystem', value: vol?.filesystem },
      { label: 'OS', value: vol?.os_info },
      { label: 'Block Size', value: vol?.block_size, format: 'bytes' },
      // Technical details
      { label: 'Chunk Size', value: ad1.logical.zlib_chunk_size, format: 'bytes' },
      { label: 'Source', value: ad1.logical.data_source_name, type: 'full-width' },
      // Notes (hashes now displayed via storedHashes at end)
      { label: 'Notes', value: log?.notes, type: 'full-width', format: 'notes' },
    );
  }
  
  // E01
  if (info.e01) {
    const e01 = info.e01;
    fields.push(
      { label: 'Format', value: e01.format_version },
      { label: 'Segments', value: e01.segment_count },
      { label: 'Total Size', value: e01.total_size, format: 'bytes' },
      { label: 'Compression', value: e01.compression },
      { label: 'Bytes/Sector', value: e01.bytes_per_sector },
      { label: 'Sectors/Chunk', value: e01.sectors_per_chunk },
      { label: 'Case #', value: e01.case_number, type: 'highlight' },
      { label: 'Evidence #', value: e01.evidence_number, type: 'highlight' },
      { label: 'Examiner', value: e01.examiner_name },
      { label: 'Acquired', value: e01.acquiry_date },
      { label: 'System Date', value: e01.system_date },
      { label: 'Model', value: e01.model, type: 'device' },
      { label: 'Serial #', value: e01.serial_number, type: 'device' },
      { label: 'Description', value: e01.description, type: 'full-width' },
      { label: 'Notes', value: e01.notes, type: 'full-width', format: 'notes' },
      // Stored hashes now displayed via storedHashes at end
    );
  }
  
  // L01 (Logical Evidence - uses same EwfInfo type as E01)
  if (info.l01) {
    const l01 = info.l01;
    fields.push(
      { label: 'Format', value: l01.format_version },
      { label: 'Segments', value: l01.segment_count },
      { label: 'Total Size', value: l01.total_size, format: 'bytes' },
      { label: 'Compression', value: l01.compression },
      { label: 'Bytes/Sector', value: l01.bytes_per_sector },
      { label: 'Sectors/Chunk', value: l01.sectors_per_chunk },
      { label: 'Case #', value: l01.case_number, type: 'highlight' },
      { label: 'Evidence #', value: l01.evidence_number, type: 'highlight' },
      { label: 'Examiner', value: l01.examiner_name },
      { label: 'Acquired', value: l01.acquiry_date },
      { label: 'System Date', value: l01.system_date },
      { label: 'Model', value: l01.model, type: 'device' },
      { label: 'Serial #', value: l01.serial_number, type: 'device' },
      { label: 'Description', value: l01.description, type: 'full-width' },
      { label: 'Notes', value: l01.notes, type: 'full-width', format: 'notes' },
    );
  }
  
  // Raw
  if (info.raw) {
    const raw = info.raw;
    fields.push(
      { label: 'Format', value: 'Raw Image' },
      { label: 'Segments', value: raw.segment_count },
      { label: 'Total Size', value: raw.total_size, format: 'bytes' },
    );
    if (raw.segment_count > 1) {
      const segList = raw.segment_names.slice(0, 5).join(', ') + 
        (raw.segment_count > 5 ? ` (+${raw.segment_count - 5} more)` : '');
      fields.push({ label: 'Segment Files', value: segList, type: 'full-width', format: 'list' });
    }
  }
  
  // Archive (ZIP/7z)
  if (info.archive) {
    const archive = info.archive;
    fields.push(
      { label: 'Format', value: `${archive.format}${archive.version ? ` v${archive.version}` : ''}` },
      { label: 'Segments', value: archive.segment_count },
      { label: 'Total Size', value: archive.total_size, format: 'bytes' },
      { label: 'Entries', value: archive.entry_count },
      { label: 'AES Encrypted', value: archive.aes_encrypted ? 'Yes' : undefined, type: 'highlight' },
      { label: 'Encrypted Headers', value: archive.encrypted_headers ? 'Filenames Hidden' : undefined, type: 'highlight' },
    );
    if (archive.start_header_crc_valid !== undefined && archive.start_header_crc_valid !== null) {
      fields.push({ 
        label: 'Header CRC', 
        value: archive.start_header_crc_valid ? '✓ Valid' : '✗ Invalid',
        type: archive.start_header_crc_valid ? 'normal' : 'highlight',
        condition: true 
      });
    }
    fields.push(
      { label: 'Central Dir', value: archive.central_dir_offset ? `@ ${archive.central_dir_offset.toLocaleString()}` : undefined },
      { label: 'Next Header', value: archive.next_header_offset ? formatOffsetLabel(archive.next_header_offset) : undefined },
    );
    if (archive.segment_count > 1) {
      const segList = archive.segment_names.slice(0, 5).join(', ') + 
        (archive.segment_count > 5 ? ` (+${archive.segment_count - 5} more)` : '');
      fields.push({ label: 'Segment Files', value: segList, type: 'full-width', format: 'list' });
    }
  }
  
  // UFED (Cellebrite)
  if (info.ufed) {
    const ufed = info.ufed;
    const allFiles: string[] = [...ufed.associated_files.map(f => f.filename)];
    if (ufed.collection_info?.ufdx_path) {
      const ufdxName = ufed.collection_info.ufdx_path.split('/').pop() || ufed.collection_info.ufdx_path.split('\\').pop();
      if (ufdxName && !allFiles.includes(ufdxName)) allFiles.push(ufdxName);
    }
    
    fields.push(
      { label: 'Format', value: `UFED (${ufed.format})` },
      { label: 'Total Size', value: ufed.size, format: 'bytes' },
      { label: 'Extraction', value: ufed.extraction_info?.extraction_type },
      { label: 'Tool', value: ufed.extraction_info?.acquisition_tool ? 
        `${ufed.extraction_info.acquisition_tool}${ufed.extraction_info.tool_version ? ` v${ufed.extraction_info.tool_version}` : ''}` : undefined },
      { label: 'Case #', value: ufed.case_info?.case_identifier, type: 'highlight' },
      { label: 'Evidence #', value: ufed.case_info?.device_name || ufed.evidence_number, type: 'highlight' },
      { label: 'Examiner', value: ufed.case_info?.examiner_name },
      { label: 'Acquired', value: ufed.extraction_info?.start_time },
      { label: 'Completed', value: ufed.extraction_info?.end_time },
      { label: 'Device', value: ufed.device_info?.full_name || ufed.device_hint, type: 'device' },
      { label: 'Model', value: ufed.device_info?.model, type: 'device' },
      { label: 'Serial #', value: ufed.device_info?.serial_number, type: 'device' },
      { label: 'IMEI', value: ufed.device_info?.imei ? 
        `${ufed.device_info.imei}${ufed.device_info.imei2 ? ` / ${ufed.device_info.imei2}` : ''}` : undefined, type: 'device' },
      { label: 'OS', value: ufed.device_info?.os_version ? 
        `${ufed.device_info.vendor ? `${ufed.device_info.vendor} ` : ''}${ufed.device_info.os_version}` : undefined, type: 'device' },
      { label: 'Connection', value: ufed.extraction_info?.connection_type, type: 'full-width' },
      { label: 'Location', value: ufed.case_info?.location, type: 'full-width' },
      { label: 'GUID', value: ufed.extraction_info?.guid, type: 'full-width', format: 'mono' },
      { label: 'Files', value: allFiles.length > 0 ? allFiles.join(', ') : undefined, type: 'full-width' },
    );
  }
  
  // Companion log
  if (info.companion_log) {
    const log = info.companion_log;
    fields.push(
      { label: 'Created By', value: log.created_by },
      { label: 'Case #', value: log.case_number, type: 'highlight' },
      { label: 'Evidence #', value: log.evidence_number, type: 'highlight' },
      { label: 'Examiner', value: log.examiner },
      { label: 'Acquired', value: log.acquisition_started },
      { label: 'Source', value: log.unique_description, type: 'full-width' },
      { label: 'Notes', value: log.notes, type: 'full-width', format: 'notes' },
    );
  }
  
  // Add all stored hashes (unified display for all container types)
  if (storedHashes && storedHashes.length > 0) {
    for (const sh of storedHashes) {
      const algo = sh.algorithm?.toUpperCase() || 'HASH';
      const hash = sh.hash || '';
      const sourceIcon = sh.source === 'container' ? '📦' : sh.source === 'companion' ? '📄' : '💻';
      const verifyIcon = sh.verified === true ? ' ✓' : sh.verified === false ? ' ✗' : '';
      // Show filename if available (UFED has per-file hashes)
      const filenameLabel = sh.filename ? ` (${sh.filename})` : '';
      fields.push({ 
        label: `${sourceIcon} ${algo}${verifyIcon}${filenameLabel}`, 
        value: hash, 
        type: 'hash' 
      });
    }
  }
  
  return fields;
}

// ============================================================================
// Container Details Component - Uses common template
// ============================================================================

function ContainerDetails(props: { info: ContainerInfo; storedHashes: StoredHash[] }) {
  const fields = () => normalizeContainerFields(props.info, props.storedHashes);
  
  return (
    <div class="compact-section">
      <div class="section-title">📋 Container Details</div>
      <div class="info-compact">
        <InfoRows fields={fields()} />
      </div>
    </div>
  );
}


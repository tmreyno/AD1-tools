import { Show } from "solid-js";
import type { DiscoveredFile, ContainerInfo, HashHistoryEntry } from "../types";
import type { FileStatus, FileHashInfo } from "../hooks";
import { formatBytes, typeIcon, typeClass } from "../utils";

interface FileRowProps {
  file: DiscoveredFile;
  index: number;
  isSelected: boolean;
  isActive: boolean;
  isFocused: boolean;
  isHovered: boolean;
  fileStatus: FileStatus | undefined;
  fileInfo: ContainerInfo | undefined;
  fileHash: FileHashInfo | undefined;
  hashHistory: HashHistoryEntry[];
  busy: boolean;
  onSelect: () => void;
  onToggleSelection: () => void;
  onHash: () => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}

export function FileRow(props: FileRowProps) {
  // Check if container is incomplete (missing segments)
  const isIncomplete = () => (props.fileInfo?.ad1?.missing_segments?.length ?? 0) > 0;
  
  // Get total container size (all segments combined) when available
  const totalContainerSize = () => {
    const info = props.fileInfo;
    if (info?.ad1?.total_size) return info.ad1.total_size;
    if (info?.e01?.total_size) return info.e01.total_size;
    if (info?.l01?.total_size) return info.l01.total_size;
    if (info?.raw?.total_size) return info.raw.total_size;
    if (info?.archive?.total_size) return info.archive.total_size;
    return null;
  };
  
  // Display size: use total container size if available, otherwise first segment size
  const displaySize = () => totalContainerSize() ?? props.file.size;
  const hasMultipleSegments = () => (props.file.segment_count ?? 1) > 1;
  const sizeLabel = () => {
    const total = totalContainerSize();
    if (total && hasMultipleSegments()) {
      return `Total: ${formatBytes(total)} (${props.file.segment_count} segments, first segment: ${formatBytes(props.file.size)})`;
    }
    return `${formatBytes(displaySize())}`;
  };
  
  // Unified hash indicator logic
  const storedHashCount = () => (props.fileInfo?.e01?.stored_hashes?.length ?? 0) + (props.fileInfo?.companion_log?.stored_hashes?.length ?? 0);
  const historyCount = () => props.hashHistory?.length ?? 0;
  const totalHashCount = () => storedHashCount() + (props.fileHash ? 1 : 0) + historyCount();
  const isHashing = () => props.fileStatus?.status === "hashing" && !props.fileHash && (props.fileStatus?.progress ?? 0) < 95;
  const isCompleting = () => props.fileStatus?.status === "hashing" && (props.fileStatus?.progress ?? 0) >= 95 && !props.fileHash;
  const hashProgress = () => props.fileStatus?.progress ?? 0;
  const chunksProcessed = () => props.fileStatus?.chunksProcessed;
  const chunksTotal = () => props.fileStatus?.chunksTotal;
  const hasChunkProgress = () => chunksTotal() !== undefined && chunksTotal()! > 0 && hashProgress() < 100;
  
  // Format chunk progress for display
  const formatChunks = (count: number) => {
    if (count >= 1000000) return `${(count / 1000000).toFixed(1)}M`;
    if (count >= 1000) return `${(count / 1000).toFixed(0)}k`;
    return count.toString();
  };
  
  // Check if any hash matches exist (stored vs history, or history vs history)
  const hasVerifiedMatch = () => {
    const storedHashes = [
      ...(props.fileInfo?.e01?.stored_hashes ?? []), 
      ...(props.fileInfo?.ufed?.stored_hashes ?? []),
      ...(props.fileInfo?.companion_log?.stored_hashes ?? [])
    ];
    const history = props.hashHistory ?? [];
    
    // Check if any stored hash matches any history hash
    for (const stored of storedHashes) {
      const match = history.find(h => 
        h.algorithm.toLowerCase() === stored.algorithm.toLowerCase() && 
        h.hash.toLowerCase() === stored.hash.toLowerCase()
      );
      if (match) return true;
    }
    
    // Check if any history entries match each other (same algorithm, same hash, different times)
    for (let i = 0; i < history.length; i++) {
      for (let j = i + 1; j < history.length; j++) {
        if (history[i].algorithm.toLowerCase() === history[j].algorithm.toLowerCase() &&
            history[i].hash.toLowerCase() === history[j].hash.toLowerCase()) {
          return true;
        }
      }
    }
    
    return false;
  };
  
  // Determine hash state
  const hashState = () => {
    // Check for incomplete container first
    if (isIncomplete()) return "incomplete";
    const hash = props.fileHash;
    if (hash?.verified === true) return "verified";
    if (hash?.verified === false) return "failed";
    if (hash) return "computed";
    // Check for verified matches even without current fileHash
    if (hasVerifiedMatch()) return "verified";
    if (storedHashCount() > 0) return "stored";
    if (historyCount() > 0) return "computed"; // Has history but no stored to verify against
    return "none";
  };

  return (
    <div 
      class={`file-row ${props.isSelected ? "selected" : ""} ${props.isActive ? "active" : ""} ${props.isFocused ? "focused" : ""}`} 
      onMouseEnter={props.onMouseEnter} 
      onMouseLeave={props.onMouseLeave} 
      onClick={props.onSelect}
      data-index={props.index}
    >
      <input 
        type="checkbox" 
        checked={props.isSelected} 
        onChange={(e) => { e.stopPropagation(); props.onToggleSelection(); }} 
        onClick={(e) => e.stopPropagation()} 
      />
      
      <span class={`type-icon ${typeClass(props.file.container_type)}`} title={props.file.container_type}>
        {typeIcon(props.file.container_type)}
      </span>
      
      <div class="file-info">
        <span class="file-name" title={props.file.path}>{props.file.filename}</span>
        <span class="file-meta">
          <span title={sizeLabel()}>{formatBytes(displaySize())}</span>
          <Show when={props.file.segment_count && props.file.segment_count > 1}>
            <span class="seg-count">• {props.file.segment_count} segs</span>
          </Show>
        </span>
      </div>
      
      <div class="file-actions">
        <Show when={props.fileInfo?.ad1?.item_count}>
          <span class="item-count-badge" title={`${props.fileInfo!.ad1!.item_count.toLocaleString()} items`}>
            📁{props.fileInfo!.ad1!.item_count > 999 ? Math.round(props.fileInfo!.ad1!.item_count / 1000) + "k" : props.fileInfo!.ad1!.item_count}
          </span>
        </Show>
        
        {/* Hash Indicators - Icon button with overlay badge */}
        <Show when={isHashing()}>
          <span 
            class="hash-indicator hashing" 
            title={hasChunkProgress()
              ? `Hashing... ${hashProgress().toFixed(0)}%\nDecompressing: ${formatChunks(chunksProcessed() ?? 0)}/${formatChunks(chunksTotal() ?? 0)} chunks`
              : `Hashing... ${hashProgress().toFixed(0)}%`
            }
          >
            <span class="hash-status">{hashProgress().toFixed(0)}%</span>
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
              <Show when={totalHashCount() > 0}>
                <span class="hash-badge">{totalHashCount()}</span>
              </Show>
            </span>
          </span>
        </Show>
        
        {/* Completing state - 100% but hash result not yet received */}
        <Show when={isCompleting()}>
          <span class="hash-indicator completing" title="Finalizing hash...">
            <span class="hash-status">✓</span>
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
              <Show when={totalHashCount() > 0}>
                <span class="hash-badge">{totalHashCount()}</span>
              </Show>
            </span>
          </span>
        </Show>
        
        <Show when={!isHashing() && !isCompleting() && hashState() === "verified"}>
          <button 
            class="hash-indicator verified clickable" 
            onClick={(e) => { e.stopPropagation(); props.onHash(); }} 
            disabled={props.busy} 
            title={`✓✓ VERIFIED: Hash matches ${props.fileHash ? "stored hash" : "in history"}\n${totalHashCount()} hash(es) • Click to re-hash`}
          >
            <span class="hash-status stacked-checks"><span class="check-1">✓</span><span class="check-2">✓</span></span>
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
              <span class="hash-badge">{totalHashCount()}</span>
            </span>
          </button>
        </Show>
        
        <Show when={!isHashing() && !isCompleting() && hashState() === "failed"}>
          <button 
            class="hash-indicator failed clickable" 
            onClick={(e) => { e.stopPropagation(); props.onHash(); }} 
            disabled={props.busy} 
            title={`✗ MISMATCH: ${props.fileHash?.algorithm ?? "hash"} does NOT match stored hash\n${totalHashCount()} hash(es) • Click to re-hash`}
          >
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
              <span class="hash-badge fail">{totalHashCount()}</span>
            </span>
          </button>
        </Show>
        
        <Show when={!isHashing() && !isCompleting() && hashState() === "computed"}>
          <button 
            class="hash-indicator computed clickable" 
            onClick={(e) => { e.stopPropagation(); props.onHash(); }} 
            disabled={props.busy} 
            title={`✓ Computed: ${props.fileHash?.algorithm ?? "hash"} (no stored hash to verify against)\n${totalHashCount()} hash(es) • Click to re-hash`}
          >
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
              <span class="hash-badge">{totalHashCount()}</span>
            </span>
          </button>
        </Show>
        
        <Show when={!isHashing() && !isCompleting() && hashState() === "incomplete"}>
          <span 
            class="hash-indicator incomplete" 
            title={`⚠️ Incomplete: Missing ${props.fileInfo?.ad1?.missing_segments?.length ?? 0} segment(s)\nCannot hash - segments are missing`}
          >
            <span class="hash-status">⚠</span>
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
            </span>
          </span>
        </Show>
        
        <Show when={!isHashing() && !isCompleting() && hashState() === "stored"}>
          <button 
            class="hash-indicator stored clickable" 
            onClick={(e) => { e.stopPropagation(); props.onHash(); }} 
            disabled={props.busy} 
            title={`${storedHashCount()} stored hash(es) • Click to verify`}
          >
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
              <span class="hash-badge">{storedHashCount()}</span>
            </span>
          </button>
        </Show>
        
        <Show when={!isHashing() && !isCompleting() && hashState() === "none"}>
          <button 
            class="hash-indicator none clickable" 
            onClick={(e) => { e.stopPropagation(); props.onHash(); }} 
            disabled={props.busy} 
            title="Click to hash this file"
          >
            <span class="hash-icon-wrap">
              <span class="hash-icon">#</span>
            </span>
          </button>
        </Show>
      </div>
      
      {/* Tooltip on hover */}
      <Show when={props.isHovered && !props.isActive}>
        <FileTooltip 
          file={props.file} 
          fileInfo={props.fileInfo} 
          fileHash={props.fileHash} 
        />
      </Show>
    </div>
  );
}

interface FileTooltipProps {
  file: DiscoveredFile;
  fileInfo: ContainerInfo | undefined;
  fileHash: FileHashInfo | undefined;
}

function FileTooltip(props: FileTooltipProps) {
  return (
    <div class="file-tooltip">
      <div class="tooltip-header">{props.file.container_type}</div>
      <div class="tooltip-path">{props.file.path}</div>
      <div class="tooltip-row"><span>Size:</span><span>{formatBytes(props.file.size)}</span></div>
      
      <Show when={props.file.segment_count}>
        <div class="tooltip-row"><span>Segments:</span><span>{props.file.segment_count}</span></div>
      </Show>
      
      <Show when={props.fileInfo}>
        <div class="tooltip-divider" />
        
        <Show when={props.fileInfo!.ad1}>
          <div class="tooltip-row"><span>Items:</span><span>{props.fileInfo!.ad1!.item_count}</span></div>
          <Show when={props.fileInfo!.ad1!.companion_log?.case_number}>
            <div class="tooltip-row"><span>Case:</span><span>{props.fileInfo!.ad1!.companion_log!.case_number}</span></div>
          </Show>
          <Show when={props.fileInfo!.ad1!.companion_log?.evidence_number}>
            <div class="tooltip-row"><span>Evidence:</span><span>{props.fileInfo!.ad1!.companion_log!.evidence_number}</span></div>
          </Show>
          <Show when={props.fileInfo!.ad1!.volume?.filesystem}>
            <div class="tooltip-row"><span>FS:</span><span>{props.fileInfo!.ad1!.volume!.filesystem}</span></div>
          </Show>
          <div class="tooltip-row"><span>Source:</span><span>{props.fileInfo!.ad1!.logical.data_source_name}</span></div>
        </Show>
        
        <Show when={props.fileInfo!.e01}>
          <div class="tooltip-row"><span>Format:</span><span>{props.fileInfo!.e01!.format_version}</span></div>
          <div class="tooltip-row"><span>Compression:</span><span>{props.fileInfo!.e01!.compression}</span></div>
          <Show when={props.fileInfo!.e01!.case_number}>
            <div class="tooltip-row"><span>Case:</span><span>{props.fileInfo!.e01!.case_number}</span></div>
          </Show>
        </Show>
        
        <Show when={props.fileInfo!.raw}>
          <div class="tooltip-row"><span>Segments:</span><span>{props.fileInfo!.raw!.segment_count}</span></div>
        </Show>
        
        <Show when={(props.fileInfo?.e01?.stored_hashes?.length ?? 0) > 0 || (props.fileInfo?.companion_log?.stored_hashes?.length ?? 0) > 0}>
          <div class="tooltip-divider" />
          <div class="tooltip-section-title">📜 Stored Hashes</div>
          
          <Show when={(props.fileInfo?.e01?.stored_hashes?.length ?? 0) > 0}>
            {props.fileInfo!.e01!.stored_hashes!.map((sh) => (
              <div class="tooltip-hash-row">
                <span class="tooltip-hash-algo">{sh.algorithm}</span>
                <code class="tooltip-hash-val">{sh.hash.substring(0, 16)}...</code>
                <Show when={sh.verified === true}><span class="tooltip-verified">✓</span></Show>
                <Show when={sh.timestamp}><span class="tooltip-date">{sh.timestamp}</span></Show>
              </div>
            ))}
          </Show>
          
          <Show when={(props.fileInfo?.companion_log?.stored_hashes?.length ?? 0) > 0}>
            {props.fileInfo!.companion_log!.stored_hashes.map((sh) => (
              <div class="tooltip-hash-row">
                <span class="tooltip-hash-algo">{sh.algorithm}</span>
                <code class="tooltip-hash-val">{sh.hash.substring(0, 16)}...</code>
                <Show when={sh.verified === true}><span class="tooltip-verified">✓</span></Show>
                <Show when={sh.timestamp}><span class="tooltip-date">{sh.timestamp}</span></Show>
              </div>
            ))}
          </Show>
        </Show>
      </Show>
      
      <Show when={props.fileHash}>
        <div class="tooltip-divider" />
        <div class="tooltip-hash">
          <span class="hash-algo">🔐 {props.fileHash!.algorithm}</span>
          <code>{props.fileHash!.hash}</code>
        </div>
      </Show>
    </div>
  );
}

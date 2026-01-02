import { createSignal, createEffect, For, Show, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import type { DiscoveredFile } from "../types";

// --- Types from viewer.rs ---

interface FileChunk {
  bytes: number[];
  offset: number;
  total_size: number;
  has_more: boolean;
  has_prev: boolean;
}

interface HeaderRegion {
  start: number;
  end: number;
  name: string;
  color_class: string;  // CSS class name for coloring
  description: string;
}

interface MetadataField {
  key: string;
  value: string;
  category: string;
}

interface ParsedMetadata {
  format: string;
  version: string | null;
  fields: MetadataField[];
  regions: HeaderRegion[];
}

interface FileTypeInfo {
  mime_type: string | null;
  description: string;
  extension: string;
  is_text: boolean;
  is_forensic_format: boolean;
  magic_hex: string;
}

// --- Constants ---
const BYTES_PER_LINE = 16;
const DEFAULT_CHUNK_SIZE = 4096; // 256 lines
const MIN_CHUNK_SIZE = 256;
const MAX_CHUNK_SIZE = 65536;

// Map color classes to actual colors
const COLOR_MAP: Record<string, string> = {
  "region-signature": "#ef4444",    // Red - file signatures
  "region-header": "#f97316",       // Orange - headers
  "region-segment": "#f97316",      // Orange - segments
  "region-metadata": "#eab308",     // Yellow - metadata
  "region-data": "#22c55e",         // Green - data sections
  "region-checksum": "#3b82f6",     // Blue - checksums
  "region-reserved": "#8b5cf6",     // Purple - reserved
  "region-footer": "#ec4899",       // Pink - footers
};

// Helper to get actual color from color_class
function getRegionColor(colorClass: string): string {
  return COLOR_MAP[colorClass] || "#6a6a7a";
}

// --- Helper Functions ---

function formatOffset(offset: number, width: number = 8): string {
  return offset.toString(16).toUpperCase().padStart(width, '0');
}

function byteToHex(byte: number): string {
  return byte.toString(16).toUpperCase().padStart(2, '0');
}

function byteToAscii(byte: number): string {
  // Printable ASCII range: 32-126
  if (byte >= 32 && byte <= 126) {
    return String.fromCharCode(byte);
  }
  return '.';
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// --- Component Props ---

interface HexViewerProps {
  file: DiscoveredFile;
  /** Callback when metadata is loaded (for right panel) */
  onMetadataLoaded?: (metadata: ParsedMetadata | null) => void;
}

export function HexViewer(props: HexViewerProps) {
  // Viewer state
  const [chunk, setChunk] = createSignal<FileChunk | null>(null);
  const [metadata, setMetadata] = createSignal<ParsedMetadata | null>(null);
  const [fileType, setFileType] = createSignal<FileTypeInfo | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  
  // Navigation state
  const [currentOffset, setCurrentOffset] = createSignal(0);
  const [chunkSize, setChunkSize] = createSignal(DEFAULT_CHUNK_SIZE);
  const [gotoOffset, setGotoOffset] = createSignal("");
  
  // View options
  const [showAscii, setShowAscii] = createSignal(true);
  const [highlightRegions, setHighlightRegions] = createSignal(true);
  const [showAddress, setShowAddress] = createSignal(true);
  
  // Load file data
  const loadChunk = async (offset: number) => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await invoke<FileChunk>("viewer_read_chunk", {
        path: props.file.path,
        offset,
        size: chunkSize()
      });
      setChunk(result);
      setCurrentOffset(result.offset);
    } catch (e) {
      setError(`Failed to load file: ${e}`);
      setChunk(null);
    } finally {
      setLoading(false);
    }
  };
  
  // Load metadata and type on file change
  createEffect(() => {
    const file = props.file;
    if (!file) return;
    
    // Reset state
    setChunk(null);
    setMetadata(null);
    setFileType(null);
    setCurrentOffset(0);
    setError(null);
    
    // Load initial data
    loadChunk(0);
    
    // Load file type
    invoke<FileTypeInfo>("viewer_detect_type", { path: file.path })
      .then(setFileType)
      .catch(e => console.warn("Failed to detect file type:", e));
    
    // Load metadata (for forensic formats)
    invoke<ParsedMetadata>("viewer_parse_header", { path: file.path })
      .then(meta => {
        setMetadata(meta);
        if (props.onMetadataLoaded) {
          props.onMetadataLoaded(meta);
        }
      })
      .catch(() => {
        // Not all files have parseable metadata
        setMetadata(null);
        if (props.onMetadataLoaded) {
          props.onMetadataLoaded(null);
        }
      });
  });
  
  // Navigation handlers
  const goToStart = () => loadChunk(0);
  const goToEnd = () => {
    const c = chunk();
    if (c) {
      const lastOffset = Math.max(0, c.total_size - chunkSize());
      loadChunk(lastOffset);
    }
  };
  const goPrev = () => {
    const newOffset = Math.max(0, currentOffset() - chunkSize());
    loadChunk(newOffset);
  };
  const goNext = () => {
    const c = chunk();
    if (c && c.has_more) {
      loadChunk(currentOffset() + chunkSize());
    }
  };
  
  const handleGotoOffset = () => {
    const input = gotoOffset().trim();
    let offset: number;
    
    // Support hex (0x...) or decimal
    if (input.toLowerCase().startsWith("0x")) {
      offset = parseInt(input, 16);
    } else {
      offset = parseInt(input, 10);
    }
    
    if (isNaN(offset) || offset < 0) {
      setError("Invalid offset");
      return;
    }
    
    const c = chunk();
    if (c && offset >= c.total_size) {
      setError("Offset exceeds file size");
      return;
    }
    
    loadChunk(offset);
    setGotoOffset("");
  };
  
  // Get color for a byte based on metadata regions
  const getByteColor = (byteOffset: number): string | null => {
    if (!highlightRegions()) return null;
    
    const meta = metadata();
    if (!meta) return null;
    
    for (const region of meta.regions) {
      if (byteOffset >= region.start && byteOffset < region.end) {
        return getRegionColor(region.color_class);
      }
    }
    return null;
  };
  
  // Get region name for tooltip
  const getByteRegion = (byteOffset: number): HeaderRegion | null => {
    const meta = metadata();
    if (!meta) return null;
    
    for (const region of meta.regions) {
      if (byteOffset >= region.start && byteOffset < region.end) {
        return region;
      }
    }
    return null;
  };
  
  // Render hex lines
  const renderHexLines = () => {
    const c = chunk();
    if (!c) return [];
    
    const lines: { offset: number; bytes: number[] }[] = [];
    for (let i = 0; i < c.bytes.length; i += BYTES_PER_LINE) {
      lines.push({
        offset: c.offset + i,
        bytes: c.bytes.slice(i, i + BYTES_PER_LINE)
      });
    }
    return lines;
  };
  
  // Keyboard navigation
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "PageDown" || (e.key === "ArrowDown" && e.ctrlKey)) {
      e.preventDefault();
      goNext();
    } else if (e.key === "PageUp" || (e.key === "ArrowUp" && e.ctrlKey)) {
      e.preventDefault();
      goPrev();
    } else if (e.key === "Home" && e.ctrlKey) {
      e.preventDefault();
      goToStart();
    } else if (e.key === "End" && e.ctrlKey) {
      e.preventDefault();
      goToEnd();
    }
  };
  
  // Cleanup
  onCleanup(() => {
    // Any cleanup needed
  });
  
  return (
    <div class="hex-viewer" tabIndex={0} onKeyDown={handleKeyDown}>
      {/* Toolbar */}
      <div class="hex-toolbar">
        <div class="hex-toolbar-left">
          {/* File info */}
          <Show when={fileType()}>
            {type => (
              <span class="hex-file-type" title={type().magic_hex}>
                {type().description}
              </span>
            )}
          </Show>
          <Show when={chunk()}>
            {c => (
              <span class="hex-file-size">
                {formatFileSize(c().total_size)}
              </span>
            )}
          </Show>
        </div>
        
        <div class="hex-toolbar-center">
          {/* Navigation */}
          <button 
            class="hex-nav-btn" 
            onClick={goToStart} 
            disabled={loading() || !chunk()?.has_prev}
            title="Go to start (Ctrl+Home)"
          >
            ⏮
          </button>
          <button 
            class="hex-nav-btn" 
            onClick={goPrev} 
            disabled={loading() || !chunk()?.has_prev}
            title="Previous page (PageUp)"
          >
            ◀
          </button>
          
          {/* Offset display */}
          <Show when={chunk()}>
            {c => (
              <span class="hex-offset-display">
                0x{formatOffset(c().offset)} - 0x{formatOffset(Math.min(c().offset + c().bytes.length, c().total_size))}
              </span>
            )}
          </Show>
          
          <button 
            class="hex-nav-btn" 
            onClick={goNext} 
            disabled={loading() || !chunk()?.has_more}
            title="Next page (PageDown)"
          >
            ▶
          </button>
          <button 
            class="hex-nav-btn" 
            onClick={goToEnd} 
            disabled={loading() || !chunk()?.has_more}
            title="Go to end (Ctrl+End)"
          >
            ⏭
          </button>
        </div>
        
        <div class="hex-toolbar-right">
          {/* Go to offset */}
          <input
            type="text"
            class="hex-goto-input"
            placeholder="Go to offset (hex: 0x...)"
            value={gotoOffset()}
            onInput={e => setGotoOffset(e.currentTarget.value)}
            onKeyDown={e => e.key === "Enter" && handleGotoOffset()}
          />
          <button class="hex-goto-btn" onClick={handleGotoOffset}>
            Go
          </button>
          
          {/* View options */}
          <label class="hex-option">
            <input
              type="checkbox"
              checked={showAscii()}
              onChange={e => setShowAscii(e.currentTarget.checked)}
            />
            ASCII
          </label>
          <label class="hex-option">
            <input
              type="checkbox"
              checked={highlightRegions()}
              onChange={e => setHighlightRegions(e.currentTarget.checked)}
            />
            Highlight
          </label>
          
          {/* Chunk size */}
          <select
            class="hex-chunk-select"
            value={chunkSize()}
            onChange={e => {
              setChunkSize(parseInt(e.currentTarget.value));
              loadChunk(currentOffset());
            }}
          >
            <option value={MIN_CHUNK_SIZE}>256 B</option>
            <option value={1024}>1 KB</option>
            <option value={DEFAULT_CHUNK_SIZE}>4 KB</option>
            <option value={16384}>16 KB</option>
            <option value={MAX_CHUNK_SIZE}>64 KB</option>
          </select>
        </div>
      </div>
      
      {/* Legend for highlighted regions */}
      <Show when={highlightRegions() && metadata()?.regions.length}>
        <div class="hex-legend">
          <For each={metadata()?.regions}>
            {region => {
              const color = getRegionColor(region.color_class);
              return (
                <span 
                  class="hex-legend-item" 
                  style={{ "--region-color": color }}
                  title={region.description}
                >
                  <span class="hex-legend-color" style={{ background: color }}></span>
                  {region.name}
                </span>
              );
            }}
          </For>
        </div>
      </Show>
      
      {/* Error display */}
      <Show when={error()}>
        <div class="hex-error">{error()}</div>
      </Show>
      
      {/* Loading indicator */}
      <Show when={loading()}>
        <div class="hex-loading">Loading...</div>
      </Show>
      
      {/* Hex content */}
      <Show when={!loading() && chunk()}>
        <div class="hex-content">
          {/* Header */}
          <div class="hex-header">
            <Show when={showAddress()}>
              <span class="hex-address-header">Offset</span>
            </Show>
            <span class="hex-bytes-header">
              <For each={[...Array(BYTES_PER_LINE).keys()]}>
                {i => <span class="hex-col-header">{byteToHex(i)}</span>}
              </For>
            </span>
            <Show when={showAscii()}>
              <span class="hex-ascii-header">ASCII</span>
            </Show>
          </div>
          
          {/* Lines */}
          <div class="hex-lines">
            <For each={renderHexLines()}>
              {line => (
                <div class="hex-line">
                  <Show when={showAddress()}>
                    <span class="hex-address">
                      {formatOffset(line.offset)}
                    </span>
                  </Show>
                  
                  <span class="hex-bytes">
                    <For each={line.bytes}>
                      {(byte, i) => {
                        const byteOffset = line.offset + i();
                        const color = getByteColor(byteOffset);
                        const region = getByteRegion(byteOffset);
                        return (
                          <span 
                            class="hex-byte"
                            classList={{ 'highlighted': !!color }}
                            style={color ? { 
                              background: color, 
                              color: '#fff' 
                            } : {}}
                            title={region ? `${region.name}: ${region.description}` : `Offset: 0x${formatOffset(byteOffset)}`}
                          >
                            {byteToHex(byte)}
                          </span>
                        );
                      }}
                    </For>
                    {/* Pad incomplete lines */}
                    <For each={[...Array(Math.max(0, BYTES_PER_LINE - line.bytes.length)).keys()]}>
                      {() => <span class="hex-byte hex-byte-empty">  </span>}
                    </For>
                  </span>
                  
                  <Show when={showAscii()}>
                    <span class="hex-ascii">
                      <For each={line.bytes}>
                        {(byte, i) => {
                          const byteOffset = line.offset + i();
                          const color = getByteColor(byteOffset);
                          return (
                            <span 
                              class="hex-ascii-char"
                              classList={{ 'highlighted': !!color }}
                              style={color ? { background: color, color: '#fff' } : {}}
                            >
                              {byteToAscii(byte)}
                            </span>
                          );
                        }}
                      </For>
                    </span>
                  </Show>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
      
      {/* Empty state */}
      <Show when={!loading() && !chunk() && !error()}>
        <div class="hex-empty">
          Select a file to view its contents
        </div>
      </Show>
    </div>
  );
}

export type { ParsedMetadata, FileTypeInfo, HeaderRegion, MetadataField };

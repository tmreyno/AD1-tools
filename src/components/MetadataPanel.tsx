import { For, Show, createSignal, createMemo } from "solid-js";
import type { ParsedMetadata, MetadataField } from "./HexViewer";
import type { ContainerInfo } from "../types";
import { formatBytes, formatOffsetLabel } from "../utils";

// File info passed from parent
interface FileInfo {
  path: string;
  filename: string;
  size: number;
  created?: string;
  modified?: string;
  container_type?: string;
  segment_count?: number;
}

interface MetadataPanelProps {
  metadata: ParsedMetadata | null;
  /** File information from discovery */
  fileInfo?: FileInfo | null;
  /** Full container info with details */
  containerInfo?: ContainerInfo | null;
  /** Currently selected/navigated offset (to highlight in list) */
  selectedOffset?: number | null;
  /** Callback when a region is clicked (to jump to offset in hex viewer) */
  onRegionClick?: (offset: number, size?: number) => void;
}

export function MetadataPanel(props: MetadataPanelProps) {
  // Track expanded categories
  const [expandedCategories, setExpandedCategories] = createSignal<Set<string>>(
    new Set(["Format", "Case Info", "Hashes", "Container", "_container"]) // Start with key sections expanded
  );
  
  const toggleCategory = (category: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };
  
  const isExpanded = (category: string) => expandedCategories().has(category);
  
  // Preferred category order
  const CATEGORY_ORDER = [
    "Format",
    "Case Info", 
    "Acquisition",
    "Device",
    "Volume",
    "Hashes",
    "Errors",
    "Sections",
    "General"
  ];
  
  // Group fields by category
  const groupedFields = () => {
    const meta = props.metadata;
    if (!meta?.fields.length) return new Map<string, MetadataField[]>();
    
    const groups = new Map<string, MetadataField[]>();
    for (const field of meta.fields) {
      const category = field.category || "General";
      if (!groups.has(category)) {
        groups.set(category, []);
      }
      groups.get(category)!.push(field);
    }
    
    // Sort by preferred order
    const sortedGroups = new Map<string, MetadataField[]>();
    for (const cat of CATEGORY_ORDER) {
      if (groups.has(cat)) {
        sortedGroups.set(cat, groups.get(cat)!);
        groups.delete(cat);
      }
    }
    // Add remaining
    for (const [cat, fields] of groups) {
      sortedGroups.set(cat, fields);
    }
    
    return sortedGroups;
  };
  
  // Get EWF info from container (either E01 or L01) - use memo for reactivity
  const ewfInfo = createMemo(() => {
    const info = props.containerInfo;
    if (!info) return null;
    return info.e01 || info.l01 || null;
  });
  
  const handleRowClick = (offset: number | undefined | null, size?: number) => {
    if (offset !== undefined && offset !== null && props.onRegionClick) {
      props.onRegionClick(offset, size);
    }
  };
  
  return (
    <div class="meta-panel">
      <Show when={!props.metadata && !props.fileInfo}>
        <div class="meta-empty">
          <span class="meta-empty-icon">📋</span>
          <span class="meta-empty-text">No metadata</span>
        </div>
      </Show>
      
      {/* Format header - prominent display */}
      <Show when={props.metadata}>
        {meta => (
          <div class="meta-format-header">
            <span class="meta-format-label">Format</span>
            <span class="meta-format-value">{meta().format}</span>
            <Show when={meta().version}>
              <span class="meta-format-version">v{meta().version}</span>
            </Show>
          </div>
        )}
      </Show>
      
      {/* File info row */}
      <Show when={props.fileInfo}>
        {info => (
          <div class="meta-file-info">
            <div class="meta-row">
              <span class="meta-key">File</span>
              <span class="meta-value" title={info().path}>{info().filename}</span>
              <span class="meta-offset"></span>
            </div>
            <div class="meta-row">
              <span class="meta-key">Size</span>
              <span class="meta-value">{formatBytes(info().size)}</span>
              <span class="meta-offset"></span>
            </div>
            <Show when={info().segment_count && info().segment_count! > 1}>
              <div class="meta-row">
                <span class="meta-key">Segments</span>
                <span class="meta-value">{info().segment_count}</span>
                <span class="meta-offset"></span>
              </div>
            </Show>
          </div>
        )}
      </Show>
      
      {/* Debug: Show if containerInfo is missing */}
      <Show when={!ewfInfo() && props.fileInfo?.container_type?.toLowerCase().includes('e01')}>
        <div class="meta-category">
          <div class="meta-category-header">
            <span class="meta-category-name">⏳ Loading container info...</span>
          </div>
        </div>
      </Show>
      
      {/* 📋 CONTAINER DETAILS Section */}
      <Show when={ewfInfo()}>
        {ewf => {
          // Use actual section offsets from backend, fall back to typical defaults
          // EWF structure: signature(0x0) + segment(0x9) + section_header(0xD) + section_data
          const headerOffset = ewf().header_section_offset ?? 0xD;
          const volumeOffset = ewf().volume_section_offset ?? 0x59;
          // hashOffset and digestOffset available for future hash navigation
          // const hashOffset = ewf().hash_section_offset;
          // const digestOffset = ewf().digest_section_offset;
          
          // Section data starts 76 bytes after section header
          // Field offsets within volume data: chunk_count +4, sectors_per_chunk +8, bytes_per_sector +12, compression +56
          const volumeDataStart = volumeOffset + 76;
          // Header section data is zlib-compressed - show where the compressed blob starts
          const headerDataStart = headerOffset + 76;
          
          return (
          <div class="meta-category">
            <div 
              class="meta-category-header"
              onClick={() => toggleCategory("_container")}
            >
              <span class="meta-category-toggle">
                {isExpanded("_container") ? "▾" : "▸"}
              </span>
              <span class="meta-category-name">📋 CONTAINER DETAILS</span>
            </div>
            
            <Show when={isExpanded("_container")}>
              <div class="meta-rows">
                {/* Format Info - links to signature */}
                <div 
                  class="meta-row meta-row-clickable"
                  onClick={() => handleRowClick(0x0, 8)}
                  title="Click to view EVF signature at 0x0"
                >
                  <span class="meta-key">FORMAT</span>
                  <span class="meta-value">{ewf().format_version}</span>
                  <span class="meta-offset">{formatOffsetLabel(0x0)}</span>
                </div>
                
                {/* Segments - links to segment number field */}
                <div 
                  class="meta-row meta-row-clickable"
                  onClick={() => handleRowClick(0x9, 2)}
                  title="Click to view segment number at 0x9"
                >
                  <span class="meta-key">SEGMENTS</span>
                  <span class="meta-value">{ewf().segment_count}</span>
                  <span class="meta-offset">{formatOffsetLabel(0x9)}</span>
                </div>
                
                {/* Total Size */}
                <div class="meta-row">
                  <span class="meta-key">TOTAL SIZE</span>
                  <span class="meta-value">{formatBytes(ewf().total_size)}</span>
                  <span class="meta-offset"></span>
                </div>
                
                {/* Compression - in volume section at offset +56 (0x38) */}
                <div 
                  class="meta-row meta-row-clickable"
                  onClick={() => handleRowClick(volumeDataStart + 0x38, 1)}
                  title="Click to view compression level in volume section"
                >
                  <span class="meta-key">COMPRESSION</span>
                  <span class="meta-value">{ewf().compression || "Unknown"}</span>
                  <span class="meta-offset">{formatOffsetLabel(volumeDataStart + 0x38)}</span>
                </div>
                
                {/* Bytes per sector - in volume section at offset +12 (0x0C) */}
                <div 
                  class="meta-row meta-row-clickable"
                  onClick={() => handleRowClick(volumeDataStart + 0x0C, 4)}
                  title="Click to view bytes/sector in volume section"
                >
                  <span class="meta-key">BYTES/SECTOR</span>
                  <span class="meta-value">{ewf().bytes_per_sector}</span>
                  <span class="meta-offset">{formatOffsetLabel(volumeDataStart + 0x0C)}</span>
                </div>
                
                {/* Sectors per chunk - in volume section at offset +8 */}
                <div 
                  class="meta-row meta-row-clickable"
                  onClick={() => handleRowClick(volumeDataStart + 0x08, 4)}
                  title="Click to view sectors/chunk in volume section"
                >
                  <span class="meta-key">SECTORS/CHUNK</span>
                  <span class="meta-value">{ewf().sectors_per_chunk}</span>
                  <span class="meta-offset">{formatOffsetLabel(volumeDataStart + 0x08)}</span>
                </div>
                
                {/* Case Info - stored as zlib-compressed data in header section */}
                <Show when={ewf().case_number}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">CASE #</span>
                    <span class="meta-value">{ewf().case_number}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().evidence_number}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">EVIDENCE #</span>
                    <span class="meta-value">{ewf().evidence_number}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().examiner_name}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">EXAMINER</span>
                    <span class="meta-value">{ewf().examiner_name}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().acquiry_date}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">ACQUIRED</span>
                    <span class="meta-value">{ewf().acquiry_date}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().system_date}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">SYSTEM DATE</span>
                    <span class="meta-value">{ewf().system_date}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().description}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">DESCRIPTION</span>
                    <span class="meta-value">{ewf().description}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().notes}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">NOTES</span>
                    <span class="meta-value">{ewf().notes}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                
                {/* Device Info */}
                <Show when={ewf().model}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">MODEL</span>
                    <span class="meta-value">{ewf().model}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                <Show when={ewf().serial_number}>
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={() => handleRowClick(headerDataStart)}
                    title="Click to view compressed header data (zlib stream)"
                  >
                    <span class="meta-key">SERIAL #</span>
                    <span class="meta-value">{ewf().serial_number}</span>
                    <span class="meta-offset">{formatOffsetLabel(headerDataStart)} 📦</span>
                  </div>
                </Show>
                
                {/* Stored Hashes - raw bytes in hash/digest section (NOT compressed) */}
                <Show when={ewf().stored_hashes && ewf().stored_hashes!.length > 0}>
                  <For each={ewf().stored_hashes}>
                    {hash => {
                      const hasOffset = hash.offset != null && hash.size != null;
                      return (
                        <div 
                          class={`meta-row ${hasOffset ? 'clickable' : ''}`}
                          onClick={() => {
                            if (hasOffset) {
                              handleRowClick(hash.offset!, hash.size!);
                            }
                          }}
                        >
                          <span class="meta-key">� {hash.algorithm.toUpperCase()}</span>
                          <span class="meta-value meta-hash">{hash.hash}</span>
                          <span class="meta-offset">
                            {hasOffset ? formatOffsetLabel(hash.offset!) : ''}
                          </span>
                        </div>
                      );
                    }}
                  </For>
                </Show>
              </div>
            </Show>
          </div>
          );
        }}
      </Show>
      
      {/* Categories */}
      <Show when={props.metadata}>
        <div class="meta-categories">
          <For each={[...groupedFields().entries()]}>
            {([category, fields]) => (
              <div class="meta-category">
                <div 
                  class="meta-category-header"
                  onClick={() => toggleCategory(category)}
                >
                  <span class="meta-category-toggle">
                    {isExpanded(category) ? "▾" : "▸"}
                  </span>
                  <span class="meta-category-name">{category}</span>
                  <span class="meta-category-count">{fields.length}</span>
                </div>
                
                <Show when={isExpanded(category)}>
                  <div class="meta-rows">
                    <For each={fields}>
                      {field => {
                        const hasOffset = field.source_offset !== undefined && field.source_offset !== null;
                        return (
                          <div 
                            class="meta-row"
                            classList={{ "meta-row-clickable": hasOffset }}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRowClick(field.source_offset);
                            }}
                            title={hasOffset ? `Click to view hex at ${formatOffsetLabel(field.source_offset)}` : field.value}
                          >
                            <span class="meta-key">{field.key}</span>
                            <span class="meta-value">{field.value}</span>
                            <span class="meta-offset">{formatOffsetLabel(field.source_offset)}</span>
                          </div>
                        );
                      }}
                    </For>
                  </div>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>
      
      {/* Header Regions - compact list */}
      <Show when={props.metadata?.regions.length}>
        <div class="meta-category">
          <div 
            class="meta-category-header"
            onClick={() => toggleCategory("_regions")}
          >
            <span class="meta-category-toggle">
              {isExpanded("_regions") ? "▾" : "▸"}
            </span>
            <span class="meta-category-name">Hex Regions</span>
            <span class="meta-category-count">{props.metadata!.regions.length}</span>
          </div>
          
          <Show when={isExpanded("_regions")}>
            <div class="meta-rows">
              <For each={props.metadata!.regions}>
                {region => (
                  <div 
                    class="meta-row meta-row-clickable"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRowClick(region.start);
                    }}
                    title={region.description}
                  >
                    <span class="meta-key">{region.name}</span>
                    <span class="meta-value">{region.end - region.start} bytes</span>
                    <span class="meta-offset">{formatOffsetLabel(region.start)}</span>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
}

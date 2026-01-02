import { For, Show, createSignal } from "solid-js";
import type { ParsedMetadata, MetadataField, HeaderRegion } from "./HexViewer";

// Map color classes to actual colors (matches ewf_parser.rs color_class values)
const COLOR_MAP: Record<string, string> = {
  // General regions
  "region-signature": "#ef4444",    // Red - File signatures/magic bytes
  "region-header": "#f97316",       // Orange - Section headers
  "region-segment": "#fb923c",      // Light Orange - Segment info
  "region-metadata": "#eab308",     // Yellow - Metadata content
  "region-data": "#22c55e",         // Green - Data sections
  "region-checksum": "#8b5cf6",     // Purple - Checksums
  "region-reserved": "#6b7280",     // Gray - Reserved/padding
  "region-footer": "#ec4899",       // Pink - Footer/end markers
  "region-version": "#06b6d4",      // Cyan - Version info
  
  // EWF-specific regions
  "region-section-type": "#facc15", // Yellow - EWF section type field
  "region-offset": "#3b82f6",       // Blue - Offset/size fields
  "region-hash": "#a16207",         // Brown - Hash values
  "region-error": "#dc2626",        // Dark Red - Error regions
};

function getRegionColor(colorClass: string): string {
  return COLOR_MAP[colorClass] || "#6a6a7a";
}

interface MetadataPanelProps {
  metadata: ParsedMetadata | null;
  /** Callback when a region is clicked (to jump to offset in hex viewer) */
  onRegionClick?: (offset: number) => void;
}

export function MetadataPanel(props: MetadataPanelProps) {
  const [expandedSections, setExpandedSections] = createSignal<Set<string>>(
    new Set(["fields", "regions"])
  );
  
  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };
  
  const isExpanded = (section: string) => expandedSections().has(section);
  
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
    return groups;
  };
  
  const formatValue = (value: string): string => {
    // Truncate long values
    if (value.length > 100) {
      return value.slice(0, 97) + "...";
    }
    return value;
  };
  
  const formatOffset = (offset: number): string => {
    return "0x" + offset.toString(16).toUpperCase().padStart(8, '0');
  };
  
  return (
    <div class="metadata-panel">
      <Show when={!props.metadata}>
        <div class="metadata-empty">
          <div class="metadata-empty-icon">📋</div>
          <div class="metadata-empty-text">No metadata available</div>
          <div class="metadata-empty-hint">
            Select a forensic image file to view parsed header information
          </div>
        </div>
      </Show>
      
      <Show when={props.metadata}>
        {meta => (
          <>
            {/* Format header */}
            <div class="metadata-header">
              <span class="metadata-format">{meta().format}</span>
              <Show when={meta().version}>
                <span class="metadata-version">v{meta().version}</span>
              </Show>
            </div>
            
            {/* Fields section */}
            <div class="metadata-section">
              <div 
                class="metadata-section-header"
                onClick={() => toggleSection("fields")}
              >
                <span class="metadata-section-toggle">
                  {isExpanded("fields") ? "▼" : "▶"}
                </span>
                <span class="metadata-section-title">
                  Metadata ({meta().fields.length})
                </span>
              </div>
              
              <Show when={isExpanded("fields")}>
                <div class="metadata-fields">
                  <For each={[...groupedFields().entries()]}>
                    {([category, fields]) => (
                      <div class="metadata-group">
                        <div class="metadata-group-header">
                          {category}
                        </div>
                        <div class="metadata-group-fields">
                          <For each={fields}>
                            {field => (
                              <div class="metadata-field">
                                <div class="metadata-field-header">
                                  <span class="metadata-field-name">{field.key}</span>
                                </div>
                                <div class="metadata-field-value">
                                  {formatValue(field.value)}
                                </div>
                              </div>
                            )}
                          </For>
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>
            
            {/* Regions section */}
            <Show when={meta().regions.length > 0}>
              <div class="metadata-section">
                <div 
                  class="metadata-section-header"
                  onClick={() => toggleSection("regions")}
                >
                  <span class="metadata-section-toggle">
                    {isExpanded("regions") ? "▼" : "▶"}
                  </span>
                  <span class="metadata-section-title">
                    Header Regions ({meta().regions.length})
                  </span>
                </div>
                
                <Show when={isExpanded("regions")}>
                  <div class="metadata-regions">
                    <For each={meta().regions}>
                      {region => {
                        const color = getRegionColor(region.color_class);
                        return (
                          <div 
                            class="metadata-region"
                            onClick={() => props.onRegionClick?.(region.start)}
                            title={region.description}
                          >
                            <span 
                              class="metadata-region-color"
                              style={{ background: color }}
                            ></span>
                            <span class="metadata-region-name">{region.name}</span>
                            <span class="metadata-region-range">
                              {formatOffset(region.start)} - {formatOffset(region.end)}
                            </span>
                            <span class="metadata-region-size">
                              {region.end - region.start} B
                            </span>
                          </div>
                        );
                      }}
                    </For>
                  </div>
                </Show>
              </div>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}

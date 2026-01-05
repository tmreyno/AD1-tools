import { For, Show } from "solid-js";
import { HASH_ALGORITHMS } from "../types";
import type { HashAlgorithm, HashAlgorithmInfo } from "../types";

interface ToolbarProps {
  scanDir: string;
  onScanDirChange: (dir: string) => void;
  recursiveScan: boolean;
  onRecursiveScanChange: (recursive: boolean) => void;
  selectedHashAlgorithm: HashAlgorithm;
  onHashAlgorithmChange: (algorithm: HashAlgorithm) => void;
  selectedCount: number;
  discoveredCount: number;
  busy: boolean;
  onBrowse: () => void;
  onScan: () => void;
  onHashSelected: () => void;
  onLoadAll: () => void;
  // Project management
  projectPath?: string | null;
  projectModified?: boolean;
  onSaveProject?: () => void;
  onLoadProject?: () => void;
  // Report generation
  onGenerateReport?: () => void;
  // Responsive mode - show only icons when true
  compact?: boolean;
}

// Get tooltip for hash algorithm
const getAlgorithmTooltip = (alg: HashAlgorithmInfo): string => {
  const parts: string[] = [alg.label.replace(/ ⚡+/g, '')];
  if (alg.speed === "fast") parts.push("🚀 Very Fast");
  else if (alg.speed === "medium") parts.push("⏱️ Medium Speed");
  else parts.push("🐢 Slower");
  if (alg.forensic) parts.push("⚖️ Court-accepted");
  if (alg.cryptographic) parts.push("🔐 Cryptographic");
  else parts.push("🔓 Non-cryptographic");
  return parts.join(" • ");
};

export function Toolbar(props: ToolbarProps) {
  // Get current algorithm info for tooltip
  const currentAlgoInfo = () => HASH_ALGORITHMS.find(a => a.value === props.selectedHashAlgorithm);
  const compact = () => props.compact ?? false;
  
  return (
    <div class="flex items-center gap-2 px-3 py-2 bg-bg-panel border-b border-border shrink-0 h-11 flex-nowrap overflow-x-auto">
      <button 
        class="btn btn-primary" 
        onClick={props.onBrowse} 
        disabled={props.busy}
        title="Open Evidence Directory"
      >
        📁<Show when={!compact()}> Open Directory</Show>
      </button>
      
      <div class={`flex ${compact() ? 'flex-1 min-w-[80px] max-w-[200px]' : 'flex-1 min-w-[120px] max-w-[400px]'}`}>
        <input 
          type="text" 
          class="flex-1 min-w-0 px-2.5 py-1.5 bg-bg border border-border rounded-l text-txt text-sm focus:outline-none focus:border-accent overflow-hidden text-ellipsis"
          style={{ direction: "rtl", "text-align": "left" }}
          value={props.scanDir} 
          onInput={(e) => props.onScanDirChange(e.currentTarget.value)} 
          placeholder={compact() ? "Path..." : "Evidence directory path..."} 
          onKeyDown={(e) => e.key === "Enter" && props.onScan()}
          title={props.scanDir || "Evidence directory path"}
        />
        <button 
          class="btn btn-default rounded-l-none border-l-0" 
          onClick={props.onScan} 
          disabled={props.busy || !props.scanDir}
          title="Scan Directory"
        >
          🔍
        </button>
      </div>
      
      <Show when={!compact()}>
        <label class="flex items-center gap-1.5 text-sm text-txt-muted cursor-pointer whitespace-nowrap" title="Scan subdirectories">
          <input 
            type="checkbox" 
            class="accent-accent"
            checked={props.recursiveScan} 
            onChange={(e) => props.onRecursiveScanChange(e.currentTarget.checked)} 
          />
          <span>Recursive</span>
        </label>
      </Show>
      <Show when={compact()}>
        <button
          class={`btn btn-icon ${props.recursiveScan ? 'btn-accent' : 'btn-default'}`}
          onClick={() => props.onRecursiveScanChange(!props.recursiveScan)}
          title={props.recursiveScan ? "Recursive scan enabled" : "Recursive scan disabled"}
        >
          🔄
        </button>
      </Show>
      
      <div class="w-px h-6 bg-border mx-1" />
      
      <select 
        class={`select ${compact() ? 'w-20' : ''} ${currentAlgoInfo()?.speed === 'fast' ? 'border-success bg-gradient-to-br from-bg-card to-success-soft' : ''}`}
        value={props.selectedHashAlgorithm} 
        onChange={(e) => props.onHashAlgorithmChange(e.currentTarget.value as HashAlgorithm)} 
        title={currentAlgoInfo() ? getAlgorithmTooltip(currentAlgoInfo()!) : "Hash algorithm"}
      >
        <optgroup label="⚖️ Forensic Standard">
          <For each={HASH_ALGORITHMS.filter(a => a.forensic)}>
            {(alg) => <option value={alg.value} title={getAlgorithmTooltip(alg)}>{compact() ? alg.value.toUpperCase() : alg.label}</option>}
          </For>
        </optgroup>
        <optgroup label="⚡ Fast (Non-forensic)">
          <For each={HASH_ALGORITHMS.filter(a => !a.forensic)}>
            {(alg) => <option value={alg.value} title={getAlgorithmTooltip(alg)}>{compact() ? alg.value.toUpperCase() : alg.label}</option>}
          </For>
        </optgroup>
      </select>
      
      <button 
        class="btn btn-default" 
        onClick={props.onHashSelected} 
        disabled={props.busy || props.selectedCount === 0} 
        title={`Hash ${props.selectedCount} selected files in parallel`}
      >
        🔐<Show when={!compact()}> Hash</Show> ({props.selectedCount})
      </button>
      
      <button 
        class="btn btn-default" 
        onClick={props.onLoadAll} 
        disabled={props.busy || props.discoveredCount === 0} 
        title="Load metadata for all files"
      >
        ℹ️<Show when={!compact()}> Load All</Show>
      </button>
      
      <div class="w-px h-6 bg-border mx-1" />
      
      {/* Project Management */}
      <Show when={props.onSaveProject}>
        <button 
          class={`btn ${props.projectModified ? 'btn-warning' : 'btn-default'}`}
          onClick={props.onSaveProject} 
          disabled={props.busy || !props.scanDir}
          title={props.projectPath 
            ? `Save project to ${props.projectPath}${props.projectModified ? ' (modified)' : ''}`
            : "Save project"}
        >
          💾<Show when={!compact()}> {props.projectModified ? 'Save*' : 'Save'}</Show>
        </button>
      </Show>
      
      <Show when={props.onLoadProject}>
        <button 
          class="btn btn-default" 
          onClick={props.onLoadProject} 
          disabled={props.busy}
          title="Load a project file"
        >
          📂<Show when={!compact()}> Load</Show>
        </button>
      </Show>
      
      <div class="w-px h-6 bg-border mx-1" />
      
      {/* Report Generation */}
      <Show when={props.onGenerateReport}>
        <button 
          class="btn btn-primary" 
          onClick={props.onGenerateReport} 
          disabled={props.busy || props.discoveredCount === 0}
          title="Generate forensic report from evidence"
        >
          📝<Show when={!compact()}> Report</Show>
        </button>
      </Show>
    </div>
  );
}

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
  onHashAll: () => void;
  onLoadAll: () => void;
  // Project management
  projectPath?: string | null;
  projectModified?: boolean;
  onSaveProject?: () => void;
  onLoadProject?: () => void;
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
  
  return (
    <div class="flex items-center gap-2 px-3 py-2 bg-bg-panel border-b border-border shrink-0 h-11 flex-nowrap overflow-x-auto">
      <button 
        class="btn btn-primary" 
        onClick={props.onBrowse} 
        disabled={props.busy}
      >
        📁 Open Directory
      </button>
      
      <div class="flex flex-1 min-w-[200px] max-w-[400px]">
        <input 
          type="text" 
          class="flex-1 px-2.5 py-1.5 bg-bg border border-border rounded-l text-txt text-sm focus:outline-none focus:border-accent"
          value={props.scanDir} 
          onInput={(e) => props.onScanDirChange(e.currentTarget.value)} 
          placeholder="Evidence directory path..." 
          onKeyDown={(e) => e.key === "Enter" && props.onScan()} 
        />
        <button 
          class="btn btn-default rounded-l-none border-l-0" 
          onClick={props.onScan} 
          disabled={props.busy || !props.scanDir}
        >
          🔍
        </button>
      </div>
      
      <label class="flex items-center gap-1.5 text-sm text-txt-muted cursor-pointer whitespace-nowrap" title="Scan subdirectories">
        <input 
          type="checkbox" 
          class="accent-accent"
          checked={props.recursiveScan} 
          onChange={(e) => props.onRecursiveScanChange(e.currentTarget.checked)} 
        />
        <span>Recursive</span>
      </label>
      
      <div class="w-px h-6 bg-border mx-1" />
      
      <select 
        class={`select ${currentAlgoInfo()?.speed === 'fast' ? 'border-success bg-gradient-to-br from-bg-card to-success-soft' : ''}`}
        value={props.selectedHashAlgorithm} 
        onChange={(e) => props.onHashAlgorithmChange(e.currentTarget.value as HashAlgorithm)} 
        title={currentAlgoInfo() ? getAlgorithmTooltip(currentAlgoInfo()!) : "Hash algorithm"}
      >
        <optgroup label="⚖️ Forensic Standard">
          <For each={HASH_ALGORITHMS.filter(a => a.forensic)}>
            {(alg) => <option value={alg.value} title={getAlgorithmTooltip(alg)}>{alg.label}</option>}
          </For>
        </optgroup>
        <optgroup label="⚡ Fast (Non-forensic)">
          <For each={HASH_ALGORITHMS.filter(a => !a.forensic)}>
            {(alg) => <option value={alg.value} title={getAlgorithmTooltip(alg)}>{alg.label}</option>}
          </For>
        </optgroup>
      </select>
      
      <button 
        class="btn btn-default" 
        onClick={props.onHashSelected} 
        disabled={props.busy || props.selectedCount === 0} 
        title={`Hash ${props.selectedCount} selected files in parallel`}
      >
        🔐 Hash ({props.selectedCount})
      </button>
      
      <button 
        class="btn btn-default" 
        onClick={props.onHashAll} 
        disabled={props.busy || props.discoveredCount === 0} 
        title={props.selectedCount > 0 
          ? `Hash ${props.selectedCount} selected files in parallel using all CPU cores`
          : `Select all and hash ${props.discoveredCount} files in parallel using all CPU cores`}
      >
        ⚡ Hash All ({props.selectedCount > 0 ? props.selectedCount : props.discoveredCount})
      </button>
      
      <button 
        class="btn btn-default" 
        onClick={props.onLoadAll} 
        disabled={props.busy || props.discoveredCount === 0} 
        title="Load metadata for all files"
      >
        ℹ️ Load All
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
          💾 {props.projectModified ? 'Save*' : 'Save'}
        </button>
      </Show>
      
      <Show when={props.onLoadProject}>
        <button 
          class="btn btn-default" 
          onClick={props.onLoadProject} 
          disabled={props.busy}
          title="Load a project file"
        >
          📂 Load
        </button>
      </Show>
    </div>
  );
}

import { For } from "solid-js";
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
    <div class="toolbar">
      <button 
        class="tool-btn primary" 
        onClick={props.onBrowse} 
        disabled={props.busy}
      >
        📁 Open Directory
      </button>
      
      <div class="tool-input">
        <input 
          type="text" 
          value={props.scanDir} 
          onInput={(e) => props.onScanDirChange(e.currentTarget.value)} 
          placeholder="Evidence directory path..." 
          onKeyDown={(e) => e.key === "Enter" && props.onScan()} 
        />
        <button 
          class="tool-btn" 
          onClick={props.onScan} 
          disabled={props.busy || !props.scanDir}
        >
          🔍
        </button>
      </div>
      
      <label class="tool-toggle" title="Scan subdirectories">
        <input 
          type="checkbox" 
          checked={props.recursiveScan} 
          onChange={(e) => props.onRecursiveScanChange(e.currentTarget.checked)} 
        />
        <span>Recursive</span>
      </label>
      
      <div class="tool-sep" />
      
      <select 
        class={`tool-select ${currentAlgoInfo()?.speed === 'fast' ? 'fast-algo' : ''}`}
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
        class="tool-btn" 
        onClick={props.onHashSelected} 
        disabled={props.busy || props.selectedCount === 0} 
        title={`Hash ${props.selectedCount} selected files in parallel`}
      >
        🔐 Hash ({props.selectedCount})
      </button>
      
      <button 
        class="tool-btn" 
        onClick={props.onHashAll} 
        disabled={props.busy || props.discoveredCount === 0} 
        title={props.selectedCount > 0 
          ? `Hash ${props.selectedCount} selected files in parallel using all CPU cores`
          : `Select all and hash ${props.discoveredCount} files in parallel using all CPU cores`}
      >
        ⚡ Hash All ({props.selectedCount > 0 ? props.selectedCount : props.discoveredCount})
      </button>
      
      <button 
        class="tool-btn" 
        onClick={props.onLoadAll} 
        disabled={props.busy || props.discoveredCount === 0} 
        title="Load metadata for all files"
      >
        ℹ️ Load All
      </button>
    </div>
  );
}

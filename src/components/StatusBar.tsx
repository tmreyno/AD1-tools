import { Show } from "solid-js";
import type { SystemStats } from "../hooks";
import { formatBytes } from "../utils";

interface StatusBarProps {
  statusKind: "idle" | "working" | "ok" | "error";
  statusMessage: string;
  discoveredCount: number;
  totalSize: number;
  selectedCount: number;
  systemStats: SystemStats | null;
}

export function StatusBar(props: StatusBarProps) {
  const statusIcon = () => {
    switch (props.statusKind) {
      case "working": return "⏳";
      case "ok": return "✓";
      case "error": return "✗";
      default: return "○";
    }
  };

  // Format CPU usage - show cores used (e.g., "4.9 cores" instead of "489%")
  const formatCpuUsage = (cpuPercent: number, cores: number) => {
    const coresUsed = cpuPercent / 100;
    if (coresUsed >= 1) {
      return `${coresUsed.toFixed(1)}/${cores}`;
    }
    return `${cpuPercent.toFixed(0)}%`;
  };

  // Parse status message to add animated icons
  const renderStatusMessage = () => {
    const msg = props.statusMessage;
    // Replace hash symbol with animated version, remove book emoji
    const cleanedMsg = msg.replace(/📖/g, '');
    const parts = cleanedMsg.split(/(#)/g);
    return parts.map((part) => {
      if (part === "#") {
        return <span class="inline-block text-base font-black animate-spin-slow">#</span>;
      }
      return part;
    });
  };

  const statusBg = () => {
    switch (props.statusKind) {
      case "idle": return "bg-bg-card text-txt-muted";
      case "working": return "bg-warning-soft text-warning";
      case "ok": return "bg-success-soft text-success";
      case "error": return "bg-error-soft text-error";
    }
  };

  return (
    <footer class="flex flex-col bg-bg-panel border-t border-border shrink-0">
      <div class={`flex items-center gap-2 px-4 py-1.5 text-sm ${statusBg()}`}>
        <span class={`text-sm shrink-0 ${props.statusKind === 'working' ? 'animate-pulse-slow' : ''}`}>{statusIcon()}</span>
        <span class="font-medium truncate flex items-center gap-0.5">{renderStatusMessage()}</span>
        
        <div class="flex items-center gap-1.5 text-xs opacity-80">
          <Show when={props.discoveredCount > 0}>
            <span>📁 {props.discoveredCount}</span>
            <span>💾 {formatBytes(props.totalSize)}</span>
          </Show>
          <Show when={props.selectedCount > 0}>
            <span>☑ {props.selectedCount}</span>
          </Show>
        </div>
        
        <div class="flex items-center gap-2 ml-auto text-xs font-mono pl-3 border-l border-white/15 opacity-85">
          <Show when={props.systemStats}>
            <span title={`App CPU: ${props.systemStats!.app_cpu_usage.toFixed(1)}% (${(props.systemStats!.app_cpu_usage / 100).toFixed(1)} cores)\nSystem CPU: ${props.systemStats!.cpu_usage.toFixed(1)}%\nCores: ${props.systemStats!.cpu_cores}`}>
              🔥 {formatCpuUsage(props.systemStats!.app_cpu_usage, props.systemStats!.cpu_cores)}
            </span>
            <span title={`App Memory: ${formatBytes(props.systemStats!.app_memory)}\nSystem: ${formatBytes(props.systemStats!.memory_used)} / ${formatBytes(props.systemStats!.memory_total)} (${props.systemStats!.memory_percent.toFixed(1)}%)`}>
              🧠 {formatBytes(props.systemStats!.app_memory)}
            </span>
            <span title={`Worker threads: ${props.systemStats!.app_threads}`}>
              🧵 {props.systemStats!.app_threads}
            </span>
          </Show>
        </div>
      </div>
    </footer>
  );
}

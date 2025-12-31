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
        return <span class="status-icon-spin">#</span>;
      }
      return part;
    });
  };

  return (
    <footer class="status-bar">
      <div class={`status-message-row ${props.statusKind}`}>
        <span class="status-icon">{statusIcon()}</span>
        <span class="status-text">{renderStatusMessage()}</span>
        
        <div class="status-stats">
          <Show when={props.discoveredCount > 0}>
            <span class="stat-item">📁 {props.discoveredCount}</span>
            <span class="stat-item">💾 {formatBytes(props.totalSize)}</span>
          </Show>
          <Show when={props.selectedCount > 0}>
            <span class="stat-item">☑ {props.selectedCount}</span>
          </Show>
        </div>
        
        <div class="system-stats">
          <Show when={props.systemStats}>
            <span class="stat-item" title={`App CPU: ${props.systemStats!.app_cpu_usage.toFixed(1)}% (${(props.systemStats!.app_cpu_usage / 100).toFixed(1)} cores)\nSystem CPU: ${props.systemStats!.cpu_usage.toFixed(1)}%\nCores: ${props.systemStats!.cpu_cores}`}>
              🔥 {formatCpuUsage(props.systemStats!.app_cpu_usage, props.systemStats!.cpu_cores)}
            </span>
            <span class="stat-item" title={`App Memory: ${formatBytes(props.systemStats!.app_memory)}\nSystem: ${formatBytes(props.systemStats!.memory_used)} / ${formatBytes(props.systemStats!.memory_total)} (${props.systemStats!.memory_percent.toFixed(1)}%)`}>
              🧠 {formatBytes(props.systemStats!.app_memory)}
            </span>
            <span class="stat-item" title={`App threads: ${props.systemStats!.app_threads}`}>
              🧵 {props.systemStats!.app_threads}
            </span>
          </Show>
        </div>
      </div>
    </footer>
  );
}

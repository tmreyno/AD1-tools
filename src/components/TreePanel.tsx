import { For, Show, createSignal, createMemo } from "solid-js";
import { formatBytes } from "../utils";
import type { ContainerInfo, UfedAssociatedFile } from "../types";

export interface TreeNode {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  type?: string;
  hash?: string | null;
  children?: TreeNode[];
}

interface TreePanelProps {
  info: ContainerInfo | undefined;
}

// Build a tree structure from associated files
function buildTreeFromAssociatedFiles(files: UfedAssociatedFile[], parentFolder?: string): TreeNode[] {
  // Group files by their parent path
  const root: TreeNode = {
    name: parentFolder || "Extraction",
    path: "/",
    isDir: true,
    size: 0,
    children: [],
  };
  
  // Sort files - directories first (indicated by ../), then by name
  const sortedFiles = [...files].sort((a, b) => {
    const aIsParent = a.filename.startsWith("../");
    const bIsParent = b.filename.startsWith("../");
    if (aIsParent && !bIsParent) return 1;
    if (!aIsParent && bIsParent) return -1;
    return a.filename.localeCompare(b.filename);
  });
  
  for (const file of sortedFiles) {
    // Handle files in parent directory (marked with ../)
    if (file.filename.startsWith("../")) {
      const fileName = file.filename.substring(3);
      root.children!.push({
        name: `📁 ../${fileName}`,
        path: file.filename,
        isDir: false,
        size: file.size,
        type: file.file_type,
        hash: file.stored_hash,
      });
    } else {
      root.children!.push({
        name: file.filename,
        path: file.filename,
        isDir: false,
        size: file.size,
        type: file.file_type,
        hash: file.stored_hash,
      });
    }
    root.size += file.size;
  }
  
  return root.children!.length > 0 ? [root] : [];
}

// Tree node component
function TreeNodeItem(props: { 
  node: TreeNode; 
  depth: number;
  expanded: boolean;
  onToggle: (path: string) => void;
}) {
  const indent = () => props.depth * 16;
  const icon = () => {
    if (props.node.isDir) {
      return props.expanded ? "📂" : "📁";
    }
    // Determine icon based on type
    const type = props.node.type?.toLowerCase() || "";
    if (type.includes("zip")) return "🗜️";
    if (type.includes("pdf")) return "📕";
    if (type.includes("xml") || type.includes("ufdx")) return "📋";
    if (type.includes("ufd") || type.includes("ufdr")) return "📱";
    if (type.includes("report")) return "📝";
    return "📄";
  };
  
  const handleClick = () => {
    if (props.node.isDir && props.node.children) {
      props.onToggle(props.node.path);
    }
  };
  
  return (
    <>
      <div 
        class={`tree-node ${props.node.isDir ? 'dir' : 'file'}`}
        style={{ "padding-left": `${indent()}px` }}
        onClick={handleClick}
        title={props.node.path}
      >
        <span class="tree-icon">{icon()}</span>
        <span class="tree-name" title={props.node.name}>{props.node.name}</span>
        <Show when={!props.node.isDir && props.node.size > 0}>
          <span class="tree-size">{formatBytes(props.node.size)}</span>
        </Show>
        <Show when={props.node.type && !props.node.isDir}>
          <span class="tree-type">{props.node.type}</span>
        </Show>
        <Show when={props.node.hash}>
          <span class="tree-hash-badge" title={props.node.hash || ""}>✓</span>
        </Show>
      </div>
      <Show when={props.node.isDir && props.expanded && props.node.children}>
        <For each={props.node.children}>
          {(child) => (
            <TreeNodeItem 
              node={child} 
              depth={props.depth + 1}
              expanded={true}
              onToggle={props.onToggle}
            />
          )}
        </For>
      </Show>
    </>
  );
}

export function TreePanel(props: TreePanelProps) {
  const [expandedPaths, setExpandedPaths] = createSignal<Set<string>>(new Set(["/"]) );
  
  const togglePath = (path: string) => {
    setExpandedPaths(prev => {
      const newSet = new Set(prev);
      if (newSet.has(path)) {
        newSet.delete(path);
      } else {
        newSet.add(path);
      }
      return newSet;
    });
  };
  
  // Build tree from container info
  const treeData = createMemo(() => {
    if (!props.info) return [];
    
    // UFED: use associated_files
    if (props.info.ufed?.associated_files) {
      return buildTreeFromAssociatedFiles(
        props.info.ufed.associated_files,
        props.info.ufed.parent_folder || props.info.ufed.device_hint || undefined
      );
    }
    
    // AD1: use tree entries if available
    if (props.info.ad1?.tree) {
      const entries = props.info.ad1.tree;
      const root: TreeNode = {
        name: props.info.ad1.logical.data_source_name || "AD1 Contents",
        path: "/",
        isDir: true,
        size: 0,
        children: [],
      };
      
      // Build tree from flat entries
      for (const entry of entries.slice(0, 50)) { // Limit to first 50 for performance
        root.children!.push({
          name: entry.path.split(/[/\\]/).pop() || entry.path,
          path: entry.path,
          isDir: entry.is_dir,
          size: entry.size,
        });
        root.size += entry.size;
      }
      
      if (entries.length > 50) {
        root.children!.push({
          name: `... and ${entries.length - 50} more items`,
          path: "_more_",
          isDir: false,
          size: 0,
        });
      }
      
      return root.children!.length > 0 ? [root] : [];
    }
    
    // Archive: use entry count hint
    if (props.info.archive) {
      const arch = props.info.archive;
      const root: TreeNode = {
        name: `${arch.format} Archive`,
        path: "/",
        isDir: true,
        size: arch.total_size,
        children: [{
          name: `${arch.entry_count} entries (tree not loaded)`,
          path: "_entries_",
          isDir: false,
          size: 0,
        }],
      };
      return [root];
    }
    
    return [];
  });
  
  const hasTree = () => treeData().length > 0;
  
  return (
    <aside class="tree-panel">
      <div class="tree-header">
        <span class="tree-title">📁 Files</span>
        <Show when={hasTree()}>
          <span class="tree-count">{treeData()[0]?.children?.length || 0}</span>
        </Show>
      </div>
      
      <div class="tree-content">
        <Show 
          when={hasTree()}
          fallback={
            <div class="tree-empty">
              <span>No file tree available</span>
              <span class="tree-empty-hint">Select a UFED, AD1, or archive file</span>
            </div>
          }
        >
          <For each={treeData()}>
            {(node) => (
              <TreeNodeItem 
                node={node} 
                depth={0}
                expanded={expandedPaths().has(node.path)}
                onToggle={togglePath}
              />
            )}
          </For>
        </Show>
      </div>
    </aside>
  );
}

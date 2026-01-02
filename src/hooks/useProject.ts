import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { 
  FFXProject, 
  ProjectSaveResult, 
  ProjectLoadResult,
  ProjectTab,
  ProjectHashHistory,
  DiscoveredFile,
  HashHistoryEntry
} from "../types";

/**
 * Hook for managing FFX project files (.ffxproj)
 * Handles saving/loading project state including open tabs, hash history, and UI state
 */
export function useProject() {
  // Current project state
  const [project, setProject] = createSignal<FFXProject | null>(null);
  const [projectPath, setProjectPath] = createSignal<string | null>(null);
  const [modified, setModified] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  
  /**
   * Check if a project exists for the given root directory
   */
  const checkProjectExists = async (rootPath: string): Promise<string | null> => {
    try {
      return await invoke<string | null>("project_check_exists", { rootPath });
    } catch (e) {
      console.warn("Failed to check project:", e);
      return null;
    }
  };
  
  /**
   * Get the default project path for a root directory
   */
  const getDefaultProjectPath = async (rootPath: string): Promise<string> => {
    return await invoke<string>("project_get_default_path", { rootPath });
  };
  
  /**
   * Create a new project for the given root directory
   */
  const createProject = async (rootPath: string): Promise<FFXProject> => {
    const proj = await invoke<FFXProject>("project_create", { rootPath });
    setProject(proj);
    setProjectPath(null); // Not saved yet
    setModified(true);
    return proj;
  };
  
  /**
   * Build project from current app state
   */
  const buildProjectFromState = (
    rootPath: string,
    openTabs: { file: DiscoveredFile; id: string }[],
    activeTabPath: string | null,
    hashHistory: Map<string, HashHistoryEntry[]>
  ): FFXProject => {
    const existingProject = project();
    
    // Convert tabs to project format
    const tabs: ProjectTab[] = openTabs.map((tab, index) => ({
      file_path: tab.file.path,
      order: index,
    }));
    
    // Convert hash history to project format
    const hashHistoryObj: ProjectHashHistory = {
      files: {},
    };
    hashHistory.forEach((entries, filePath) => {
      hashHistoryObj.files[filePath] = entries.map(entry => ({
        algorithm: entry.algorithm,
        hash_value: entry.hash,
        computed_at: entry.timestamp instanceof Date 
          ? entry.timestamp.toISOString() 
          : String(entry.timestamp),
        verified: entry.verified && entry.verified_against ? {
          result: "match" as const,
          verified_at: entry.timestamp instanceof Date 
            ? entry.timestamp.toISOString() 
            : String(entry.timestamp),
        } : undefined,
      }));
    });
    
    const now = new Date().toISOString();
    const name = rootPath.split('/').pop() || 'Untitled';
    
    return {
      version: 1,
      name: existingProject?.name || name,
      root_path: rootPath,
      created_at: existingProject?.created_at || now,
      saved_at: now,
      app_version: "0.1.0", // Should come from package.json
      tabs,
      active_tab_path: activeTabPath,
      hash_history: hashHistoryObj,
      ui_state: existingProject?.ui_state || {
        panel_sizes: [],
        expanded_paths: [],
        scroll_positions: {},
      },
      notes: existingProject?.notes,
      tags: existingProject?.tags || [],
    };
  };
  
  /**
   * Save current project state
   */
  const saveProject = async (
    rootPath: string,
    openTabs: { file: DiscoveredFile; id: string }[],
    activeTabPath: string | null,
    hashHistory: Map<string, HashHistoryEntry[]>,
    customPath?: string
  ): Promise<ProjectSaveResult> => {
    try {
      // Build project from current state
      const proj = buildProjectFromState(rootPath, openTabs, activeTabPath, hashHistory);
      
      // Determine save path
      let savePath = customPath || projectPath();
      
      // If no path, ask for one
      if (!savePath) {
        const defaultPath = await getDefaultProjectPath(rootPath);
        const selected = await save({
          defaultPath,
          filters: [{ name: "FFX Project", extensions: ["ffxproj"] }],
          title: "Save Project",
        });
        
        if (!selected) {
          return { success: false, error: "Save cancelled" };
        }
        savePath = selected;
      }
      
      // Save via Tauri
      const result = await invoke<ProjectSaveResult>("project_save", {
        project: proj,
        path: savePath,
      });
      
      if (result.success) {
        setProject(proj);
        setProjectPath(result.path || savePath);
        setModified(false);
        setError(null);
        console.log(`Project saved to: ${result.path}`);
      } else {
        setError(result.error || "Failed to save project");
      }
      
      return result;
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      setError(errorMsg);
      return { success: false, error: errorMsg };
    }
  };
  
  /**
   * Save project to a new location (Save As)
   */
  const saveProjectAs = async (
    rootPath: string,
    openTabs: { file: DiscoveredFile; id: string }[],
    activeTabPath: string | null,
    hashHistory: Map<string, HashHistoryEntry[]>
  ): Promise<ProjectSaveResult> => {
    const defaultPath = await getDefaultProjectPath(rootPath);
    const selected = await save({
      defaultPath,
      filters: [{ name: "FFX Project", extensions: ["ffxproj"] }],
      title: "Save Project As",
    });
    
    if (!selected) {
      return { success: false, error: "Save cancelled" };
    }
    
    return saveProject(rootPath, openTabs, activeTabPath, hashHistory, selected);
  };
  
  /**
   * Load a project from file
   */
  const loadProject = async (
    customPath?: string
  ): Promise<{ project: FFXProject | null; error?: string }> => {
    try {
      let loadPath = customPath;
      
      // If no path provided, show file picker
      if (!loadPath) {
        const selected = await open({
          filters: [{ name: "FFX Project", extensions: ["ffxproj"] }],
          title: "Open Project",
          multiple: false,
        });
        
        if (!selected) {
          return { project: null, error: "Open cancelled" };
        }
        loadPath = selected as string;
      }
      
      // Load via Tauri
      const result = await invoke<ProjectLoadResult>("project_load", {
        path: loadPath,
      });
      
      if (result.success && result.project) {
        setProject(result.project);
        setProjectPath(loadPath);
        setModified(false);
        setError(null);
        console.log(`Project loaded: ${result.project.name}`);
        return { project: result.project };
      } else {
        const errorMsg = result.error || "Failed to load project";
        setError(errorMsg);
        return { project: null, error: errorMsg };
      }
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      setError(errorMsg);
      return { project: null, error: errorMsg };
    }
  };
  
  /**
   * Mark project as modified (call when state changes)
   */
  const markModified = () => {
    if (project() || projectPath()) {
      setModified(true);
    }
  };
  
  /**
   * Clear current project
   */
  const clearProject = () => {
    setProject(null);
    setProjectPath(null);
    setModified(false);
    setError(null);
  };
  
  return {
    // State
    project,
    projectPath,
    modified,
    error,
    
    // Actions
    checkProjectExists,
    getDefaultProjectPath,
    createProject,
    saveProject,
    saveProjectAs,
    loadProject,
    markModified,
    clearProject,
  };
}

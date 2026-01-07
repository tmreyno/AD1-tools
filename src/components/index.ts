// Re-export components
export { Toolbar } from "./Toolbar";
export { StatusBar } from "./StatusBar";
export { FilePanel } from "./FilePanel";
export { FileRow } from "./FileRow";
export { DetailPanel } from "./DetailPanel";
export { DetailPanelContent } from "./DetailPanelContent";
export { TabBar } from "./TabBar";
export type { OpenTab, TabViewMode } from "./TabBar";
export { TreePanel } from "./TreePanel";
export { ProgressModal } from "./ProgressModal";
export { HexViewer } from "./HexViewer";
// Viewer types are now in types.ts but re-exported from HexViewer for backward compatibility
export type { ParsedMetadata, FileTypeInfo, HeaderRegion, MetadataField } from "../types";
export { MetadataPanel } from "./MetadataPanel";
export { TextViewer } from "./TextViewer";

// Report components
export { ReportWizard } from "./report";
export type { ForensicReport as ReportData, OutputFormat as ReportFormat } from "./report";

// Project Setup
export { default as ProjectSetupWizard } from "./ProjectSetupWizard";
export type { ProjectLocations } from "./ProjectSetupWizard";

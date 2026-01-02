// =============================================================================
// REPORT MODULE - JSON-based forensic report generation
// =============================================================================

// Type exports
export type {
  ForensicReport,
  ReportMeta,
  CaseInfo,
  EvidenceItem,
  HashRecord,
  ContainerMetadata,
  DeviceInfo,
  ExtractionInfo,
  SessionInfo,
  ExportOptions,
  ExportFormat,
} from "./types";

// Generator exports
export {
  generateReport,
  exportAsJson,
  exportAsMarkdown,
  type ReportInput,
} from "./generator";

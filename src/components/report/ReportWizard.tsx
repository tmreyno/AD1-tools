/**
 * ReportWizard - Multi-step wizard for forensic report generation
 * 
 * Steps:
 * 1. Case Information - Enter case details
 * 2. Evidence Selection - Select which items to include
 * 3. Findings - Add/edit findings
 * 4. Preview - Review the report
 * 5. Export - Choose format and export
 */

import { createSignal, For, Show, createEffect, onMount } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import DOMPurify from "dompurify";
import type { DiscoveredFile, ContainerInfo } from "../../types";
import { 
  isAiAvailable, 
  getAiProviders, 
  checkOllamaConnection, 
  generateAiNarrative,
  buildEvidenceContext,
  type AiProviderInfo,
  type NarrativeType 
} from "../../report/api";

// Types matching the Rust backend
export type Classification = 
  | "Public"
  | "Internal"
  | "Confidential"
  | "Restricted"
  | "LawEnforcementSensitive";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type EvidenceType = "HardDrive" | "SSD" | "USBDrive" | "MemoryCard" | "MobileDevice" | "Optical" | "NetworkCapture" | "CloudStorage" | "VirtualMachine" | "ForensicImage" | "Other";

export interface ReportMetadata {
  title: string;
  report_number: string;
  version: string;
  classification: Classification;
  generated_at: string;
  generated_by: string;
}

export interface CaseInfo {
  case_number: string;
  case_name?: string;
  agency?: string;
  requestor?: string;
  request_date?: string;
  exam_start_date?: string;
  exam_end_date?: string;
  investigation_type?: string;
  description?: string;
}

export interface ExaminerInfo {
  name: string;
  title?: string;
  organization?: string;
  email?: string;
  phone?: string;
  certifications: string[];
  badge_number?: string;
}

// Hash algorithm enum matching Rust
export type HashAlgorithmType = "MD5" | "SHA1" | "SHA256" | "SHA512" | "Blake2b" | "Blake3" | "XXH3" | "XXH64";

export interface HashValue {
  item: string;
  algorithm: HashAlgorithmType;
  value: string;
  computed_at?: string;
  verified?: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  description: string;
  evidence_type: EvidenceType;
  make?: string;
  model?: string;
  serial_number?: string;
  capacity?: string;
  acquisition_date?: string;
  acquisition_method?: string;
  acquisition_tool?: string;
  acquisition_hashes: HashValue[];
  verification_hashes: HashValue[];
  notes?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  artifact_paths: string[];
  timestamps: string[];
  evidence_refs: string[];
  analysis: string;
  conclusions?: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  source: string;
  evidence_ref?: string;
  artifact_path?: string;
}

export interface ToolInfo {
  name: string;
  version: string;
  vendor?: string;
  purpose?: string;
}

export interface ForensicReport {
  metadata: ReportMetadata;
  case_info: CaseInfo;
  examiner: ExaminerInfo;
  executive_summary?: string;
  scope?: string;
  methodology?: string;
  evidence_items: EvidenceItem[];
  chain_of_custody: CustodyRecord[];
  findings: Finding[];
  timeline: TimelineEvent[];
  hash_records: HashRecord[];
  tools: ToolInfo[];
  conclusions?: string;
  appendices: Appendix[];
  notes?: string;
}

// Chain of custody record
export interface CustodyRecord {
  timestamp: string;
  action: string;
  handler: string;
  location?: string;
  notes?: string;
}

// Hash record for report
export interface HashRecord {
  algorithm: string;
  value: string;
  verified?: boolean;
  timestamp?: string;
  item_reference?: string;
}

// Appendix
export interface Appendix {
  appendix_id: string;
  title: string;
  content_type: "Markdown" | "Text" | "FileListing" | "HashTable" | "FileReference";
  content: string;
}

export interface OutputFormat {
  format: "Pdf" | "Docx" | "Html" | "Markdown" | "Typst";
  name: string;
  description: string;
  extension: string;
  supported: boolean;
}

interface ReportWizardProps {
  /** Files discovered in the workspace */
  files: DiscoveredFile[];
  /** Map of file path to container info */
  fileInfoMap: Map<string, ContainerInfo>;
  /** Map of file path to hash info */
  fileHashMap: Map<string, { algorithm: string; hash: string; verified?: boolean | null }>;
  /** Called when wizard is closed */
  onClose: () => void;
  /** Called when report is generated */
  onGenerated?: (path: string, format: string) => void;
}

// Wizard steps
type WizardStep = "case" | "examiner" | "evidence" | "findings" | "preview" | "export";

const STEPS: { id: WizardStep; label: string; icon: string }[] = [
  { id: "case", label: "Case Info", icon: "📋" },
  { id: "examiner", label: "Examiner", icon: "👤" },
  { id: "evidence", label: "Evidence", icon: "💾" },
  { id: "findings", label: "Findings", icon: "🔍" },
  { id: "preview", label: "Preview", icon: "👁️" },
  { id: "export", label: "Export", icon: "📤" },
];

const CLASSIFICATIONS: { value: Classification; label: string; color: string }[] = [
  { value: "Public", label: "Public", color: "#22c55e" },
  { value: "Internal", label: "Internal", color: "#3b82f6" },
  { value: "Confidential", label: "Confidential", color: "#f97316" },
  { value: "Restricted", label: "Restricted", color: "#ef4444" },
  { value: "LawEnforcementSensitive", label: "Law Enforcement Sensitive", color: "#a855f7" },
];

const SEVERITIES: { value: Severity; label: string; color: string }[] = [
  { value: "Critical", label: "Critical", color: "#dc2626" },
  { value: "High", label: "High", color: "#ea580c" },
  { value: "Medium", label: "Medium", color: "#ca8a04" },
  { value: "Low", label: "Low", color: "#16a34a" },
  { value: "Informational", label: "Info", color: "#6b7280" },
];

/** Evidence type options for dropdowns - exported for extensions */
export const EVIDENCE_TYPES: { value: EvidenceType; label: string }[] = [
  { value: "HardDrive", label: "Hard Drive" },
  { value: "SSD", label: "SSD" },
  { value: "USBDrive", label: "USB Drive" },
  { value: "MemoryCard", label: "Memory Card" },
  { value: "MobileDevice", label: "Mobile Device" },
  { value: "Optical", label: "Optical Media" },
  { value: "NetworkCapture", label: "Network Capture" },
  { value: "CloudStorage", label: "Cloud Storage" },
  { value: "VirtualMachine", label: "Virtual Machine" },
  { value: "ForensicImage", label: "Forensic Image" },
  { value: "Other", label: "Other" },
];

export function ReportWizard(props: ReportWizardProps) {
  // Current step
  const [currentStep, setCurrentStep] = createSignal<WizardStep>("case");
  
  // Report data
  const [caseInfo, setCaseInfo] = createSignal<CaseInfo>({
    case_number: "",
  });
  
  const [examiner, setExaminer] = createSignal<ExaminerInfo>({
    name: "",
    certifications: [],
  });
  
  const [metadata, setMetadata] = createSignal<ReportMetadata>({
    title: "Digital Forensic Examination Report",
    report_number: `FR-${new Date().getFullYear()}-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`,
    version: "1.0",
    classification: "LawEnforcementSensitive",
    generated_at: new Date().toISOString(),
    generated_by: "FFX - Forensic File Xplorer",
  });
  
  const [selectedEvidence, setSelectedEvidence] = createSignal<Set<string>>(new Set());
  const [findings, setFindings] = createSignal<Finding[]>([]);
  const [executiveSummary, setExecutiveSummary] = createSignal("");
  const [scope, setScope] = createSignal("");
  const [methodology, setMethodology] = createSignal("");
  const [conclusions, setConclusions] = createSignal("");
  
  // Preview HTML
  const [previewHtml, setPreviewHtml] = createSignal("");
  const [previewLoading, setPreviewLoading] = createSignal(false);
  
  // Export state
  const [outputFormats, setOutputFormats] = createSignal<OutputFormat[]>([]);
  const [selectedFormat, setSelectedFormat] = createSignal<string>("Pdf");
  const [exporting, setExporting] = createSignal(false);
  const [exportError, setExportError] = createSignal<string | null>(null);
  
  // New certification input
  const [newCert, setNewCert] = createSignal("");
  
  // AI Assistant state
  const [aiAvailable, setAiAvailable] = createSignal(false);
  const [aiProviders, setAiProviders] = createSignal<AiProviderInfo[]>([]);
  const [selectedProvider, setSelectedProvider] = createSignal<string>("ollama");
  const [selectedModel, setSelectedModel] = createSignal<string>("llama3.2");
  const [apiKey, setApiKey] = createSignal<string>("");
  const [ollamaConnected, setOllamaConnected] = createSignal(false);
  const [aiGenerating, setAiGenerating] = createSignal<string | null>(null); // Which section is generating
  const [aiError, setAiError] = createSignal<string | null>(null);
  const [showAiSettings, setShowAiSettings] = createSignal(false);
  
  // Auto-populate case info from container metadata
  const autoPopulateCaseInfo = () => {
    for (const file of props.files) {
      const info = props.fileInfoMap.get(file.path);
      if (!info) continue;
      
      const ewfInfo = info.e01 || info.l01;
      const ad1Info = info.ad1;
      const ufedInfo = info.ufed;
      
      // Extract case info from first container that has it
      const extractedCaseNumber = ewfInfo?.case_number ?? ad1Info?.companion_log?.case_number ?? ufedInfo?.case_info?.case_identifier;
      const extractedEvidenceNumber = ewfInfo?.evidence_number ?? ad1Info?.companion_log?.evidence_number ?? ufedInfo?.evidence_number;
      const extractedExaminer = ewfInfo?.examiner_name ?? ad1Info?.companion_log?.examiner ?? ufedInfo?.case_info?.examiner_name;
      const extractedAgency = ufedInfo?.case_info?.department;
      
      if (extractedCaseNumber || extractedEvidenceNumber || extractedExaminer) {
        // Update case info
        setCaseInfo(prev => ({
          ...prev,
          case_number: prev.case_number || extractedCaseNumber || "",
          agency: prev.agency || extractedAgency || undefined,
        }));
        
        // Update examiner
        if (extractedExaminer && !examiner().name) {
          setExaminer(prev => ({
            ...prev,
            name: extractedExaminer,
          }));
        }
        
        break; // Only use first container with info
      }
    }
  };
  
  // Load output formats and AI settings on mount
  onMount(async () => {
    try {
      const formats = await invoke<OutputFormat[]>("get_output_formats");
      setOutputFormats(formats);
    } catch (e) {
      console.warn("Failed to load output formats:", e);
      // Fallback formats
      setOutputFormats([
        { format: "Pdf", name: "PDF", description: "Portable Document Format", extension: "pdf", supported: true },
        { format: "Docx", name: "Word", description: "Microsoft Word", extension: "docx", supported: true },
        { format: "Html", name: "HTML", description: "Web page", extension: "html", supported: true },
        { format: "Markdown", name: "Markdown", description: "Plain text", extension: "md", supported: true },
      ]);
    }
    
    // Load AI settings
    try {
      const available = await isAiAvailable();
      setAiAvailable(available);
      
      if (available) {
        const providers = await getAiProviders();
        setAiProviders(providers);
        
        // Set default provider and model
        if (providers.length > 0) {
          setSelectedProvider(providers[0].id);
          setSelectedModel(providers[0].default_model);
        }
        
        // Check Ollama connection
        const ollamaOk = await checkOllamaConnection();
        setOllamaConnected(ollamaOk);
      }
    } catch (e) {
      console.warn("Failed to load AI settings:", e);
    }
    
    // Auto-select all discovered files
    const allPaths = new Set(props.files.map(f => f.path));
    setSelectedEvidence(allPaths);
    
    // Auto-populate case info from containers
    autoPopulateCaseInfo();
  });
  
  // Build the report object from current state
  const buildReport = (): ForensicReport => {
    const evidenceItems: EvidenceItem[] = [];
    
    props.files.forEach((file, index) => {
      if (!selectedEvidence().has(file.path)) return;
      
      const info = props.fileInfoMap.get(file.path);
      const hashInfo = props.fileHashMap.get(file.path);
      
      const hashes: HashValue[] = [];
      if (hashInfo) {
        // Map algorithm string to enum type
        const algoMap: Record<string, HashAlgorithmType> = {
          "md5": "MD5",
          "sha1": "SHA1", 
          "sha256": "SHA256",
          "sha512": "SHA512",
          "blake2b": "Blake2b",
          "blake3": "Blake3",
          "xxh3": "XXH3",
          "xxh64": "XXH64",
        };
        const algo = algoMap[hashInfo.algorithm.toLowerCase()] || "SHA256";
        
        hashes.push({
          item: file.filename,
          algorithm: algo,
          value: hashInfo.hash,
          verified: hashInfo.verified ?? undefined,
        });
      }
      
      // Extract info from container metadata (dig into the nested structure)
      const ewfInfo = info?.e01 || info?.l01;
      const ad1Info = info?.ad1;
      const ufedInfo = info?.ufed;
      
      // Get total size from various sources
      const totalSize = ewfInfo?.total_size ?? ad1Info?.total_size ?? file.size;
      
      // Get acquisition date from various sources
      const acquisitionDate = ewfInfo?.acquiry_date ?? ad1Info?.companion_log?.acquisition_date ?? ufedInfo?.extraction_info?.start_time;
      
      // Get serial number from various sources
      const serialNumber = ewfInfo?.serial_number ?? ufedInfo?.device_info?.serial_number;
      
      // Get acquisition tool from various sources
      const acquisitionTool = ewfInfo?.notes ?? ufedInfo?.extraction_info?.acquisition_tool ?? ad1Info?.companion_log?.notes;
      
      // Get notes from various sources
      const notes = ewfInfo?.notes ?? ad1Info?.companion_log?.notes ?? info?.note;
      
      const evidenceItem: EvidenceItem = {
        evidence_id: `E${String(index + 1).padStart(3, '0')}`,
        description: file.filename,
        evidence_type: detectEvidenceType(file, info),
        serial_number: serialNumber ?? undefined,
        capacity: totalSize ? formatBytes(totalSize) : undefined,
        acquisition_date: acquisitionDate ?? undefined,
        acquisition_tool: acquisitionTool ?? undefined,
        acquisition_hashes: hashes,
        verification_hashes: [],
        notes: notes ?? undefined,
      };
      
      evidenceItems.push(evidenceItem);
    });
    
    return {
      metadata: metadata(),
      case_info: caseInfo(),
      examiner: examiner(),
      executive_summary: executiveSummary() || undefined,
      scope: scope() || undefined,
      methodology: methodology() || undefined,
      evidence_items: evidenceItems,
      chain_of_custody: [],
      findings: findings(),
      timeline: [],
      hash_records: [],
      tools: [
        {
          name: "FFX - Forensic File Xplorer",
          version: "1.0.0",
          vendor: "FFX Team",
          purpose: "Forensic image analysis and report generation",
        },
      ],
      conclusions: conclusions() || undefined,
      appendices: [],
      notes: undefined,
    };
  };
  
  // Generate preview
  const generatePreview = async () => {
    setPreviewLoading(true);
    try {
      const report = buildReport();
      const html = await invoke<string>("preview_report", { report });
      setPreviewHtml(html);
    } catch (e) {
      console.error("Preview failed:", e);
      setPreviewHtml(`<div style="color: red; padding: 20px;">Preview failed: ${e}</div>`);
    } finally {
      setPreviewLoading(false);
    }
  };
  
  // Effect to generate preview when entering preview step
  createEffect(() => {
    if (currentStep() === "preview") {
      generatePreview();
    }
  });
  
  // Export report
  const exportReport = async () => {
    setExporting(true);
    setExportError(null);
    
    try {
      const report = buildReport();
      const format = outputFormats().find(f => f.format === selectedFormat());
      
      // Open save dialog
      const path = await save({
        title: "Save Report",
        defaultPath: `${report.metadata.report_number}.${format?.extension || 'pdf'}`,
        filters: format ? [{ name: format.name, extensions: [format.extension] }] : [],
      });
      
      if (!path) {
        setExporting(false);
        return;
      }
      
      // Generate report
      const outputPath = await invoke<string>("generate_report", {
        report,
        format: selectedFormat(),
        outputPath: path,
      });
      
      props.onGenerated?.(outputPath, selectedFormat());
      props.onClose();
    } catch (e) {
      console.error("Export failed:", e);
      setExportError(String(e));
    } finally {
      setExporting(false);
    }
  };
  
  // Navigate between steps
  const goToStep = (step: WizardStep) => {
    setCurrentStep(step);
  };
  
  const nextStep = () => {
    const idx = STEPS.findIndex(s => s.id === currentStep());
    if (idx < STEPS.length - 1) {
      setCurrentStep(STEPS[idx + 1].id);
    }
  };
  
  const prevStep = () => {
    const idx = STEPS.findIndex(s => s.id === currentStep());
    if (idx > 0) {
      setCurrentStep(STEPS[idx - 1].id);
    }
  };
  
  // Toggle evidence selection
  const toggleEvidence = (path: string) => {
    const current = selectedEvidence();
    const next = new Set(current);
    if (next.has(path)) {
      next.delete(path);
    } else {
      next.add(path);
    }
    setSelectedEvidence(next);
  };
  
  // Add finding
  const addFinding = () => {
    const newFinding: Finding = {
      id: `F${String(findings().length + 1).padStart(3, '0')}`,
      title: "",
      severity: "Medium",
      category: "General",
      description: "",
      artifact_paths: [],
      timestamps: [],
      evidence_refs: [],
      analysis: "",
    };
    setFindings([...findings(), newFinding]);
  };
  
  // Update finding
  const updateFinding = (index: number, updates: Partial<Finding>) => {
    const current = findings();
    const updated = [...current];
    updated[index] = { ...updated[index], ...updates };
    setFindings(updated);
  };
  
  // Remove finding
  const removeFinding = (index: number) => {
    setFindings(findings().filter((_, i) => i !== index));
  };
  
  // Add certification
  const addCertification = () => {
    const cert = newCert().trim();
    if (cert && !examiner().certifications.includes(cert)) {
      setExaminer({
        ...examiner(),
        certifications: [...examiner().certifications, cert],
      });
      setNewCert("");
    }
  };
  
  // Remove certification
  const removeCertification = (cert: string) => {
    setExaminer({
      ...examiner(),
      certifications: examiner().certifications.filter(c => c !== cert),
    });
  };
  
  // Get current provider info
  const currentProviderInfo = () => aiProviders().find(p => p.id === selectedProvider());
  
  // Build evidence context for AI
  const buildAiContext = () => {
    const report = buildReport();
    const evidenceContext = buildEvidenceContext(
      report.evidence_items.map(item => ({
        evidence_id: item.evidence_id,
        description: item.description,
        evidence_type: item.evidence_type,
        model: item.model,
        serial_number: item.serial_number,
        capacity: item.capacity,
        acquisition_hashes: item.acquisition_hashes.map(h => ({
          item: h.algorithm,
          algorithm: h.algorithm,
          value: h.value,
          verified: h.verified,
        })),
        image_info: item.acquisition_tool ? {
          format: "",
          file_names: [],
          total_size: 0,
          acquisition_tool: item.acquisition_tool,
        } : undefined,
        notes: item.notes,
      }))
    );
    
    // Add case context
    let context = `=== CASE INFORMATION ===\n`;
    context += `Case Number: ${caseInfo().case_number || "Not specified"}\n`;
    context += `Case Name: ${caseInfo().case_name || "Not specified"}\n`;
    context += `Agency: ${caseInfo().agency || "Not specified"}\n`;
    context += `Investigation Type: ${caseInfo().investigation_type || "Not specified"}\n`;
    context += `\n${evidenceContext}`;
    
    // Add existing findings summary
    if (findings().length > 0) {
      context += `\n=== FINDINGS ===\n`;
      for (const finding of findings()) {
        context += `- ${finding.title} (${finding.severity}): ${finding.description}\n`;
      }
    }
    
    return context;
  };
  
  // Generate AI narrative for a section
  const generateNarrative = async (type: NarrativeType, setter: (value: string) => void) => {
    if (!aiAvailable() || aiGenerating()) return;
    
    // Check Ollama connection for Ollama provider
    if (selectedProvider() === "ollama" && !ollamaConnected()) {
      setAiError("Ollama is not running. Please start Ollama first (run 'ollama serve' in terminal).");
      return;
    }
    
    // Check API key for OpenAI
    if (selectedProvider() === "openai" && !apiKey()) {
      setAiError("OpenAI API key is required. Please enter your API key in AI settings.");
      setShowAiSettings(true);
      return;
    }
    
    setAiGenerating(type);
    setAiError(null);
    
    try {
      const context = buildAiContext();
      const result = await generateAiNarrative(
        context,
        type,
        selectedProvider(),
        selectedModel(),
        selectedProvider() === "openai" ? apiKey() : undefined
      );
      setter(result);
    } catch (e) {
      console.error("AI generation failed:", e);
      setAiError(String(e));
    } finally {
      setAiGenerating(null);
    }
  };
  
  // Refresh Ollama connection status
  const refreshOllamaStatus = async () => {
    try {
      const connected = await checkOllamaConnection();
      setOllamaConnected(connected);
    } catch (e) {
      setOllamaConnected(false);
    }
  };

  return (
    <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div class="bg-bg-panel rounded-lg shadow-xl w-[900px] max-h-[85vh] flex flex-col">
        {/* Header */}
        <div class="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 class="text-lg font-semibold">📝 Generate Forensic Report</h2>
          <button 
            class="text-txt-muted hover:text-txt p-1"
            onClick={props.onClose}
          >
            ✕
          </button>
        </div>
        
        {/* Step indicators */}
        <div class="flex items-center gap-1 px-4 py-2 border-b border-border bg-bg-card">
          <For each={STEPS}>
            {(step, index) => (
              <>
                <button
                  class={`flex items-center gap-1.5 px-3 py-1.5 rounded text-sm transition-colors ${
                    currentStep() === step.id 
                      ? 'bg-accent text-white' 
                      : 'text-txt-muted hover:bg-bg-hover'
                  }`}
                  onClick={() => goToStep(step.id)}
                >
                  <span>{step.icon}</span>
                  <span>{step.label}</span>
                </button>
                <Show when={index() < STEPS.length - 1}>
                  <span class="text-txt-muted">→</span>
                </Show>
              </>
            )}
          </For>
        </div>
        
        {/* Content area */}
        <div class="flex-1 overflow-y-auto p-4">
          {/* Step 1: Case Information */}
          <Show when={currentStep() === "case"}>
            <div class="space-y-4">
              <h3 class="text-lg font-medium">Case Information</h3>
              
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium mb-1">Case Number *</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={caseInfo().case_number}
                    onInput={(e) => setCaseInfo({ ...caseInfo(), case_number: e.currentTarget.value })}
                    placeholder="e.g., 2026-CF-00123"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Case Name</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={caseInfo().case_name || ""}
                    onInput={(e) => setCaseInfo({ ...caseInfo(), case_name: e.currentTarget.value || undefined })}
                    placeholder="e.g., State v. John Doe"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Agency/Department</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={caseInfo().agency || ""}
                    onInput={(e) => setCaseInfo({ ...caseInfo(), agency: e.currentTarget.value || undefined })}
                    placeholder="e.g., Metro Police Department"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Requestor</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={caseInfo().requestor || ""}
                    onInput={(e) => setCaseInfo({ ...caseInfo(), requestor: e.currentTarget.value || undefined })}
                    placeholder="e.g., Det. Jane Smith"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Investigation Type</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={caseInfo().investigation_type || ""}
                    onInput={(e) => setCaseInfo({ ...caseInfo(), investigation_type: e.currentTarget.value || undefined })}
                    placeholder="e.g., Fraud Investigation"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Classification</label>
                  <select
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={metadata().classification}
                    onChange={(e) => setMetadata({ ...metadata(), classification: e.currentTarget.value as Classification })}
                  >
                    <For each={CLASSIFICATIONS}>
                      {(c) => <option value={c.value}>{c.label}</option>}
                    </For>
                  </select>
                </div>
              </div>
              
              <div>
                <label class="block text-sm font-medium mb-1">Case Description</label>
                <textarea
                  class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent h-24 resize-none"
                  value={caseInfo().description || ""}
                  onInput={(e) => setCaseInfo({ ...caseInfo(), description: e.currentTarget.value || undefined })}
                  placeholder="Brief description of the case and examination request..."
                />
              </div>
              
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium mb-1">Report Title</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={metadata().title}
                    onInput={(e) => setMetadata({ ...metadata(), title: e.currentTarget.value })}
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Report Number</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={metadata().report_number}
                    onInput={(e) => setMetadata({ ...metadata(), report_number: e.currentTarget.value })}
                  />
                </div>
              </div>
            </div>
          </Show>
          
          {/* Step 2: Examiner Information */}
          <Show when={currentStep() === "examiner"}>
            <div class="space-y-4">
              <h3 class="text-lg font-medium">Examiner Information</h3>
              
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium mb-1">Full Name *</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={examiner().name}
                    onInput={(e) => setExaminer({ ...examiner(), name: e.currentTarget.value })}
                    placeholder="e.g., John Smith"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Title</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={examiner().title || ""}
                    onInput={(e) => setExaminer({ ...examiner(), title: e.currentTarget.value || undefined })}
                    placeholder="e.g., Senior Digital Forensic Examiner"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Organization</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={examiner().organization || ""}
                    onInput={(e) => setExaminer({ ...examiner(), organization: e.currentTarget.value || undefined })}
                    placeholder="e.g., Metro Police Forensic Lab"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Badge/ID Number</label>
                  <input
                    type="text"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={examiner().badge_number || ""}
                    onInput={(e) => setExaminer({ ...examiner(), badge_number: e.currentTarget.value || undefined })}
                    placeholder="e.g., F-1234"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Email</label>
                  <input
                    type="email"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={examiner().email || ""}
                    onInput={(e) => setExaminer({ ...examiner(), email: e.currentTarget.value || undefined })}
                    placeholder="e.g., jsmith@agency.gov"
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Phone</label>
                  <input
                    type="tel"
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={examiner().phone || ""}
                    onInput={(e) => setExaminer({ ...examiner(), phone: e.currentTarget.value || undefined })}
                    placeholder="e.g., (555) 123-4567"
                  />
                </div>
              </div>
              
              <div>
                <label class="block text-sm font-medium mb-1">Certifications</label>
                <div class="flex gap-2 mb-2">
                  <input
                    type="text"
                    class="flex-1 px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent"
                    value={newCert()}
                    onInput={(e) => setNewCert(e.currentTarget.value)}
                    onKeyDown={(e) => e.key === "Enter" && addCertification()}
                    placeholder="e.g., EnCE, GCFE, ACE..."
                  />
                  <button
                    class="btn btn-default"
                    onClick={addCertification}
                  >
                    Add
                  </button>
                </div>
                <div class="flex flex-wrap gap-2">
                  <For each={examiner().certifications}>
                    {(cert) => (
                      <span class="inline-flex items-center gap-1 px-2 py-1 bg-accent/20 text-accent rounded text-sm">
                        {cert}
                        <button
                          class="text-accent/70 hover:text-accent"
                          onClick={() => removeCertification(cert)}
                        >
                          ×
                        </button>
                      </span>
                    )}
                  </For>
                </div>
              </div>
            </div>
          </Show>
          
          {/* Step 3: Evidence Selection */}
          <Show when={currentStep() === "evidence"}>
            <div class="space-y-4">
              <div class="flex items-center justify-between">
                <h3 class="text-lg font-medium">Evidence Items</h3>
                <span class="text-sm text-txt-muted">
                  {selectedEvidence().size} of {props.files.length} selected
                </span>
              </div>
              
              <Show when={props.files.length === 0}>
                <div class="text-center py-8 text-txt-muted">
                  <p class="text-4xl mb-2">📂</p>
                  <p>No evidence files discovered.</p>
                  <p class="text-sm">Scan a directory first to discover forensic images.</p>
                </div>
              </Show>
              
              <div class="space-y-2">
                <For each={props.files}>
                  {(file) => {
                    const info = () => props.fileInfoMap.get(file.path);
                    const hashInfo = () => props.fileHashMap.get(file.path);
                    const isSelected = () => selectedEvidence().has(file.path);
                    
                    // Extract display info from container
                    const displayInfo = () => {
                      const i = info();
                      if (!i) return null;
                      const ewfInfo = i.e01 || i.l01;
                      const ad1Info = i.ad1;
                      const totalSize = ewfInfo?.total_size ?? ad1Info?.total_size;
                      const acqDate = ewfInfo?.acquiry_date ?? ad1Info?.companion_log?.acquisition_date;
                      return { totalSize, acqDate };
                    };
                    
                    return (
                      <div 
                        class={`flex items-start gap-3 p-3 rounded border cursor-pointer transition-colors ${
                          isSelected() 
                            ? 'border-accent bg-accent/10' 
                            : 'border-border hover:border-border-hover'
                        }`}
                        onClick={() => toggleEvidence(file.path)}
                      >
                        <input
                          type="checkbox"
                          class="mt-1 accent-accent"
                          checked={isSelected()}
                          onChange={() => {}}
                        />
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-2">
                            <span class="font-medium truncate">{file.filename}</span>
                            <span class="text-xs px-1.5 py-0.5 bg-bg-card rounded text-txt-muted">
                              {file.container_type}
                            </span>
                          </div>
                          <div class="text-sm text-txt-muted truncate">{file.path}</div>
                          <Show when={displayInfo()}>
                            <div class="text-xs text-txt-muted mt-1">
                              {displayInfo()!.totalSize ? formatBytes(displayInfo()!.totalSize!) : ""}
                              {displayInfo()!.acqDate ? ` • ${displayInfo()!.acqDate}` : ""}
                            </div>
                          </Show>
                          <Show when={hashInfo()}>
                            <div class="text-xs font-mono text-accent mt-1 truncate">
                              {hashInfo()!.algorithm}: {hashInfo()!.hash}
                              {hashInfo()!.verified === true && " ✓"}
                              {hashInfo()!.verified === false && " ✗"}
                            </div>
                          </Show>
                        </div>
                      </div>
                    );
                  }}
                </For>
              </div>
            </div>
          </Show>
          
          {/* Step 4: Findings */}
          <Show when={currentStep() === "findings"}>
            <div class="space-y-4">
              {/* AI Settings Panel */}
              <Show when={aiAvailable()}>
                <div class="border border-accent/30 rounded p-3 bg-accent/5">
                  <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                      <span class="text-lg">🤖</span>
                      <span class="font-medium">AI Report Assistant</span>
                      <Show when={selectedProvider() === "ollama"}>
                        <span class={`text-xs px-1.5 py-0.5 rounded ${ollamaConnected() ? 'bg-success/20 text-success' : 'bg-error/20 text-error'}`}>
                          {ollamaConnected() ? "Connected" : "Disconnected"}
                        </span>
                      </Show>
                    </div>
                    <button 
                      class="text-sm text-accent hover:underline"
                      onClick={() => setShowAiSettings(!showAiSettings())}
                    >
                      {showAiSettings() ? "Hide Settings" : "Settings"}
                    </button>
                  </div>
                  
                  <Show when={showAiSettings()}>
                    <div class="grid grid-cols-3 gap-3 mt-3 pt-3 border-t border-border">
                      <div>
                        <label class="block text-xs text-txt-muted mb-1">Provider</label>
                        <select
                          class="w-full px-2 py-1.5 bg-bg border border-border rounded text-sm"
                          value={selectedProvider()}
                          onChange={(e) => {
                            const provider = e.currentTarget.value;
                            setSelectedProvider(provider);
                            const info = aiProviders().find(p => p.id === provider);
                            if (info) setSelectedModel(info.default_model);
                            if (provider === "ollama") refreshOllamaStatus();
                          }}
                        >
                          <For each={aiProviders()}>
                            {(p) => <option value={p.id}>{p.name}</option>}
                          </For>
                        </select>
                      </div>
                      
                      <div>
                        <label class="block text-xs text-txt-muted mb-1">Model</label>
                        <select
                          class="w-full px-2 py-1.5 bg-bg border border-border rounded text-sm"
                          value={selectedModel()}
                          onChange={(e) => setSelectedModel(e.currentTarget.value)}
                        >
                          <For each={currentProviderInfo()?.available_models || []}>
                            {(m) => <option value={m}>{m}</option>}
                          </For>
                        </select>
                      </div>
                      
                      <Show when={currentProviderInfo()?.requires_api_key}>
                        <div>
                          <label class="block text-xs text-txt-muted mb-1">API Key</label>
                          <input
                            type="password"
                            class="w-full px-2 py-1.5 bg-bg border border-border rounded text-sm"
                            value={apiKey()}
                            onInput={(e) => setApiKey(e.currentTarget.value)}
                            placeholder="sk-..."
                          />
                        </div>
                      </Show>
                      
                      <Show when={selectedProvider() === "ollama" && !ollamaConnected()}>
                        <div class="col-span-3 text-sm text-error flex items-center gap-2">
                          <span>⚠️ Ollama not running.</span>
                          <button class="text-accent hover:underline" onClick={refreshOllamaStatus}>
                            Retry
                          </button>
                          <span class="text-txt-muted">| Run: <code class="bg-bg px-1 rounded">ollama serve</code></span>
                        </div>
                      </Show>
                    </div>
                  </Show>
                  
                  <Show when={aiError()}>
                    <div class="mt-2 text-sm text-error bg-error/10 rounded p-2">
                      {aiError()}
                    </div>
                  </Show>
                </div>
              </Show>
              
              <div class="flex items-center justify-between">
                <h3 class="text-lg font-medium">Findings</h3>
                <button class="btn btn-primary" onClick={addFinding}>
                  + Add Finding
                </button>
              </div>
              
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <div class="flex items-center justify-between mb-1">
                    <label class="text-sm font-medium">Executive Summary</label>
                    <Show when={aiAvailable()}>
                      <button
                        class="text-xs text-accent hover:underline disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                        onClick={() => generateNarrative("executive_summary", setExecutiveSummary)}
                        disabled={!!aiGenerating()}
                      >
                        {aiGenerating() === "executive_summary" ? "⏳ Generating..." : "🤖 Generate with AI"}
                      </button>
                    </Show>
                  </div>
                  <textarea
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent h-32 resize-none"
                    value={executiveSummary()}
                    onInput={(e) => setExecutiveSummary(e.currentTarget.value)}
                    placeholder="Brief summary for non-technical readers..."
                  />
                </div>
                
                <div>
                  <label class="block text-sm font-medium mb-1">Scope</label>
                  <textarea
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent h-32 resize-none"
                    value={scope()}
                    onInput={(e) => setScope(e.currentTarget.value)}
                    placeholder="Scope of the examination..."
                  />
                </div>
                
                <div>
                  <div class="flex items-center justify-between mb-1">
                    <label class="text-sm font-medium">Methodology</label>
                    <Show when={aiAvailable()}>
                      <button
                        class="text-xs text-accent hover:underline disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                        onClick={() => generateNarrative("methodology", setMethodology)}
                        disabled={!!aiGenerating()}
                      >
                        {aiGenerating() === "methodology" ? "⏳ Generating..." : "🤖 Generate with AI"}
                      </button>
                    </Show>
                  </div>
                  <textarea
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent h-32 resize-none"
                    value={methodology()}
                    onInput={(e) => setMethodology(e.currentTarget.value)}
                    placeholder="Examination methodology employed..."
                  />
                </div>
                
                <div>
                  <div class="flex items-center justify-between mb-1">
                    <label class="text-sm font-medium">Conclusions</label>
                    <Show when={aiAvailable()}>
                      <button
                        class="text-xs text-accent hover:underline disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                        onClick={() => generateNarrative("conclusion", setConclusions)}
                        disabled={!!aiGenerating()}
                      >
                        {aiGenerating() === "conclusion" ? "⏳ Generating..." : "🤖 Generate with AI"}
                      </button>
                    </Show>
                  </div>
                  <textarea
                    class="w-full px-3 py-2 bg-bg border border-border rounded focus:outline-none focus:border-accent h-32 resize-none"
                    value={conclusions()}
                    onInput={(e) => setConclusions(e.currentTarget.value)}
                    placeholder="Final conclusions..."
                  />
                </div>
              </div>
              
              <Show when={findings().length === 0}>
                <div class="text-center py-6 text-txt-muted border border-dashed border-border rounded">
                  <p>No findings added yet.</p>
                  <p class="text-sm">Click "Add Finding" to document discoveries.</p>
                </div>
              </Show>
              
              <For each={findings()}>
                {(finding, index) => (
                  <div class="border border-border rounded p-3 space-y-3">
                    <div class="flex items-center justify-between">
                      <span class="text-sm font-mono text-txt-muted">{finding.id}</span>
                      <button
                        class="text-error hover:text-error/80 text-sm"
                        onClick={() => removeFinding(index())}
                      >
                        Remove
                      </button>
                    </div>
                    
                    <div class="grid grid-cols-3 gap-3">
                      <div class="col-span-2">
                        <input
                          type="text"
                          class="w-full px-2 py-1.5 bg-bg border border-border rounded text-sm focus:outline-none focus:border-accent"
                          value={finding.title}
                          onInput={(e) => updateFinding(index(), { title: e.currentTarget.value })}
                          placeholder="Finding title..."
                        />
                      </div>
                      
                      <select
                        class="px-2 py-1.5 bg-bg border border-border rounded text-sm focus:outline-none focus:border-accent"
                        value={finding.severity}
                        onChange={(e) => updateFinding(index(), { severity: e.currentTarget.value as Severity })}
                      >
                        <For each={SEVERITIES}>
                          {(s) => <option value={s.value}>{s.label}</option>}
                        </For>
                      </select>
                    </div>
                    
                    <textarea
                      class="w-full px-2 py-1.5 bg-bg border border-border rounded text-sm focus:outline-none focus:border-accent h-20 resize-none"
                      value={finding.description}
                      onInput={(e) => updateFinding(index(), { description: e.currentTarget.value })}
                      placeholder="Detailed description of the finding..."
                    />
                  </div>
                )}
              </For>
            </div>
          </Show>
          
          {/* Step 5: Preview */}
          <Show when={currentStep() === "preview"}>
            <div class="space-y-4">
              <div class="flex items-center justify-between">
                <h3 class="text-lg font-medium">Report Preview</h3>
                <button 
                  class="btn btn-default"
                  onClick={generatePreview}
                  disabled={previewLoading()}
                >
                  {previewLoading() ? "Generating..." : "🔄 Refresh Preview"}
                </button>
              </div>
              
              <Show when={previewLoading()}>
                <div class="flex items-center justify-center py-12">
                  <div class="animate-spin text-2xl">⏳</div>
                </div>
              </Show>
              
              <Show when={!previewLoading() && previewHtml()}>
                <div 
                  class="border border-border rounded bg-white text-black p-4 max-h-[50vh] overflow-auto"
                  innerHTML={DOMPurify.sanitize(previewHtml() || "")}
                />
              </Show>
            </div>
          </Show>
          
          {/* Step 6: Export */}
          <Show when={currentStep() === "export"}>
            <div class="space-y-4">
              <h3 class="text-lg font-medium">Export Report</h3>
              
              <div class="grid grid-cols-2 gap-3">
                <For each={outputFormats()}>
                  {(format) => (
                    <button
                      class={`p-4 rounded border text-left transition-colors ${
                        selectedFormat() === format.format
                          ? 'border-accent bg-accent/10'
                          : format.supported
                            ? 'border-border hover:border-accent/50'
                            : 'border-border opacity-50 cursor-not-allowed'
                      }`}
                      onClick={() => format.supported && setSelectedFormat(format.format)}
                      disabled={!format.supported}
                    >
                      <div class="flex items-center gap-2 mb-1">
                        <span class="text-lg">
                          {format.format === "Pdf" && "📄"}
                          {format.format === "Docx" && "📝"}
                          {format.format === "Html" && "🌐"}
                          {format.format === "Markdown" && "📋"}
                          {format.format === "Typst" && "⚡"}
                        </span>
                        <span class="font-medium">{format.name}</span>
                        <span class="text-xs text-txt-muted">.{format.extension}</span>
                      </div>
                      <p class="text-sm text-txt-muted">{format.description}</p>
                      <Show when={!format.supported}>
                        <span class="text-xs text-warning">Coming soon</span>
                      </Show>
                    </button>
                  )}
                </For>
              </div>
              
              <Show when={exportError()}>
                <div class="p-3 bg-error/10 border border-error/30 rounded text-error text-sm">
                  Export failed: {exportError()}
                </div>
              </Show>
              
              <div class="flex items-center gap-3 pt-4 border-t border-border">
                <button
                  class="btn btn-primary flex-1"
                  onClick={exportReport}
                  disabled={exporting() || !caseInfo().case_number || !examiner().name}
                >
                  {exporting() ? "Exporting..." : `📤 Export as ${outputFormats().find(f => f.format === selectedFormat())?.name || selectedFormat()}`}
                </button>
              </div>
              
              <Show when={!caseInfo().case_number || !examiner().name}>
                <p class="text-sm text-warning">
                  ⚠️ Please fill in required fields: Case Number and Examiner Name
                </p>
              </Show>
            </div>
          </Show>
        </div>
        
        {/* Footer navigation */}
        <div class="flex items-center justify-between px-4 py-3 border-t border-border bg-bg-card">
          <button
            class="btn btn-default"
            onClick={prevStep}
            disabled={currentStep() === "case"}
          >
            ← Previous
          </button>
          
          <div class="text-sm text-txt-muted">
            Step {STEPS.findIndex(s => s.id === currentStep()) + 1} of {STEPS.length}
          </div>
          
          <Show when={currentStep() !== "export"}>
            <button
              class="btn btn-primary"
              onClick={nextStep}
            >
              Next →
            </button>
          </Show>
          
          <Show when={currentStep() === "export"}>
            <button
              class="btn btn-default"
              onClick={props.onClose}
            >
              Close
            </button>
          </Show>
        </div>
      </div>
    </div>
  );
}

// Helper functions
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function detectEvidenceType(file: DiscoveredFile, _info?: ContainerInfo): EvidenceType {
  const name = file.filename.toLowerCase();
  const type = file.container_type.toLowerCase();
  
  if (type.includes("ufed") || type.includes("cellebrite")) return "MobileDevice";
  if (name.includes("usb") || name.includes("thumb")) return "USBDrive";
  if (name.includes("ssd")) return "SSD";
  if (name.includes("sd") || name.includes("memory")) return "MemoryCard";
  if (type.includes("e01") || type.includes("ad1") || type.includes("l01")) return "ForensicImage";
  if (name.includes("vm") || name.includes("virtual")) return "VirtualMachine";
  if (name.includes("pcap") || name.includes("network")) return "NetworkCapture";
  
  return "HardDrive";
}

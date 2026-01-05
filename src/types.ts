// Shared TypeScript types for forensic container analysis

// --- Container Structure Types ---

export type SegmentHeader = {
  signature: string;
  segment_index: number;
  segment_number: number;
  fragments_size: number;
  header_size: number;
};

export type LogicalHeader = {
  signature: string;
  image_version: number;
  zlib_chunk_size: number;
  logical_metadata_addr: number;
  first_item_addr: number;
  data_source_name_length: number;
  ad_signature: string;
  data_source_name_addr: number;
  attrguid_footer_addr: number;
  locsguid_footer_addr: number;
  data_source_name: string;
};

export type TreeEntry = {
  path: string;
  is_dir: boolean;
  size: number;
  item_type: number;
};

export type VerifyEntry = {
  path: string;
  status: string;
  message?: string;
};

// --- File Discovery Types ---

export type DiscoveredFile = {
  path: string;
  filename: string;
  container_type: string;
  size: number;
  segment_count?: number;
  created?: string;
  modified?: string;
};

// --- Container Info Types ---

export type Ad1VolumeInfo = {
  volume_label?: string | null;
  filesystem?: string | null;
  os_info?: string | null;
  block_size?: number | null;
  volume_serial?: string | null;
};

export type Ad1CompanionLogInfo = {
  case_number?: string | null;
  evidence_number?: string | null;
  examiner?: string | null;
  notes?: string | null;
  md5_hash?: string | null;
  sha1_hash?: string | null;
  acquisition_date?: string | null;
};

export type Ad1Info = {
  segment: SegmentHeader;
  logical: LogicalHeader;
  item_count: number;
  tree?: TreeEntry[];
  segment_files?: string[];
  /** Size of each segment file in bytes */
  segment_sizes?: number[];
  /** Total size of all segment files combined */
  total_size?: number;
  /** Missing segment files (incomplete container) */
  missing_segments?: string[];
  volume?: Ad1VolumeInfo | null;
  companion_log?: Ad1CompanionLogInfo | null;
};

/** EWF container info (E01/L01/Ex01/Lx01 formats) */
export type EwfInfo = {
  format_version: string;
  segment_count: number;
  sector_count: number;
  bytes_per_sector: number;
  chunk_count: number;
  sectors_per_chunk: number;
  total_size: number;
  compression: string;
  case_number?: string;
  description?: string;
  examiner_name?: string;
  evidence_number?: string;
  notes?: string;
  acquiry_date?: string;
  system_date?: string;
  model?: string;
  serial_number?: string;
  stored_hashes?: StoredHash[];
  // Section offsets for hex navigation
  header_section_offset?: number;
  volume_section_offset?: number;
  hash_section_offset?: number;
  digest_section_offset?: number;
};

/** @deprecated Use EwfInfo instead - L01 uses the same EWF format */
export type L01Info = EwfInfo;

/** @deprecated Use EwfInfo instead */
export type E01Info = EwfInfo;

export type RawInfo = {
  segment_count: number;
  total_size: number;
  segment_sizes: number[];
  segment_names: string[];
  first_segment: string;
  last_segment: string;
};

export type ArchiveInfo = {
  format: string;
  segment_count: number;
  total_size: number;
  segment_names: string[];
  segment_sizes: number[];
  first_segment: string;
  last_segment: string;
  is_multipart: boolean;
  entry_count?: number | null;
  encrypted_headers: boolean;
  aes_encrypted: boolean;
  // ZIP-specific
  central_dir_offset?: number | null;
  central_dir_size?: number | null;
  // 7z-specific
  next_header_offset?: number | null;
  next_header_size?: number | null;
  /** 7z archive version (major.minor) */
  version?: string | null;
  /** Whether Start Header CRC is valid */
  start_header_crc_valid?: boolean | null;
  /** Next Header CRC value */
  next_header_crc?: number | null;
  /** Whether Cellebrite UFED files were detected inside the archive */
  cellebrite_detected?: boolean;
  /** List of Cellebrite files found (UFD, UFDR, UFDX) */
  cellebrite_files?: string[];
};

// --- UFED (Cellebrite) Types ---

export type UfedAssociatedFile = {
  filename: string;
  file_type: string;
  size: number;
  stored_hash?: string | null;
};

export type UfedCaseInfo = {
  case_identifier?: string | null;
  crime_type?: string | null;
  department?: string | null;
  device_name?: string | null;
  examiner_name?: string | null;
  location?: string | null;
};

export type UfedDeviceInfo = {
  vendor?: string | null;
  model?: string | null;
  full_name?: string | null;
  imei?: string | null;
  imei2?: string | null;
  iccid?: string | null;
  os_version?: string | null;
  serial_number?: string | null;
};

export type UfedExtractionInfo = {
  acquisition_tool?: string | null;
  tool_version?: string | null;
  unit_id?: string | null;
  extraction_type?: string | null;
  connection_type?: string | null;
  start_time?: string | null;
  end_time?: string | null;
  guid?: string | null;
  machine_name?: string | null;
};

export type UfedStoredHash = {
  filename: string;
  algorithm: string;
  hash: string;
};

export type UfedCollectionInfo = {
  evidence_id?: string | null;
  vendor?: string | null;
  model?: string | null;
  device_guid?: string | null;
  extractions: string[];
  ufdx_path: string;
};

export type UfedInfo = {
  format: string;
  size: number;
  parent_folder?: string | null;
  associated_files: UfedAssociatedFile[];
  is_extraction_set: boolean;
  device_hint?: string | null;
  case_info?: UfedCaseInfo | null;
  device_info?: UfedDeviceInfo | null;
  extraction_info?: UfedExtractionInfo | null;
  stored_hashes?: UfedStoredHash[] | null;
  evidence_number?: string | null;
  collection_info?: UfedCollectionInfo | null;
};

// --- Hash Types ---

export type StoredHash = {
  algorithm: string;
  hash: string;
  verified?: boolean | null;
  timestamp?: string | null;
  source?: string | null;
  /** Filename this hash belongs to (for UFED which has per-file hashes) */
  filename?: string | null;
  /** Byte offset in file where raw hash bytes are located */
  offset?: number | null;
  /** Size in bytes of the hash (MD5=16, SHA1=20, SHA256=32) */
  size?: number | null;
};

export type SegmentHash = {
  segment_name: string;
  segment_number: number;
  algorithm: string;
  hash: string;
  offset_from?: number | null;
  offset_to?: number | null;
  size?: number | null;
  verified?: boolean | null;
};

export type SegmentHashResult = {
  segment_name: string;
  segment_number: number;
  segment_path: string;
  algorithm: string;
  computed_hash: string;
  expected_hash?: string | null;
  verified?: boolean | null;
  size: number;
  duration_secs: number;
};

export type HashHistoryEntry = {
  algorithm: string;
  hash: string;
  timestamp: Date;
  source: "computed" | "stored" | "verified";
  verified?: boolean | null;
  verified_against?: string | null;
};

// --- Companion Log Types ---

export type CompanionLogInfo = {
  log_path: string;
  created_by?: string;
  case_number?: string;
  evidence_number?: string;
  unique_description?: string;
  examiner?: string;
  notes?: string;
  acquisition_started?: string;
  acquisition_finished?: string;
  verification_started?: string;
  verification_finished?: string;
  stored_hashes: StoredHash[];
  segment_list: string[];
  segment_hashes: SegmentHash[];
};

// --- Combined Container Info ---

export type ContainerInfo = {
  container: string;
  ad1?: Ad1Info | null;
  /** EWF physical image (E01/Ex01) */
  e01?: EwfInfo | null;
  /** EWF logical evidence (L01/Lx01) */
  l01?: EwfInfo | null;
  raw?: RawInfo | null;
  archive?: ArchiveInfo | null;
  ufed?: UfedInfo | null;
  note?: string | null;
  companion_log?: CompanionLogInfo | null;
};

// --- Hash Algorithm Types ---

export type HashAlgorithm = "md5" | "sha1" | "sha256" | "sha512" | "blake3" | "blake2" | "xxh3" | "xxh64" | "crc32";

export type HashAlgorithmInfo = { 
  value: HashAlgorithm; 
  label: string; 
  speed: "fast" | "medium" | "slow";
  forensic: boolean;  // Court-accepted for forensics
  cryptographic: boolean;
};

export const HASH_ALGORITHMS: HashAlgorithmInfo[] = [
  { value: "sha1", label: "SHA-1", speed: "medium", forensic: true, cryptographic: true },
  { value: "sha256", label: "SHA-256", speed: "medium", forensic: true, cryptographic: true },
  { value: "md5", label: "MD5", speed: "medium", forensic: true, cryptographic: false },
  { value: "blake3", label: "BLAKE3 ⚡", speed: "fast", forensic: false, cryptographic: true },
  { value: "sha512", label: "SHA-512", speed: "slow", forensic: true, cryptographic: true },
  { value: "blake2", label: "BLAKE2b", speed: "fast", forensic: false, cryptographic: true },
  { value: "xxh3", label: "XXH3 ⚡⚡", speed: "fast", forensic: false, cryptographic: false },
  { value: "xxh64", label: "XXH64 ⚡⚡", speed: "fast", forensic: false, cryptographic: false },
  { value: "crc32", label: "CRC32", speed: "fast", forensic: false, cryptographic: false },
];

// --- Database Persistence Types ---

/** A session represents an open directory/workspace */
export type DbSession = {
  id: string;
  name: string;
  root_path: string;
  created_at: string;
  last_opened_at: string;
};

/** A file record in the database */
export type DbFileRecord = {
  id: string;
  session_id: string;
  path: string;
  filename: string;
  container_type: string;
  total_size: number;
  segment_count: number;
  discovered_at: string;
};

/** A hash record - immutable audit trail */
export type DbHashRecord = {
  id: string;
  file_id: string;
  algorithm: string;
  hash_value: string;
  computed_at: string;
  segment_index?: number | null;
  segment_name?: string | null;
  source: "computed" | "stored" | "imported";
};

/** A verification record */
export type DbVerificationRecord = {
  id: string;
  hash_id: string;
  verified_at: string;
  result: "match" | "mismatch";
  expected_hash: string;
  actual_hash: string;
};

/** An open tab record for UI state */
export type DbOpenTabRecord = {
  id: string;
  session_id: string;
  file_path: string;
  tab_order: number;
  is_active: boolean;
};

// --- Project File Types ---
// Project types are now defined in types/project.ts for comprehensive state management
// Re-export for backward compatibility
export * from './types/project';

// --- Viewer Types (from viewer.rs) ---

/** A chunk of file data for hex viewer display */
export type FileChunk = {
  bytes: number[];
  offset: number;
  total_size: number;
  has_more: boolean;
  has_prev: boolean;
};

/** A highlighted region in the hex viewer */
export type HeaderRegion = {
  start: number;
  end: number;
  name: string;
  /** CSS class name for coloring */
  color_class: string;
  description: string;
};

/** A parsed metadata field from a file header */
export type MetadataField = {
  key: string;
  value: string;
  category: string;
  linked_region?: string;
  source_offset?: number;
};

/** Parsed metadata from a file header */
export type ParsedMetadata = {
  format: string;
  version: string | null;
  fields: MetadataField[];
  regions: HeaderRegion[];
};

/** File type detection result */
export type FileTypeInfo = {
  mime_type: string | null;
  description: string;
  extension: string;
  is_text: boolean;
  is_forensic_format: boolean;
  magic_hex: string;
};

// Re-export processed database types
export * from './types/processed';

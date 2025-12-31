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
  volume?: Ad1VolumeInfo | null;
  companion_log?: Ad1CompanionLogInfo | null;
};

export type E01Info = {
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
};

export type L01Info = {
  format_version: number;
  case_info: string;
  examiner?: string;
  description?: string;
  file_count: number;
  total_size: number;
};

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
  e01?: E01Info | null;
  l01?: L01Info | null;
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

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

export type Ad1Info = {
  segment: SegmentHeader;
  logical: LogicalHeader;
  item_count: number;
  tree?: TreeEntry[];
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
  note?: string | null;
  companion_log?: CompanionLogInfo | null;
};

// --- Hash Algorithm Types ---

export type HashAlgorithm = "md5" | "sha1" | "sha256" | "sha512" | "blake3" | "blake2" | "xxh3" | "xxh64" | "crc32";

export const HASH_ALGORITHMS: { value: HashAlgorithm; label: string }[] = [
  { value: "md5", label: "MD5" },
  { value: "sha1", label: "SHA-1" },
  { value: "sha256", label: "SHA-256" },
  { value: "sha512", label: "SHA-512" },
  { value: "blake3", label: "BLAKE3" },
  { value: "blake2", label: "BLAKE2b" },
  { value: "xxh3", label: "XXH3" },
  { value: "xxh64", label: "XXH64" },
  { value: "crc32", label: "CRC32" },
];

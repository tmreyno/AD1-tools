# Format Unification Refactoring Notes

## Overview

This document summarizes the inconsistencies found across forensic format modules and the refactoring performed to unify them.

## Completed Changes

### 1. ✅ Deleted Dead Code (`e01.rs`)
- **File**: `src/e01.rs` (1,080 lines)
- **Issue**: Old/duplicate E01 parser that was never imported
- **Action**: Deleted - the `ewf/` module is the active implementation

### 2. ✅ Added L01 Verification Support
- **File**: `src/l01.rs`
- **Added Functions**:
  - `verify(path, algorithm)` - Verify L01 container integrity
  - `verify_with_progress(path, algorithm, callback)` - Verify with progress reporting
- **New Type**: `L01VerifyEntry` for verification results

### 3. ✅ Enhanced L01Info Structure
- **File**: `src/l01.rs`
- **Added Fields**:
  - `evidence_number: Option<String>` - Evidence identifier
  - `stored_hashes: Vec<StoredHash>` - Embedded hash values from metadata
- **Benefit**: L01Info now consistent with other format info structures

### 4. ✅ Updated Containers Module
- **File**: `src/containers/operations.rs`
- **Change**: L01 verification now routes to `l01::verify()` instead of returning an error

---

## Remaining Inconsistencies (Deferred)

### ~~StoredHash Type Variations~~ ✅ FIXED

Unified by creating a type alias in `ewf/types.rs`:
```rust
pub use crate::containers::StoredHash as StoredImageHash;
```

Now all formats use `containers::StoredHash` as the canonical type.

### CompanionLogInfo Duplication

Two `CompanionLogInfo` types serve different purposes:

| Location | Purpose | Fields |
|----------|---------|--------|
| `ad1::CompanionLogInfo` | AD1-specific `.ad1.txt` files | case_number, evidence_number, examiner, notes, md5_hash, sha1_hash, acquisition_date |
| `containers::CompanionLogInfo` | General companion logs (Guymager, etc.) | log_path, created_by, stored_hashes, segment_hashes, etc. |

**Decision**: Keep both - they serve different use cases.

### Verify Return Types

Different formats return different verification result types:

| Format | Return Type |
|--------|-------------|
| AD1 | `Vec<VerifyEntry>` (per-file) |
| E01 | `String` (computed hash) or `Vec<VerifyResult>` (per-chunk) |
| RAW | `String` (computed hash) |
| L01 | `Vec<L01VerifyEntry>` (per-file) |

**Note**: The `containers::verify()` function normalizes these to `Vec<VerifyEntry>`.

---

## Module Structure Summary

```
src/
├── ad1/           # AccessData Logical Image (5 files)
│   ├── mod.rs
│   ├── types.rs   # Ad1Info, VerifyEntry, CompanionLogInfo
│   ├── parser.rs  # Session struct, tree parsing
│   ├── operations.rs
│   └── utils.rs
├── ewf/           # Expert Witness Format (5 files)
│   ├── mod.rs
│   ├── types.rs   # E01Info, StoredImageHash, VerifyResult
│   ├── handle.rs  # E01Handle struct
│   ├── operations.rs
│   └── cache.rs
├── l01.rs         # EnCase Logical Evidence (enhanced)
├── raw.rs         # Raw disk images (.dd, .raw, .001)
├── ufed.rs        # Cellebrite UFED containers
├── archive.rs     # Archive formats (7z, ZIP, RAR)
├── containers/    # Unified abstraction layer
│   ├── mod.rs
│   ├── types.rs   # ContainerInfo, StoredHash, VerifyEntry
│   ├── operations.rs
│   ├── scanning.rs
│   ├── segments.rs
│   └── companion.rs
└── common/        # Shared utilities
    ├── mod.rs
    ├── hash.rs    # HashAlgorithm, StreamingHasher
    ├── binary.rs  # Binary reading utilities
    ├── segments.rs # Multi-segment discovery
    └── io_pool.rs # File handle pooling
```

---

## API Consistency

All formats now support these standard operations through `containers/`:

| Operation | AD1 | E01 | L01 | RAW | Archive | UFED |
|-----------|-----|-----|-----|-----|---------|------|
| `info()` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `info_fast()` | ✅ | ✅ | - | ✅ | ✅ | ✅ |
| `verify()` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `extract()` | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| `is_*()` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

*Last updated: 2025-12-30*

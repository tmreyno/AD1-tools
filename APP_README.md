# AD1 Tools - Tauri Application

A desktop application for working with forensic disk image formats (AD1, E01, L01) built with Tauri and Rust.

## Features

### Main App

- **AD1 Container Support**: Read and verify AccessData AD1 logical image files
- **E01 Container Support**: Read Expert Witness Format (EnCase) files
- **L01 Container Support**: Read Logical Evidence Format files
- **Directory Scanning**: Discover forensic containers in folders
- **Hash Verification**: MD5, SHA1, and CRC32 verification
- **File Extraction**: Extract contents from logical containers

### E01 v3 Test (New!)

- **libewf-Inspired Architecture**: Complete rewrite following libewf's proven design
- **Performance Testing**: Benchmark against libewf's ewfverify
- **Hash Verification**: MD5 and SHA1 with throughput metrics
- **Multi-Segment Support**: Handle E01, E02, E03... segment files
- **Smart Caching**: LRU file handle and chunk caching

## Running the Application

### Development Mode

```bash
npm run tauri dev
```

This will:

1. Start the Vite development server (frontend)
2. Compile the Rust backend
3. Launch the application window

### Production Build

```bash
npm run tauri build
```

## Using the E01 v3 Test

1. **Launch the app** with `npm run tauri dev`
2. **Click "E01 v3 Test"** in the navigation bar
3. **Select an E01 file** (E01, E02, etc.)
4. **Load Info** to see container details
5. **Compute MD5** to verify against libewf

### Test File

Use the 4Dell Latitude CPi.E01 file:

- Location: `/Users/terryreynolds/Downloads/4Dell Latitude CPi.E01`
- Segments: 2 (E01 + E02)
- Size: 4.5 GB
- Expected MD5: `aee4fcd9301c03b3b054623ca261959a`

### Performance Comparison

| Tool             | Time     | Throughput   | MD5 Hash     |
|------------------|----------|--------------|--------------|
| libewf ewfverify | ~14.6s   | ~331 MB/s    | aee4fcd9...  |
| E01 v3 (Goal)    | ~15-20s  | 250-400 MB/s | aee4fcd9...  |

## Architecture

### Rust Backend (`src-tauri/src/`)

- `lib.rs` - Tauri commands and application entry
- `main.rs` - Application main entry point
- `ad1.rs` - AD1 format implementation
- `e01.rs` - Original E01 implementation
- `e01_v3.rs` - **New libewf-inspired E01 implementation**
- `l01.rs` - L01 format implementation
- `containers.rs` - Unified container interface

### Frontend (`src/`)

- `App.tsx` - Main application interface
- `E01V3Test.tsx` - **New E01 v3 testing interface**
- `AppRouter.tsx` - Navigation between pages
- `index.tsx` - Application entry point

## E01 v3 Architecture Highlights

The new E01 v3 implementation replicates libewf's battle-tested architecture:

### File I/O Pool

```rust
struct FileIoPool {
    file_paths: Vec<PathBuf>,
    open_handles: HashMap<usize, File>,
    lru_queue: VecDeque<usize>,
    max_open: usize,
}
```

- LRU caching of file handles
- Prevents "too many open files" errors
- Configurable max open files (default: 16)

### Segment Management

```rust
struct SegmentFile {
    file_index: usize,
    segment_number: u16,
    sections: Vec<SegmentSection>,
}
```

- Per-segment metadata catalog
- Section structure parsed once
- Efficient segment lookup

### Global Chunk Table

```rust
struct ChunkLocation {
    segment_index: usize,
    section_index: usize,
    offset: u64,
}
```

- O(1) chunk location lookup
- No runtime searching required
- Pre-built index for performance

### Chunk Cache

```rust
struct ChunkCache {
    cache: HashMap<usize, Vec<u8>>,
    lru_queue: VecDeque<usize>,
    max_entries: usize,
}
```

- LRU cache for decompressed chunks
- Reduces redundant decompression
- Configurable cache size (default: 256 chunks)

## Development Status

### ✅ Completed

- Tauri application framework
- AD1, E01, L01 format parsers
- File I/O Pool with LRU management
- Segment file discovery and parsing
- Chunk location table
- Chunk cache with LRU
- MD5 hash verification API
- Test UI for E01 v3

### ⚠️ In Progress

- Section walking across segment boundaries (needs global offset fix)
- Performance optimization

### 📋 Planned

- SHA1/SHA256 hashing
- Raw dd image extraction
- CRC per-chunk verification
- Error recovery for corrupt chunks
- Batch processing interface

## Comparing with libewf

To compare performance with libewf:

```bash
# Run libewf's ewfverify
cd /Users/terryreynolds/GitHub/CORE/libewf
time ./ewftools/ewfverify "/Users/terryreynolds/Downloads/4Dell Latitude CPi.E01"

# Run E01 v3 in the app
# Click "E01 v3 Test" → Select file → Compute MD5
```

Both should produce the same MD5 hash: `aee4fcd9301c03b3b054623ca261959a`

## Troubleshooting

### App Won't Start

- Ensure Node.js and Rust are installed
- Run `npm install` to install dependencies
- Check that ports 1420 (Vite) and backend port are available

### E01 v3 Errors

- Current implementation has a known issue with section offset handling
- Works for single-segment files
- Multi-segment support in progress (see E01_V3_ARCHITECTURE.md)

### Performance Issues

- First run is slower due to cache warm-up
- Subsequent runs benefit from chunk cache
- SSD vs HDD makes a significant difference

## Contributing

See the E01_V3_ARCHITECTURE.md document for details on the implementation architecture and how to contribute improvements.

## License

See LICENSE file for details.

## References

- [libewf](https://github.com/libyal/libewf) - The reference implementation
- [Tauri](https://tauri.app/) - Desktop app framework
- [Solid.js](https://www.solidjs.com/) - UI framework
- [EnCase File Format](https://www.guidancesoftware.com/) - E01/EWF specification

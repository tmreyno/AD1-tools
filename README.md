# liblfx

A standalone Tauri + SolidJS desktop app for inspecting AccessData AD1 logical images.

## Features

- Read segment + logical headers
- Build a file tree
- Verify file hashes (MD5 or SHA1)
- Extract files with metadata timestamps
- Detect L01/Lx01 containers (parsing support planned)

## Requirements

- Node.js 18+ (npm)
- Rust toolchain (stable)

## Run (dev)

```bash
npm install
npm run tauri dev
```

## Notes

- AD1 segments must be in the same directory and named like `image.ad1`, `image.ad2`, ...
- Hash verification and extraction will decompress file data, which can be slow for large images.

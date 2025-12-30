Got it — here’s the 7-Zip equivalent of what we just did for AD1, at the exact byte / record / property level, written the same way: spec-style, reverse-engineered, tooling-accurate, and honest about what’s fixed vs variable.

Below is one clean Markdown block you can copy directly into 7Z_RECORD_LAYOUT.md.

⸻

📁 7Z_RECORD_LAYOUT.md

# 7-Zip (7z) Header & Record Layout — Byte-Level Parsing

7z is a **structured container format**, not record-based like AD1 and not directory-based like ZIP.

It consists of:
- fixed headers
- a jump table
- encoded metadata blocks
- optional encryption of metadata

There is **no central directory** and **no per-file headers at fixed offsets**.

---

## 1. 7z File Signature Header (Fixed)

### Offset 0x00 — Magic
Hex:

37 7A BC AF 27 1C

ASCII:

7z¼¯’␜

### Full Signature Header Layout

| Offset | Size | Field |
|------:|-----:|------|
| 0x00 | 6 | Signature |
| 0x06 | 2 | Version (major, minor) |
| 0x08 | 4 | Start Header CRC |
| 0x0C | 8 | Next Header Offset |
| 0x14 | 8 | Next Header Size |
| 0x1C | 4 | Next Header CRC |

📌 **This structure is always exactly 32 bytes total.**

---

## 2. Start Header (Embedded in Signature Header)

The Start Header is **not separate** — it is the fields starting at offset `0x08`.

Purpose:
- points to the **Next Header**
- verifies metadata integrity

### Absolute Location of Next Header

next_header_absolute =
0x20 + next_header_offset

(0x20 = size of Signature Header)

---

## 3. Next Header (Metadata Core)

The **Next Header** is the authoritative metadata structure.

It may be:
- stored
- compressed
- encrypted
- compressed + encrypted

### Layout

[Encoded Header?]
└── [Header]
├── Archive Properties
├── Stream Info
├── File Info

You **cannot assume plaintext**.

---

## 4. Header Encoding Detection

The first byte of the Next Header determines its meaning.

### Header Type IDs (1 byte)

| Value | Meaning |
|-----:|--------|
| `0x01` | Header |
| `0x02` | ArchiveProperties |
| `0x03` | AdditionalStreamsInfo |
| `0x04` | MainStreamsInfo |
| `0x05` | FilesInfo |
| `0x17` | EncodedHeader |
| `0x00` | End |

If the first byte is:

17

→ metadata is **encoded** (compressed and/or encrypted)

---

## 5. Encoded Header Structure (Critical)

### EncodedHeader Layout

0x17
├── StreamsInfo
├── PackedStreams
├── Decoder Info
└── Packed Header Bytes

To reach real metadata:
1. Parse StreamsInfo
2. Identify decoding pipeline
3. Decode packed header
4. Parse resulting Header

⚠️ **If encryption is used, filenames are inaccessible without password.**

---

## 6. StreamsInfo (Compression Graph)

StreamsInfo defines how bytes are decoded.

### Core Substructures

StreamsInfo
├── PackInfo
├── UnpackInfo
└── SubStreamsInfo

Each stream has:
- codec ID (LZMA, LZMA2, etc.)
- properties
- input/output sizes
- CRCs (optional)

This forms a **directed decode graph**, not linear records.

---

## 7. FilesInfo (File Table)

FilesInfo maps decoded streams to logical files.

### FilesInfo Layout

0x05
├── NumFiles (UInt64)
├── FileProperties[]
└── 0x00 (End)

---

## 8. File Properties (Variable, ID-Based)

Each property begins with **1 byte ID**, then data.

### Common File Property IDs

| ID (hex) | Property |
|--------:|---------|
| `0x11` | FileNames |
| `0x14` | EmptyStream |
| `0x15` | EmptyFile |
| `0x16` | Anti |
| `0x19` | CreationTime |
| `0x1A` | LastAccessTime |
| `0x1B` | LastWriteTime |
| `0x0E` | CRC |
| `0x09` | Attributes |

Filenames are:
- UTF-16LE
- length-prefixed
- order-aligned with NumFiles

---

## 9. File Content Mapping

Files do **not** store data inline.

Mapping:

File Index → Stream Index → Packed Stream → Offset → Bytes

Some files may:
- share streams (solid compression)
- be empty
- be anti-files (deletion markers)

---

## 10. Encrypted Header Detection (Tool-Grade)

A 7z file has **encrypted metadata** if:
- Next Header starts with `0x17`
- Decoder chain includes AES
- CRC of decoded header cannot be verified without password

Practical effect:
- filenames hidden
- directory tree unavailable
- container hash still valid

---

## 11. Parsing Algorithm (No Dependencies)

1. Read Signature Header
2. Validate Start Header CRC
3. Seek to Next Header
4. If first byte == `0x17`:
   - parse EncodedHeader
   - detect encryption
   - if encrypted → stop metadata parsing
5. Else:
   - parse Header
   - parse StreamsInfo
   - parse FilesInfo
6. Build logical file table

---

## 12. Detection Confidence

If all are true:
- file begins with `37 7A BC AF 27 1C`
- signature header CRC valid
- Next Header reachable
- property tree well-formed

→ You are **definitively parsing 7z**.

---

## 13. Hashing Implications

- Container hash = raw file bytes
- CRCs in metadata = declared integrity
- File hashes require stream reconstruction

---

## Report-Safe Language

> The 7-Zip container was identified by its format-specific signature header.  
> Archive metadata was parsed from the Next Header structure using byte-accurate offsets.

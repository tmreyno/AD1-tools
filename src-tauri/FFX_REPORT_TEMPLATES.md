# FFX Report Templates & Examples Guide

> **Comprehensive Reference for Forensic Report Generation**
> 
> Version: 1.0 | Last Updated: January 2026
> 
> This document provides templates, examples, and detailed documentation for generating forensic reports from FFX (Forensic File Explorer) data.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Report Schema Structure](#2-report-schema-structure)
3. [Supported Container Types](#3-supported-container-types)
4. [JSON Report Format](#4-json-report-format)
5. [Markdown Report Format](#5-markdown-report-format)
6. [HTML Report Format](#6-html-report-format)
7. [Example Reports by Container Type](#7-example-reports-by-container-type)
8. [Processed Database Reports](#8-processed-database-reports)
9. [Hash Verification Reports](#9-hash-verification-reports)
10. [Combined Multi-Evidence Reports](#10-combined-multi-evidence-reports)
11. [API Usage](#11-api-usage)
12. [Custom Report Templates](#12-custom-report-templates)
13. [Export Options](#13-export-options)

---

## 1. Overview

### What FFX Reports Include

FFX generates comprehensive forensic reports containing:

- **Case Information**: Case number, evidence number, examiner, department
- **Evidence Items**: All analyzed forensic containers with metadata
- **Device Information**: Mobile/computer device details (when available)
- **Extraction Details**: Acquisition tool, timestamps, connection type
- **Hash Verification**: Computed and stored hashes with verification status
- **Session Information**: Analysis timeline and file counts
- **Processed Database Data**: AXIOM, Cellebrite, and other tool outputs

### Report Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| JSON | `.json` | API integration, programmatic access, archival |
| Markdown | `.md` | Documentation, GitHub, plain text viewing |
| HTML | `.html` | Web browsers, styled presentation |
| PDF | `.pdf` | Court submission, printing (planned) |
| CSV | `.csv` | Spreadsheet analysis (planned) |

---

## 2. Report Schema Structure

### TypeScript Schema Definition

```typescript
interface ForensicReport {
  /** Schema version for compatibility */
  schemaVersion: "1.0";
  
  /** Report metadata */
  meta: ReportMeta;
  
  /** Case information */
  case: CaseInfo;
  
  /** Evidence items (containers) */
  evidence: EvidenceItem[];
  
  /** Hash verification records */
  hashes: HashRecord[];
  
  /** Analysis session info */
  session?: SessionInfo;
}
```

### Schema Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01 | Initial release |

---

## 3. Supported Container Types

### Evidence Container Types

| Type | Extensions | Description |
|------|------------|-------------|
| **AD1** | `.ad1` | AccessData/FTK Logical Image |
| **E01** | `.e01`, `.e02`, ... | EnCase Evidence File (physical) |
| **Ex01** | `.ex01` | EnCase Evidence File v2 |
| **L01** | `.l01`, `.l02`, ... | EnCase Logical Evidence |
| **Lx01** | `.lx01` | EnCase Logical Evidence v2 |
| **Raw** | `.dd`, `.raw`, `.img`, `.001` | Raw disk image |
| **UFED** | `.ufd`, `.ufdr`, `.ufdx` | Cellebrite UFED extraction |
| **Archive** | `.zip`, `.7z`, `.tar`, `.gz` | Compressed archives |

### Processed Database Types

| Type | Tool | Extensions |
|------|------|------------|
| **MagnetAxiom** | Magnet AXIOM | `.mfdb` |
| **CellebritePA** | Cellebrite Physical Analyzer | `.ufd`, `.ufdr` |
| **XWays** | X-Ways Forensics | Various |
| **Autopsy** | Autopsy | `.db` |
| **EnCase** | OpenText EnCase | Various |
| **FTK** | AccessData FTK | Various |
| **GenericSqlite** | Any SQLite | `.sqlite`, `.db` |

---

## 4. JSON Report Format

### Complete JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "FFX Forensic Report",
  "type": "object",
  "required": ["schemaVersion", "meta", "case", "evidence", "hashes"],
  "properties": {
    "schemaVersion": {
      "type": "string",
      "const": "1.0"
    },
    "meta": {
      "type": "object",
      "required": ["generatedAt", "generatedBy", "appVersion"],
      "properties": {
        "generatedAt": { "type": "string", "format": "date-time" },
        "generatedBy": { "type": "string" },
        "appVersion": { "type": "string" },
        "title": { "type": "string" },
        "notes": { "type": "string" }
      }
    },
    "case": {
      "type": "object",
      "properties": {
        "caseNumber": { "type": "string" },
        "evidenceNumber": { "type": "string" },
        "examiner": { "type": "string" },
        "department": { "type": "string" },
        "location": { "type": "string" },
        "notes": { "type": "string" }
      }
    },
    "evidence": {
      "type": "array",
      "items": { "$ref": "#/definitions/EvidenceItem" }
    },
    "hashes": {
      "type": "array",
      "items": { "$ref": "#/definitions/HashRecord" }
    },
    "session": { "$ref": "#/definitions/SessionInfo" }
  }
}
```

### Example: Complete JSON Report

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "generatedAt": "2026-01-04T15:30:00.000Z",
    "generatedBy": "FFX - Forensic File Explorer",
    "appVersion": "1.0.0",
    "title": "Evidence Analysis Report - Case 2025-0142",
    "notes": "Initial evidence processing completed"
  },
  "case": {
    "caseNumber": "2025-0142",
    "evidenceNumber": "EV-001-A",
    "examiner": "John Smith",
    "department": "Digital Forensics Unit",
    "location": "Main Lab - Station 3",
    "notes": "Subject's primary mobile device"
  },
  "evidence": [
    {
      "id": "/evidence/iPhone_14_Pro.ufd",
      "filename": "iPhone_14_Pro.ufd",
      "path": "/evidence/iPhone_14_Pro.ufd",
      "containerType": "UFED",
      "size": 128849018880,
      "segmentCount": 1,
      "created": "2025-12-15T10:30:00.000Z",
      "modified": "2025-12-15T14:22:00.000Z",
      "metadata": {
        "format": "UFED (UFDR)",
        "totalSize": 128849018880,
        "encryption": {
          "encrypted": false
        }
      },
      "device": {
        "vendor": "Apple",
        "model": "iPhone 14 Pro",
        "fullName": "Apple iPhone 14 Pro",
        "serialNumber": "F2LXYZ123ABC",
        "imei": "353456789012345",
        "iccid": "8901260123456789012",
        "osVersion": "iOS 17.2"
      },
      "extraction": {
        "tool": "UFED 4PC",
        "toolVersion": "7.62",
        "extractionType": "Advanced Logical",
        "connectionType": "USB",
        "startTime": "2025-12-15T10:30:00.000Z",
        "endTime": "2025-12-15T14:22:00.000Z",
        "machineName": "FORENSICS-WS01",
        "guid": "abc123-def456-ghi789",
        "unitId": "UFD-2024-001"
      }
    },
    {
      "id": "/evidence/Laptop_C_Drive.E01",
      "filename": "Laptop_C_Drive.E01",
      "path": "/evidence/Laptop_C_Drive.E01",
      "containerType": "E01",
      "size": 256060514304,
      "segmentCount": 4,
      "created": "2025-12-16T09:00:00.000Z",
      "modified": "2025-12-16T15:45:00.000Z",
      "metadata": {
        "format": "EWF (Expert Witness Format)",
        "formatVersion": "EWF-E01",
        "totalSize": 512110190592,
        "compression": "deflate",
        "chunkInfo": {
          "chunkCount": 7812500,
          "bytesPerSector": 512,
          "sectorsPerChunk": 64
        },
        "sourceDescription": "Dell Latitude 5530 - C: Drive",
        "notes": "Subject's work laptop"
      },
      "device": {
        "model": "Dell Latitude 5530",
        "serialNumber": "ABC1234XYZ"
      },
      "extraction": {
        "tool": "EnCase Forensic",
        "toolVersion": "22.4",
        "startTime": "2025-12-16T09:00:00.000Z"
      }
    }
  ],
  "hashes": [
    {
      "evidenceId": "/evidence/iPhone_14_Pro.ufd",
      "filename": "iPhone_14_Pro.ufd",
      "algorithm": "SHA256",
      "computedHash": "A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD",
      "storedHash": "A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD",
      "verified": true,
      "source": "container",
      "computedAt": "2026-01-04T15:28:00.000Z",
      "durationSecs": 245.5,
      "sourceTimestamp": "2025-12-15T14:22:00.000Z"
    },
    {
      "evidenceId": "/evidence/Laptop_C_Drive.E01",
      "filename": "Laptop_C_Drive.E01",
      "algorithm": "MD5",
      "computedHash": "D41D8CD98F00B204E9800998ECF8427E",
      "storedHash": "D41D8CD98F00B204E9800998ECF8427E",
      "verified": true,
      "source": "container",
      "computedAt": "2026-01-04T15:30:00.000Z",
      "durationSecs": 512.3
    },
    {
      "evidenceId": "/evidence/Laptop_C_Drive.E01",
      "filename": "Laptop_C_Drive.E01",
      "algorithm": "SHA1",
      "computedHash": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
      "storedHash": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
      "verified": true,
      "source": "container",
      "computedAt": "2026-01-04T15:30:00.000Z",
      "durationSecs": 612.7
    }
  ],
  "session": {
    "startedAt": "2026-01-04T15:00:00.000Z",
    "endedAt": "2026-01-04T15:35:00.000Z",
    "workingDirectory": "/evidence",
    "filesDiscovered": 15,
    "filesProcessed": 2
  }
}
```

---

## 5. Markdown Report Format

### Template Structure

```markdown
# [Report Title]

**Generated:** [Date/Time]
**Application:** FFX - Forensic File Explorer v[Version]

---

## Case Information

| Field | Value |
|-------|-------|
| Case # | [Case Number] |
| Evidence # | [Evidence Number] |
| Examiner | [Examiner Name] |
| Department | [Department] |
| Location | [Location] |

---

## Evidence Items

### [Filename 1]

**Type:** [Container Type]  
**Size:** [Formatted Size]  
**Path:** `[Full Path]`

#### Device Information

| Field | Value |
|-------|-------|
| Vendor | [Vendor] |
| Model | [Model] |
| Serial # | [Serial Number] |
| IMEI | [IMEI] |
| OS | [OS Version] |

#### Extraction Information

| Field | Value |
|-------|-------|
| Tool | [Tool Name] v[Version] |
| Type | [Extraction Type] |
| Start Time | [Start Time] |
| End Time | [End Time] |

---

## Hash Verification

### [Filename] ([Algorithm])

**Status:** ✓ VERIFIED | ✗ MISMATCH | ○ Computed  
**Computed:** `[Hash Value]`  
**Stored:** `[Stored Hash]`  
**Source Date:** [Timestamp]

---

## Notes

[Case notes and report notes]

---

*Report generated by FFX - Forensic File Explorer*
```

### Example: Complete Markdown Report

```markdown
# Evidence Analysis Report - Case 2025-0142

**Generated:** 1/4/2026, 3:30:00 PM
**Application:** FFX - Forensic File Explorer v1.0.0

---

## Case Information

| Field | Value |
|-------|-------|
| Case # | 2025-0142 |
| Evidence # | EV-001-A |
| Examiner | John Smith |
| Department | Digital Forensics Unit |
| Location | Main Lab - Station 3 |

---

## Evidence Items

### iPhone_14_Pro.ufd

**Type:** UFED  
**Size:** 120.02 GB  
**Path:** `/evidence/iPhone_14_Pro.ufd`

#### Device Information

| Field | Value |
|-------|-------|
| Vendor | Apple |
| Model | iPhone 14 Pro |
| Full Name | Apple iPhone 14 Pro |
| Serial # | F2LXYZ123ABC |
| IMEI | 353456789012345 |
| OS | iOS 17.2 |

#### Extraction Information

| Field | Value |
|-------|-------|
| Tool | UFED 4PC v7.62 |
| Type | Advanced Logical |
| Start Time | 12/15/2025, 10:30:00 AM |
| End Time | 12/15/2025, 2:22:00 PM |

---

### Laptop_C_Drive.E01

**Type:** E01  
**Size:** 238.51 GB  
**Path:** `/evidence/Laptop_C_Drive.E01`

#### Device Information

| Field | Value |
|-------|-------|
| Model | Dell Latitude 5530 |
| Serial # | ABC1234XYZ |

#### Extraction Information

| Field | Value |
|-------|-------|
| Tool | EnCase Forensic v22.4 |
| Start Time | 12/16/2025, 9:00:00 AM |

---

## Hash Verification

### iPhone_14_Pro.ufd (SHA256)

**Status:** ✓ VERIFIED  
**Computed:** `A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD`  
**Stored:** `A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD`  
**Source Date:** 12/15/2025, 2:22:00 PM

### Laptop_C_Drive.E01 (MD5)

**Status:** ✓ VERIFIED  
**Computed:** `D41D8CD98F00B204E9800998ECF8427E`  
**Stored:** `D41D8CD98F00B204E9800998ECF8427E`

### Laptop_C_Drive.E01 (SHA1)

**Status:** ✓ VERIFIED  
**Computed:** `DA39A3EE5E6B4B0D3255BFEF95601890AFD80709`  
**Stored:** `DA39A3EE5E6B4B0D3255BFEF95601890AFD80709`

---

## Notes

Subject's primary mobile device

---

*Report generated by FFX - Forensic File Explorer*
```

---

## 6. HTML Report Format

### Template Structure (Planned)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FFX Forensic Report - [Case Number]</title>
  <style>
    /* Professional forensic report styling */
    body { font-family: 'Segoe UI', Arial, sans-serif; }
    .header { background: #1a365d; color: white; padding: 20px; }
    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
    .verified { color: #22c55e; }
    .mismatch { color: #ef4444; }
    .hash-value { font-family: monospace; word-break: break-all; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    @media print { .no-print { display: none; } }
  </style>
</head>
<body>
  <!-- Report content generated from template -->
</body>
</html>
```

---

## 7. Example Reports by Container Type

### 7.1 AD1 Container Report

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "generatedAt": "2026-01-04T16:00:00.000Z",
    "generatedBy": "FFX - Forensic File Explorer",
    "appVersion": "1.0.0",
    "title": "AD1 Logical Image Analysis"
  },
  "case": {
    "caseNumber": "2025-0200",
    "evidenceNumber": "AD1-001",
    "examiner": "Jane Doe",
    "notes": "Logical acquisition from external USB drive"
  },
  "evidence": [
    {
      "id": "/cases/USB_Backup.AD1",
      "filename": "USB_Backup.AD1",
      "path": "/cases/USB_Backup.AD1",
      "containerType": "AD1",
      "size": 32212254720,
      "segmentCount": 1,
      "metadata": {
        "format": "AD1 (ADSEGMENTEDFILE)",
        "formatVersion": "3",
        "itemCount": 15243,
        "chunkInfo": {
          "chunkSize": 65536
        },
        "sourceDescription": "Samsung 32GB USB Drive",
        "notes": "Contains backup folder from subject's computer"
      },
      "extraction": {
        "tool": "FTK Imager",
        "toolVersion": "4.7.1",
        "startTime": "2025-12-20T08:15:00.000Z"
      }
    }
  ],
  "hashes": [
    {
      "evidenceId": "/cases/USB_Backup.AD1",
      "filename": "USB_Backup.AD1",
      "algorithm": "MD5",
      "computedHash": "5D41402ABC4B2A76B9719D911017C592",
      "storedHash": "5D41402ABC4B2A76B9719D911017C592",
      "verified": true,
      "source": "companion",
      "computedAt": "2026-01-04T16:00:00.000Z"
    }
  ]
}
```

### 7.2 E01 Physical Image Report

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "generatedAt": "2026-01-04T17:00:00.000Z",
    "generatedBy": "FFX - Forensic File Explorer",
    "appVersion": "1.0.0",
    "title": "Hard Drive Forensic Image Analysis"
  },
  "case": {
    "caseNumber": "2025-0305",
    "evidenceNumber": "HD-001",
    "examiner": "Robert Chen",
    "department": "Cyber Crimes Division"
  },
  "evidence": [
    {
      "id": "/images/Server_Drive.E01",
      "filename": "Server_Drive.E01",
      "path": "/images/Server_Drive.E01",
      "containerType": "E01",
      "size": 1099511627776,
      "segmentCount": 17,
      "metadata": {
        "format": "EWF (Expert Witness Format)",
        "formatVersion": "EWF-E01",
        "totalSize": 2199023255552,
        "compression": "deflate",
        "chunkInfo": {
          "chunkCount": 33554432,
          "bytesPerSector": 512,
          "sectorsPerChunk": 64
        },
        "sourceDescription": "Dell PowerEdge R740 - RAID Array",
        "notes": "Primary file server containing financial documents"
      },
      "device": {
        "model": "WD Red Pro 2TB",
        "serialNumber": "WD-WMAZA1234567"
      },
      "extraction": {
        "tool": "EnCase Forensic Imager",
        "toolVersion": "22.4.0.138",
        "startTime": "2025-12-10T22:00:00.000Z",
        "endTime": "2025-12-11T06:45:00.000Z",
        "machineName": "FORENSICS-IMG01"
      }
    }
  ],
  "hashes": [
    {
      "evidenceId": "/images/Server_Drive.E01",
      "filename": "Server_Drive.E01",
      "algorithm": "MD5",
      "computedHash": "098F6BCD4621D373CADE4E832627B4F6",
      "storedHash": "098F6BCD4621D373CADE4E832627B4F6",
      "verified": true,
      "source": "container",
      "computedAt": "2026-01-04T17:00:00.000Z",
      "durationSecs": 1847.3
    },
    {
      "evidenceId": "/images/Server_Drive.E01",
      "filename": "Server_Drive.E01",
      "algorithm": "SHA1",
      "computedHash": "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12",
      "storedHash": "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12",
      "verified": true,
      "source": "container",
      "computedAt": "2026-01-04T17:00:00.000Z",
      "durationSecs": 2156.8
    }
  ]
}
```

### 7.3 UFED Mobile Extraction Report

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "generatedAt": "2026-01-04T18:00:00.000Z",
    "generatedBy": "FFX - Forensic File Explorer",
    "appVersion": "1.0.0",
    "title": "Mobile Device Extraction Report"
  },
  "case": {
    "caseNumber": "2025-0412",
    "evidenceNumber": "MOB-003",
    "examiner": "Sarah Johnson",
    "department": "Mobile Forensics Lab",
    "location": "Evidence Processing Room 2"
  },
  "evidence": [
    {
      "id": "/extractions/Samsung_Galaxy_S23.ufdr",
      "filename": "Samsung_Galaxy_S23.ufdr",
      "path": "/extractions/Samsung_Galaxy_S23.ufdr",
      "containerType": "UFED",
      "size": 67108864000,
      "segmentCount": 1,
      "metadata": {
        "format": "UFED (UFDR)",
        "totalSize": 67108864000
      },
      "device": {
        "vendor": "Samsung",
        "model": "Galaxy S23 Ultra",
        "fullName": "Samsung SM-S918U",
        "serialNumber": "R5CWB1234XYZ",
        "imei": "354789012345678",
        "imei2": "354789012345679",
        "iccid": "8901410123456789012",
        "osVersion": "Android 14"
      },
      "extraction": {
        "tool": "UFED 4PC",
        "toolVersion": "7.65.0.123",
        "extractionType": "Full File System",
        "connectionType": "USB (ADB)",
        "startTime": "2025-12-18T13:30:00.000Z",
        "endTime": "2025-12-18T16:45:00.000Z",
        "machineName": "MOBILE-FORENSICS-01",
        "guid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "unitId": "UFED-2024-MOB-003"
      }
    }
  ],
  "hashes": [
    {
      "evidenceId": "/extractions/Samsung_Galaxy_S23.ufdr",
      "filename": "Samsung_Galaxy_S23.ufdr",
      "algorithm": "SHA256",
      "computedHash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
      "storedHash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
      "verified": true,
      "source": "container",
      "computedAt": "2026-01-04T18:00:00.000Z",
      "durationSecs": 423.7,
      "sourceTimestamp": "2025-12-18T16:45:00.000Z"
    }
  ]
}
```

---

## 8. Processed Database Reports

### 8.1 AXIOM Case Report

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "generatedAt": "2026-01-04T19:00:00.000Z",
    "generatedBy": "FFX - Forensic File Explorer",
    "appVersion": "1.0.0",
    "title": "AXIOM Case Analysis Summary"
  },
  "processedDatabase": {
    "type": "MagnetAxiom",
    "path": "/cases/2025-0142/Case.mfdb",
    "caseInfo": {
      "caseName": "Investigation 2025-0142",
      "caseNumber": "2025-0142",
      "caseType": "Criminal Investigation",
      "examiner": "John Smith",
      "agency": "Metro Police Digital Forensics",
      "created": "2025-12-20T10:00:00.000Z",
      "axiomVersion": "7.12.0.38756"
    },
    "evidenceSources": [
      {
        "name": "iPhone_14_Pro.ufd",
        "evidenceNumber": "MOB-001",
        "sourceType": "Mobile",
        "searchTypes": ["Full File System", "Cloud"],
        "size": 128849018880
      },
      {
        "name": "Laptop_C_Drive.E01",
        "evidenceNumber": "HD-001",
        "sourceType": "Computer",
        "searchTypes": ["Physical Disk"],
        "size": 512110190592
      }
    ],
    "searchResults": [
      { "artifactType": "iMessage/SMS/MMS", "hitCount": 15234 },
      { "artifactType": "Chrome Browser History", "hitCount": 8456 },
      { "artifactType": "WhatsApp Messages", "hitCount": 3201 },
      { "artifactType": "Cloud Google Drive Files", "hitCount": 1523 },
      { "artifactType": "Pictures", "hitCount": 12456 },
      { "artifactType": "Videos", "hitCount": 345 },
      { "artifactType": "Email", "hitCount": 4521 }
    ],
    "totalArtifacts": 45736,
    "keywordInfo": {
      "keywordsEntered": 25,
      "regexCount": 5,
      "keywordFiles": [
        {
          "fileName": "case_keywords.txt",
          "filePath": "I:\\Keywords\\case_keywords.txt",
          "recordCount": 150,
          "enabled": true
        }
      ]
    },
    "tags": [
      { "name": "Bookmark", "count": 234 },
      { "name": "Evidence", "count": 89 },
      { "name": "Of interest", "count": 156 }
    ]
  }
}
```

### 8.2 Processed Database Summary Table

```markdown
## Processed Database Summary

| Field | Value |
|-------|-------|
| Tool | Magnet AXIOM |
| Version | 7.12.0.38756 |
| Case Name | Investigation 2025-0142 |
| Examiner | John Smith |
| Agency | Metro Police Digital Forensics |
| Created | December 20, 2025 |

### Evidence Sources

| Source | Type | Evidence # | Size |
|--------|------|------------|------|
| iPhone_14_Pro.ufd | Mobile | MOB-001 | 120.02 GB |
| Laptop_C_Drive.E01 | Computer | HD-001 | 476.94 GB |

### Artifact Summary

| Artifact Type | Count |
|---------------|-------|
| iMessage/SMS/MMS | 15,234 |
| Chrome Browser History | 8,456 |
| WhatsApp Messages | 3,201 |
| Pictures | 12,456 |
| Videos | 345 |
| Email | 4,521 |
| Cloud Files | 1,523 |
| **Total** | **45,736** |

### Keyword Search Configuration

- **Keywords Entered:** 25
- **Regular Expressions:** 5
- **Keyword Files:** 1 (150 terms)

### Tags Applied

| Tag | Items Tagged |
|-----|--------------|
| Bookmark | 234 |
| Evidence | 89 |
| Of interest | 156 |
```

---

## 9. Hash Verification Reports

### Verification Summary Report

```markdown
## Hash Verification Summary

**Verification Date:** January 4, 2026 3:35 PM  
**Total Files Verified:** 5  
**Verified Successfully:** 5  
**Mismatches:** 0  
**Unverified:** 0

### Results

| File | Algorithm | Status | Duration |
|------|-----------|--------|----------|
| iPhone_14_Pro.ufd | SHA256 | ✓ Verified | 4m 5s |
| Laptop_C_Drive.E01 | MD5 | ✓ Verified | 8m 32s |
| Laptop_C_Drive.E01 | SHA1 | ✓ Verified | 10m 12s |
| USB_Backup.AD1 | MD5 | ✓ Verified | 1m 45s |
| Samsung_Galaxy_S23.ufdr | SHA256 | ✓ Verified | 7m 3s |

### Detailed Hash Values

#### iPhone_14_Pro.ufd
- **Algorithm:** SHA256
- **Computed:** `A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD`
- **Stored:** `A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD`
- **Source:** Container (UFED)
- **Original Date:** December 15, 2025 2:22 PM

#### Laptop_C_Drive.E01
- **Algorithm:** MD5
- **Computed:** `D41D8CD98F00B204E9800998ECF8427E`
- **Stored:** `D41D8CD98F00B204E9800998ECF8427E`
- **Source:** Container (E01 Header)

- **Algorithm:** SHA1
- **Computed:** `DA39A3EE5E6B4B0D3255BFEF95601890AFD80709`
- **Stored:** `DA39A3EE5E6B4B0D3255BFEF95601890AFD80709`
- **Source:** Container (E01 Header)
```

### Hash Mismatch Alert Report

```json
{
  "alert": "HASH_MISMATCH",
  "severity": "CRITICAL",
  "timestamp": "2026-01-04T20:00:00.000Z",
  "evidence": {
    "filename": "Suspicious_File.E01",
    "path": "/evidence/Suspicious_File.E01"
  },
  "verification": {
    "algorithm": "MD5",
    "computedHash": "5EB63BBBE01EEED093CB22BB8F5ACDC3",
    "storedHash": "098F6BCD4621D373CADE4E832627B4F6",
    "verified": false,
    "computedAt": "2026-01-04T20:00:00.000Z"
  },
  "recommendation": "Evidence file may be corrupted or modified. Verify chain of custody and re-acquire if possible."
}
```

---

## 10. Combined Multi-Evidence Reports

### Complete Case Report Template

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "generatedAt": "2026-01-04T21:00:00.000Z",
    "generatedBy": "FFX - Forensic File Explorer",
    "appVersion": "1.0.0",
    "title": "Complete Digital Forensic Analysis Report",
    "notes": "Comprehensive analysis of all digital evidence items"
  },
  "case": {
    "caseNumber": "2025-0142",
    "evidenceNumber": "Multiple Items",
    "examiner": "John Smith",
    "department": "Digital Forensics Unit",
    "location": "Main Lab",
    "notes": "Multi-device investigation including mobile, computer, and cloud data"
  },
  "evidence": [
    /* Array of all EvidenceItem objects */
  ],
  "hashes": [
    /* Array of all HashRecord objects */
  ],
  "processedDatabases": [
    {
      "type": "MagnetAxiom",
      "path": "/cases/Case.mfdb",
      "totalArtifacts": 45736,
      "evidenceSources": 2
    },
    {
      "type": "CellebritePA",
      "path": "/cases/PA_Report.ufdr",
      "totalArtifacts": 28934,
      "evidenceSources": 1
    }
  ],
  "summary": {
    "totalEvidenceItems": 5,
    "totalSizeBytes": 985238347776,
    "hashesVerified": 8,
    "hashesMatched": 8,
    "hashesMismatched": 0,
    "processedArtifacts": 74670
  },
  "session": {
    "startedAt": "2026-01-04T09:00:00.000Z",
    "endedAt": "2026-01-04T21:00:00.000Z",
    "workingDirectory": "/cases/2025-0142",
    "filesDiscovered": 25,
    "filesProcessed": 5
  }
}
```

---

## 11. API Usage

### Generate Report (TypeScript)

```typescript
import { generateReport, exportAsJson, exportAsMarkdown } from './report';

// Prepare input data
const input: ReportInput = {
  files: discoveredFiles,
  fileInfoMap: containerInfoMap,
  fileHashMap: computedHashes,
  workingDirectory: '/evidence',
  caseInfo: {
    caseNumber: '2025-0142',
    examiner: 'John Smith'
  },
  title: 'Evidence Analysis Report'
};

// Generate report object
const report = generateReport(input);

// Export as JSON
const jsonOutput = exportAsJson(report, true); // pretty print

// Export as Markdown
const markdownOutput = exportAsMarkdown(report);

// Save to file
await writeFile('report.json', jsonOutput);
await writeFile('report.md', markdownOutput);
```

### Tauri API Commands

```typescript
// Available Tauri commands for report generation
import { invoke } from '@tauri-apps/api/tauri';

// Get report template
const template = await invoke<string>('get_report_template', { 
  format: 'json' 
});

// Export report
await invoke('export_report_json', {
  report: reportObject,
  outputPath: '/output/report.json'
});

// Generate from current session
const report = await invoke<ForensicReport>('generate_session_report', {
  sessionId: currentSessionId,
  options: {
    includeHashHistory: true,
    includeFileTree: false
  }
});
```

---

## 12. Custom Report Templates

### Template Variables

Use these variables in custom templates:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{meta.generatedAt}}` | Report generation timestamp | 2026-01-04T15:30:00Z |
| `{{meta.generatedBy}}` | Application name | FFX - Forensic File Explorer |
| `{{case.caseNumber}}` | Case number | 2025-0142 |
| `{{case.examiner}}` | Examiner name | John Smith |
| `{{evidence.length}}` | Number of evidence items | 5 |
| `{{hashes.verified}}` | Verified hash count | 8 |
| `{{#each evidence}}` | Loop through evidence items | - |
| `{{#each hashes}}` | Loop through hash records | - |

### Custom Handlebars Template Example

```handlebars
# Forensic Analysis Report

**Case Number:** {{case.caseNumber}}  
**Examiner:** {{case.examiner}}  
**Generated:** {{formatDate meta.generatedAt}}

## Evidence Items ({{evidence.length}})

{{#each evidence}}
### {{this.filename}}

| Property | Value |
|----------|-------|
| Type | {{this.containerType}} |
| Size | {{formatBytes this.size}} |
| Path | `{{this.path}}` |

{{#if this.device}}
**Device:** {{this.device.vendor}} {{this.device.model}}  
{{#if this.device.imei}}**IMEI:** {{this.device.imei}}{{/if}}
{{/if}}

{{/each}}

## Hash Verification

| File | Algorithm | Status |
|------|-----------|--------|
{{#each hashes}}
| {{this.filename}} | {{this.algorithm}} | {{verifyStatus this.verified}} |
{{/each}}

---
*Report generated by {{meta.generatedBy}}*
```

---

## 13. Export Options

### Export Configuration

```typescript
interface ExportOptions {
  /** Output format */
  format: "json" | "markdown" | "html" | "pdf" | "csv";
  
  /** Include hash computation history */
  includeHashHistory?: boolean;
  
  /** Include file tree/directory listing */
  includeFileTree?: boolean;
  
  /** Include session timing information */
  includeSession?: boolean;
  
  /** Pretty print JSON output */
  prettyPrint?: boolean;
  
  /** Custom report title */
  title?: string;
  
  /** Include screenshots (HTML/PDF only) */
  includeScreenshots?: boolean;
  
  /** Output directory */
  outputDirectory?: string;
  
  /** Filename (without extension) */
  filename?: string;
}
```

### Format-Specific Options

#### JSON Export
```typescript
{
  format: "json",
  prettyPrint: true,        // Readable formatting
  includeSession: true,     // Add session info
  includeHashHistory: true  // All computed hashes
}
```

#### Markdown Export
```typescript
{
  format: "markdown",
  title: "Evidence Report",
  includeFileTree: false,   // Compact report
  includeSession: false     // Omit session details
}
```

#### HTML Export (Planned)
```typescript
{
  format: "html",
  title: "Forensic Report",
  includeScreenshots: true, // Embed hex viewer screenshots
  theme: "professional"     // Light professional theme
}
```

#### PDF Export (Planned)
```typescript
{
  format: "pdf",
  title: "Court-Ready Report",
  includeScreenshots: true,
  pageSize: "letter",       // or "a4"
  orientation: "portrait",
  watermark: "CONFIDENTIAL"
}
```

---

## Appendix A: Field Reference

### Evidence Item Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | Yes | Unique identifier (path) |
| filename | string | Yes | Original filename |
| path | string | Yes | Full file path |
| containerType | string | Yes | Container format type |
| size | number | Yes | File size in bytes |
| segmentCount | number | No | Number of segments |
| created | string | No | Creation timestamp |
| modified | string | No | Modification timestamp |
| metadata | object | Yes | Container metadata |
| device | object | No | Device information |
| extraction | object | No | Extraction details |

### Hash Record Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| evidenceId | string | Yes | Reference to evidence item |
| filename | string | Yes | File name |
| algorithm | string | Yes | Hash algorithm used |
| computedHash | string | Yes | Computed hash value |
| storedHash | string | No | Original stored hash |
| verified | boolean/null | Yes | Verification result |
| source | string | Yes | Hash source type |
| computedAt | string | Yes | Computation timestamp |
| durationSecs | number | No | Computation duration |

---

## Appendix B: Algorithm Support

### Supported Hash Algorithms

| Algorithm | Forensic | Speed | Output Size |
|-----------|----------|-------|-------------|
| MD5 | ✓ Court-accepted | Medium | 128 bits |
| SHA-1 | ✓ Court-accepted | Medium | 160 bits |
| SHA-256 | ✓ Court-accepted | Medium | 256 bits |
| SHA-512 | ✓ Court-accepted | Slow | 512 bits |
| BLAKE3 | Modern | Fast | 256 bits |
| BLAKE2b | Modern | Fast | 256 bits |
| XXH3 | Checksum only | Very Fast | 64 bits |
| XXH64 | Checksum only | Very Fast | 64 bits |
| CRC32 | Checksum only | Very Fast | 32 bits |

---

## Appendix C: Container Metadata Fields

### AD1 Metadata
- format, formatVersion, itemCount, chunkSize, sourceDescription, notes

### E01/L01 Metadata
- format, formatVersion, totalSize, compression, chunkCount, bytesPerSector, sectorsPerChunk, sourceDescription, notes

### UFED Metadata
- format, totalSize, encryption status

### Archive Metadata
- format, version, totalSize, entryCount, encryption status

---

*This document is for use with FFX - Forensic File Explorer. Always follow proper chain of custody procedures when handling digital evidence.*

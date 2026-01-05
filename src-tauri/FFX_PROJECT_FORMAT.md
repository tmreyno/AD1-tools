# FFX Project File Format (.ffxproj)

## Overview

The `.ffxproj` file is a comprehensive JSON-based project file that saves and restores the complete state of an FFX (Forensic File Xplorer) session. It enables examiners to:

- **Resume work** exactly where they left off
- **Track activity** with a complete audit log
- **Verify integrity** of processed databases
- **Collaborate** with session/user tracking
- **Document findings** with bookmarks and notes

## File Location

By default, `.ffxproj` files are saved in the root evidence directory:

```
/path/to/evidence/
├── 1.Evidence/
│   └── case.E01
├── 2.Processed.Database/
│   └── Case.mfdb
└── evidence.ffxproj  ← Project file
```

---

## Project File Structure (v2)

```json
{
  "version": 2,
  "project_id": "unique-id-string",
  "name": "Project Name",
  "description": "Optional project description",
  "root_path": "/absolute/path/to/evidence",
  "created_at": "2026-01-04T12:00:00.000Z",
  "saved_at": "2026-01-04T15:30:00.000Z",
  "created_by_version": "0.1.0",
  "saved_by_version": "0.1.0",
  
  "users": [...],
  "sessions": [...],
  "activity_log": [...],
  
  "open_directories": [...],
  "tabs": [...],
  "file_selection": {...},
  "hash_history": {...},
  
  "processed_databases": {...},
  
  "bookmarks": [...],
  "notes": [...],
  "tags": [...],
  
  "reports": [...],
  "saved_searches": [...],
  "recent_searches": [...],
  
  "ui_state": {...},
  "settings": {...}
}
```

---

## Section Details

### 1. Metadata

| Field | Type | Description |
|-------|------|-------------|
| `version` | number | Project file format version (currently 2) |
| `project_id` | string | Unique identifier for this project |
| `name` | string | Project display name |
| `description` | string? | Optional description |
| `root_path` | string | Absolute path to evidence root directory |
| `created_at` | ISO string | When project was created |
| `saved_at` | ISO string | When project was last saved |
| `created_by_version` | string | App version that created project |
| `saved_by_version` | string | App version that last saved project |

---

### 2. Users & Sessions

#### Users Array

Tracks all examiners who have accessed this project:

```json
{
  "users": [
    {
      "username": "examiner1",
      "display_name": "John Smith",
      "hostname": "forensic-workstation",
      "first_access": "2026-01-04T10:00:00.000Z",
      "last_access": "2026-01-04T15:30:00.000Z"
    }
  ],
  "current_user": "examiner1"
}
```

#### Sessions Array

Records each work session:

```json
{
  "sessions": [
    {
      "session_id": "abc123",
      "user": "examiner1",
      "started_at": "2026-01-04T10:00:00.000Z",
      "ended_at": "2026-01-04T12:30:00.000Z",
      "duration_seconds": 9000,
      "hostname": "forensic-workstation",
      "app_version": "0.1.0",
      "summary": "Initial evidence review"
    }
  ],
  "current_session_id": "def456"
}
```

#### Activity Log

Comprehensive audit trail of all actions:

```json
{
  "activity_log": [
    {
      "id": "log-001",
      "timestamp": "2026-01-04T10:15:00.000Z",
      "user": "examiner1",
      "category": "file",
      "action": "open",
      "description": "Opened evidence container: case.E01",
      "file_path": "/evidence/case.E01",
      "details": { "container_type": "E01", "size": 5368709120 }
    },
    {
      "id": "log-002",
      "timestamp": "2026-01-04T10:20:00.000Z",
      "user": "examiner1",
      "category": "hash",
      "action": "compute",
      "description": "Computed SHA-256 hash for case.E01",
      "file_path": "/evidence/case.E01",
      "details": { "algorithm": "SHA-256", "hash": "abc123..." }
    }
  ],
  "activity_log_limit": 1000
}
```

**Activity Categories:**
- `file` - File operations (open, close, select)
- `hash` - Hash computations and verifications
- `search` - Searches performed
- `export` - Exports/reports generated
- `bookmark` - Bookmarks added/removed
- `note` - Notes created/edited
- `tag` - Tags applied/removed
- `database` - Processed database operations
- `project` - Project save/load
- `system` - System events

---

### 3. Evidence State

#### Open Directories

```json
{
  "open_directories": [
    {
      "path": "/evidence/1.Evidence",
      "opened_at": "2026-01-04T10:00:00.000Z",
      "recursive": true,
      "file_count": 15,
      "total_size": 107374182400,
      "last_scanned": "2026-01-04T10:05:00.000Z"
    }
  ],
  "recent_directories": [
    {
      "path": "/previous/case",
      "open_count": 5,
      "last_opened": "2026-01-03T16:00:00.000Z",
      "name": "Previous Case"
    }
  ]
}
```

#### Open Tabs

```json
{
  "tabs": [
    {
      "file_path": "/evidence/case.E01",
      "name": "case.E01",
      "order": 0,
      "container_type": "E01",
      "scroll_position": 1024,
      "last_viewed": "2026-01-04T15:00:00.000Z"
    }
  ],
  "active_tab_path": "/evidence/case.E01"
}
```

#### File Selection State

```json
{
  "file_selection": {
    "selected_paths": ["/evidence/case.E01", "/evidence/case.E02"],
    "active_path": "/evidence/case.E01",
    "timestamp": "2026-01-04T15:00:00.000Z"
  }
}
```

#### Hash History

```json
{
  "hash_history": {
    "files": {
      "/evidence/case.E01": [
        {
          "algorithm": "SHA-256",
          "hash_value": "abc123def456...",
          "computed_at": "2026-01-04T10:30:00.000Z",
          "verification": {
            "result": "match",
            "verified_against": "stored_in_container",
            "verified_at": "2026-01-04T10:31:00.000Z"
          }
        },
        {
          "algorithm": "MD5",
          "hash_value": "d41d8cd98f00b204e9800998ecf8427e",
          "computed_at": "2026-01-04T10:32:00.000Z"
        }
      ]
    }
  }
}
```

---

### 4. Processed Databases

Tracks AXIOM, Cellebrite, and other processed database state:

```json
{
  "processed_databases": {
    "loaded_paths": [
      "/evidence/2.Processed.Database/Case.mfdb"
    ],
    "selected_path": "/evidence/2.Processed.Database/Case.mfdb",
    "detail_view_type": "case",
    "integrity": {
      "/evidence/2.Processed.Database/Case.mfdb": {
        "path": "/evidence/2.Processed.Database/Case.mfdb",
        "file_size": 524288000,
        "baseline_hash": "hash-when-first-loaded",
        "baseline_timestamp": "2026-01-04T10:00:00.000Z",
        "current_hash": "hash-now",
        "current_hash_timestamp": "2026-01-04T15:00:00.000Z",
        "status": "modified",
        "metrics": {
          "total_scans": 1,
          "last_scan_date": "2026-01-04T11:00:00.000Z",
          "total_jobs": 45,
          "last_job_date": "2026-01-04T11:30:00.000Z",
          "total_notes": 12,
          "total_tagged_items": 150,
          "total_users": 1,
          "user_names": ["SA Reynolds"]
        },
        "changes": ["12 new notes added", "150 items tagged"]
      }
    },
    "cached_metadata": {
      "/evidence/2.Processed.Database/Case.mfdb": {
        "db_type": "MagnetAxiom",
        "name": "Case.mfdb",
        "case_name": "24-042.0854",
        "examiner": "SA Reynolds"
      }
    }
  }
}
```

**Integrity Status Values:**
- `unchanged` - Hash matches baseline
- `modified` - Hash differs (work was done)
- `new_baseline` - User accepted new baseline
- `not_verified` - Not yet verified

---

### 5. Bookmarks & Notes

#### Bookmarks

```json
{
  "bookmarks": [
    {
      "id": "bm-001",
      "target_type": "artifact",
      "target_path": "/evidence/Case.mfdb:artifact:12345",
      "name": "Suspicious email",
      "created_by": "examiner1",
      "created_at": "2026-01-04T11:00:00.000Z",
      "color": "#ff0000",
      "tags": ["suspicious", "priority"],
      "notes": "Follow up with sender IP",
      "context": { "artifact_type": "Email", "subject": "..." }
    }
  ]
}
```

#### Notes

```json
{
  "notes": [
    {
      "id": "note-001",
      "target_type": "file",
      "target_path": "/evidence/case.E01",
      "title": "Acquisition Notes",
      "content": "# Acquisition Details\n\nEvidence acquired on 2026-01-03...",
      "created_by": "examiner1",
      "created_at": "2026-01-04T10:30:00.000Z",
      "modified_at": "2026-01-04T14:00:00.000Z",
      "tags": ["acquisition", "documentation"],
      "priority": "normal"
    }
  ]
}
```

#### Tag Definitions

```json
{
  "tags": [
    {
      "id": "tag-001",
      "name": "Suspicious",
      "color": "#ff0000",
      "description": "Items requiring follow-up",
      "created_at": "2026-01-04T10:00:00.000Z"
    },
    {
      "id": "tag-002",
      "name": "Exported",
      "color": "#00ff00",
      "description": "Items included in report",
      "created_at": "2026-01-04T10:00:00.000Z"
    }
  ]
}
```

---

### 6. Reports

```json
{
  "reports": [
    {
      "id": "rpt-001",
      "title": "Case Summary Report",
      "report_type": "summary",
      "format": "markdown",
      "output_path": "/evidence/reports/summary_2026-01-04.md",
      "generated_at": "2026-01-04T16:00:00.000Z",
      "generated_by": "examiner1",
      "included_items": ["/evidence/case.E01"],
      "config": { "include_hashes": true, "include_timeline": false },
      "status": "completed"
    }
  ]
}
```

---

### 7. Searches

#### Saved Searches

```json
{
  "saved_searches": [
    {
      "id": "search-001",
      "name": "Find PDFs",
      "query": "*.pdf",
      "search_type": "filename",
      "is_regex": false,
      "case_sensitive": false,
      "scope": "all",
      "created_at": "2026-01-04T11:00:00.000Z",
      "use_count": 5,
      "last_used": "2026-01-04T15:00:00.000Z"
    }
  ]
}
```

#### Recent Searches

```json
{
  "recent_searches": [
    {
      "query": "password",
      "timestamp": "2026-01-04T14:00:00.000Z",
      "result_count": 42
    }
  ]
}
```

#### Filter State

```json
{
  "filter_state": {
    "type_filter": "E01",
    "status_filter": null,
    "search_query": null,
    "sort_by": "name",
    "sort_direction": "asc"
  }
}
```

---

### 8. UI State

Complete UI restoration:

```json
{
  "ui_state": {
    "left_panel_width": 320,
    "right_panel_width": 280,
    "left_panel_collapsed": false,
    "right_panel_collapsed": true,
    "left_panel_tab": "evidence",
    "detail_view_mode": "info",
    "tree_state": [
      {
        "path": "/evidence/1.Evidence",
        "expanded": true,
        "children": [
          { "path": "/evidence/1.Evidence/subfolder", "expanded": false }
        ]
      }
    ],
    "scroll_positions": {
      "file_list": 1024,
      "detail_panel": 0
    },
    "window_dimensions": {
      "width": 1920,
      "height": 1080
    },
    "preferences": {
      "theme": "dark",
      "font_size": 14,
      "show_hidden_files": false,
      "confirm_on_close": true
    }
  }
}
```

---

### 9. Settings

Project-specific settings:

```json
{
  "settings": {
    "auto_save": true,
    "auto_save_interval": 300000,
    "default_hash_algorithm": "SHA-256",
    "verify_hashes_on_load": false,
    "track_activity": true,
    "max_recent_items": 50
  }
}
```

---

## Auto-Save Behavior

When `auto_save` is enabled:
1. Project saves automatically every `auto_save_interval` milliseconds (default: 5 minutes)
2. Auto-save only triggers if:
   - Project has been modified since last save
   - Project has been saved at least once (has a path)
3. Auto-save is non-blocking and logs to console

---

## Version Migration

When loading a project with a different version:

| From Version | To Version | Migration |
|--------------|------------|-----------|
| 1 | 2 | Add new fields with defaults |
| 2+ | Any | Forward compatible if possible |

Warnings are returned in `ProjectLoadResult.warnings` for any migration issues.

---

## Forensic Considerations

### Chain of Custody

The `.ffxproj` file provides:
- Complete activity audit log
- User/session tracking with timestamps
- Hash history with verification records
- All operations are timestamped

### Integrity

- Processed database integrity tracking with baseline hashes
- Change detection shows what examiner work was done
- Distinguishes legitimate work from unexpected modifications

### Best Practices

1. **Save frequently** or enable auto-save
2. **Use descriptive project names**
3. **Add notes** for important findings
4. **Bookmark** items for follow-up
5. **Review activity log** before closing

---

## Example Project File

```json
{
  "version": 2,
  "project_id": "prj-20260104-abc123",
  "name": "24-042.0854 Investigation",
  "description": "Digital forensic analysis of suspect device",
  "root_path": "/Users/examiner/Cases/24-042.0854",
  "created_at": "2026-01-04T10:00:00.000Z",
  "saved_at": "2026-01-04T16:30:00.000Z",
  "created_by_version": "0.1.0",
  "saved_by_version": "0.1.0",
  
  "users": [{
    "username": "sa_reynolds",
    "display_name": "SA Reynolds",
    "first_access": "2026-01-04T10:00:00.000Z",
    "last_access": "2026-01-04T16:30:00.000Z"
  }],
  "current_user": "sa_reynolds",
  "sessions": [{
    "session_id": "sess-001",
    "user": "sa_reynolds",
    "started_at": "2026-01-04T10:00:00.000Z",
    "ended_at": null,
    "app_version": "0.1.0"
  }],
  "current_session_id": "sess-001",
  "activity_log": [
    {
      "id": "act-001",
      "timestamp": "2026-01-04T10:00:00.000Z",
      "user": "sa_reynolds",
      "category": "project",
      "action": "create",
      "description": "Project created: 24-042.0854 Investigation"
    }
  ],
  "activity_log_limit": 1000,
  
  "open_directories": [{
    "path": "/Users/examiner/Cases/24-042.0854/1.Evidence",
    "opened_at": "2026-01-04T10:05:00.000Z",
    "recursive": true,
    "file_count": 3,
    "total_size": 16106127360,
    "last_scanned": "2026-01-04T10:05:00.000Z"
  }],
  "recent_directories": [],
  "tabs": [{
    "file_path": "/Users/examiner/Cases/24-042.0854/1.Evidence/device.E01",
    "name": "device.E01",
    "order": 0,
    "container_type": "E01",
    "last_viewed": "2026-01-04T16:30:00.000Z"
  }],
  "active_tab_path": "/Users/examiner/Cases/24-042.0854/1.Evidence/device.E01",
  "file_selection": {
    "selected_paths": ["/Users/examiner/Cases/24-042.0854/1.Evidence/device.E01"],
    "active_path": "/Users/examiner/Cases/24-042.0854/1.Evidence/device.E01",
    "timestamp": "2026-01-04T16:30:00.000Z"
  },
  "hash_history": {
    "files": {}
  },
  
  "processed_databases": {
    "loaded_paths": [],
    "selected_path": null,
    "detail_view_type": null,
    "integrity": {}
  },
  
  "bookmarks": [],
  "notes": [],
  "tags": [],
  "reports": [],
  "saved_searches": [],
  "recent_searches": [],
  "filter_state": {
    "type_filter": null,
    "status_filter": null,
    "search_query": null,
    "sort_by": "name",
    "sort_direction": "asc"
  },
  
  "ui_state": {
    "left_panel_width": 320,
    "right_panel_width": 280,
    "left_panel_collapsed": false,
    "right_panel_collapsed": true,
    "left_panel_tab": "evidence",
    "detail_view_mode": "info",
    "tree_state": [],
    "scroll_positions": {},
    "preferences": {
      "theme": "auto",
      "confirm_on_close": true
    }
  },
  
  "settings": {
    "auto_save": true,
    "auto_save_interval": 300000,
    "default_hash_algorithm": "SHA-256",
    "verify_hashes_on_load": false,
    "track_activity": true,
    "max_recent_items": 50
  }
}
```

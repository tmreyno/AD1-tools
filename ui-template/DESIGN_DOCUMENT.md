# FFX UI/UX Design System
## Forensic File Explorer - Design Document

**Version:** 1.0  
**Framework:** SolidJS + TypeScript + Tauri  
**Theme:** Dark Professional (GitHub-inspired)

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Layout Architecture](#2-layout-architecture)
3. [Color System](#3-color-system)
4. [Typography](#4-typography)
5. [Component Inventory](#5-component-inventory)
6. [Interaction Patterns](#6-interaction-patterns)
7. [State Management Architecture](#7-state-management-architecture)
8. [Responsive Behavior](#8-responsive-behavior)
9. [Accessibility](#9-accessibility)
10. [Implementation Guide](#10-implementation-guide)

---

## 1. Design Philosophy

### Core Principles

1. **Information Density** - Professional tools need to show more data without overwhelming users
2. **Dark-First** - Reduces eye strain during long work sessions
3. **Status Visibility** - Operations status always visible; never leave users guessing
4. **Progressive Disclosure** - Show summary first, details on demand
5. **Keyboard-First** - Power users expect full keyboard navigation
6. **Immediate Feedback** - All actions have visual feedback within 100ms

### Visual Language

- **Compact** - Dense but not cramped; 4-8px spacing rhythm
- **Layered** - Background → Panel → Card → Highlight hierarchy
- **Semantic Colors** - Colors carry meaning (success=green, error=red, etc.)
- **Subtle Borders** - Definition without harsh lines
- **Emoji-Enhanced** - Strategic emoji use for quick visual scanning

---

## 2. Layout Architecture

### Master Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ HEADER BAR (44px fixed)                                         │
│ [Brand Logo] [Brand Name] [Tag]           [Status Dot] [Status] │
├─────────────────────────────────────────────────────────────────┤
│ TOOLBAR (44px fixed)                                            │
│ [Primary Action] [Input] [Toggle] │ [Select] [Actions...]       │
├───────────────────────┬─────────────────────────────────────────┤
│ FILE PANEL            │ DETAIL PANEL                            │
│ (320px sidebar)       │ (flex: 1)                               │
│                       │                                          │
│ ┌─────────────────┐   │ ┌─────────────────────────────────────┐ │
│ │ Panel Header    │   │ │ Detail Header                       │ │
│ ├─────────────────┤   │ │ [Type Badge] [Title] [Path]        │ │
│ │ Type Filters    │   │ ├─────────────────────────────────────┤ │
│ ├─────────────────┤   │ │ Stat Row (horizontal metrics)      │ │
│ │ Select All Row  │   │ ├─────────────────────────────────────┤ │
│ ├─────────────────┤   │ │ Progress Section (when active)     │ │
│ │                 │   │ ├─────────────────────────────────────┤ │
│ │ File List       │   │ │ Hash Card (result)                 │ │
│ │ (scrollable)    │   │ ├─────────────────────────────────────┤ │
│ │                 │   │ │ Compact Sections (collapsible)     │ │
│ │                 │   │ │ - Stored Hashes                    │ │
│ │                 │   │ │ - Container Details                │ │
│ │                 │   │ │ - File Tree                        │ │
│ └─────────────────┘   │ ├─────────────────────────────────────┤ │
│                       │ │ Action Buttons                      │ │
│                       │ └─────────────────────────────────────┘ │
├───────────────────────┴─────────────────────────────────────────┤
│ STATUS BAR (32px fixed)                                         │
│ [Icon] [Message]        [Stats]              [System Stats]     │
└─────────────────────────────────────────────────────────────────┘
```

### Fixed vs Flexible Zones

| Zone | Height | Behavior |
|------|--------|----------|
| Header Bar | 44px | Fixed, always visible |
| Toolbar | 44px | Fixed, horizontal scroll on overflow |
| Main Layout | flex: 1 | Fills remaining space |
| File Panel | 320px wide | Fixed width, scrollable content |
| Detail Panel | flex: 1 | Fills width, scrollable content |
| Status Bar | ~32px | Fixed, background color = status |

---

## 3. Color System

### CSS Custom Properties

```css
:root {
  /* Backgrounds (darkest to lightest) */
  --bg: #0f1419;           /* App background */
  --bg-panel: #161b22;     /* Panel backgrounds */
  --bg-card: #1c2128;      /* Card/section backgrounds */
  --bg-hover: #21262d;     /* Hover states */
  
  /* Borders */
  --border: #30363d;       /* Primary borders */
  --border-muted: #21262d; /* Subtle borders */
  
  /* Text */
  --text: #e6edf3;         /* Primary text */
  --text-muted: #8b949e;   /* Secondary text */
  --text-faint: #6e7681;   /* Tertiary/disabled text */
  
  /* Semantic Colors */
  --accent: #2f81f7;       /* Primary accent (blue) */
  --accent-soft: rgba(47, 129, 247, 0.15);
  
  --success: #3fb950;      /* Success/verified (green) */
  --success-soft: rgba(63, 185, 80, 0.15);
  
  --warning: #d29922;      /* Warning/pending (orange) */
  --warning-soft: rgba(210, 153, 34, 0.15);
  
  --error: #f85149;        /* Error/failed (red) */
  --error-soft: rgba(248, 81, 73, 0.15);
  
  /* Radii */
  --radius: 6px;           /* Standard border radius */
  --radius-lg: 10px;       /* Large elements */
}
```

### Semantic Color Usage

| Color | Use Case |
|-------|----------|
| `--accent` | Primary actions, links, focus states, selected items |
| `--success` | Verified, completed, valid states |
| `--warning` | Pending, in-progress, caution states |
| `--error` | Failed, invalid, destructive actions |

### Type-Specific Colors (Badges & Icons)

```css
.type-ad1    { background: var(--accent-soft); color: var(--accent); }
.type-e01    { background: var(--success-soft); color: var(--success); }
.type-l01    { background: var(--warning-soft); color: var(--warning); }
.type-raw    { background: rgba(163, 113, 247, 0.15); color: #a371f7; }
.type-ufed   { background: rgba(56, 182, 255, 0.15); color: #38b6ff; }
.type-archive{ background: rgba(255, 123, 114, 0.15); color: #ff7b72; }
```

---

## 4. Typography

### Font Stack

```css
:root {
  --sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
}
```

### Type Scale

| Element | Size | Weight | Use |
|---------|------|--------|-----|
| Brand Name | 15px | 700 | App title in header |
| Panel Header (h3) | 12px | 600 | Section titles, uppercase |
| Detail Header (h2) | 20px | 600 | Main content title |
| Body Text | 13px | 400 | Default text |
| Small Text | 12px | 400-500 | Buttons, inputs |
| Tiny Text | 11px | 400-500 | Meta info, labels |
| Micro Text | 10px | 500-600 | Badges, timestamps |
| Mono (hashes) | 10-12px | 400 | Code, hashes, paths |

### Label Pattern

```css
.info-label {
  font-size: 10px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.02em;
  color: var(--text-faint);
}
```

---

## 5. Component Inventory

### 5.1 Header Bar

**Purpose:** Brand identity + global status indicator

**Structure:**
```tsx
<header class="header-bar">
  <div class="brand">
    <span class="brand-icon">🔬</span>
    <span class="brand-name">AppName</span>
    <span class="brand-tag">Tagline</span>
  </div>
  <div class="header-status">
    <span class="status-dot {statusKind}" />
    <span class="status-text">{message}</span>
  </div>
</header>
```

**States:** `idle` | `working` | `ok` | `error`

---

### 5.2 Toolbar

**Purpose:** Primary actions and controls

**Components:**
- **Primary Button** (`.tool-btn.primary`) - Main action
- **Secondary Button** (`.tool-btn`) - Supporting actions
- **Input Group** (`.tool-input`) - Text input + button combo
- **Toggle** (`.tool-toggle`) - Checkbox with label
- **Select** (`.tool-select`) - Dropdown menu
- **Separator** (`.tool-sep`) - Visual divider

**Pattern:**
```tsx
<div class="toolbar">
  <button class="tool-btn primary">📁 Open</button>
  <div class="tool-input">
    <input type="text" placeholder="..." />
    <button class="tool-btn">🔍</button>
  </div>
  <label class="tool-toggle">
    <input type="checkbox" />
    <span>Label</span>
  </label>
  <div class="tool-sep" />
  <select class="tool-select">...</select>
  <button class="tool-btn">Action ({count})</button>
</div>
```

---

### 5.3 File Panel (Sidebar)

**Purpose:** List view with filtering and selection

**Sections:**
1. **Panel Header** - Title + stats
2. **Type Filters** - Clickable badge pills
3. **Select All Row** - Bulk selection
4. **File List** - Scrollable item rows
5. **Empty State** - When no items

**Type Badge Pattern:**
```tsx
<button class={`type-badge ${typeClass} ${active ? "active" : ""}`}>
  {type}: {count}
</button>
```

---

### 5.4 File Row

**Purpose:** Single item in list with inline actions

**Structure:**
```tsx
<div class={`file-row ${selected} ${active} ${focused}`}>
  <input type="checkbox" />
  <span class={`type-icon ${typeClass}`}>{emoji}</span>
  <div class="file-info">
    <span class="file-name">{name}</span>
    <span class="file-meta">{size} • {segments}</span>
  </div>
  <div class="file-actions">
    <HashIndicator ... />
  </div>
</div>
```

**States:** `selected` | `active` | `focused` | `hovered`

---

### 5.5 Hash Indicator

**Purpose:** Show hash status with interactive count badge

**States:**
- `none` - No hashes, clickable to start
- `stored` - Has stored hashes, yellow badge
- `hashing` - In progress, animated
- `completing` - Almost done
- `computed` - Computed, no stored to verify
- `verified` - Matches stored hash, green ✓✓
- `failed` - Mismatch, red badge

**Pattern:**
```tsx
<button class={`hash-indicator ${state} clickable`}>
  <span class="hash-status">{progress}%</span>
  <span class="hash-icon-wrap">
    <span class="hash-icon">#</span>
    <span class="hash-badge">{count}</span>
  </span>
</button>
```

---

### 5.6 Detail Panel

**Purpose:** Full details of selected item

**Sections:**
1. **Header** - Type badge, title, path
2. **Stat Row** - Horizontal key metrics
3. **Progress Section** - When hashing/verifying
4. **Hash Card** - Computed hash result
5. **Compact Sections** - Collapsible detail groups
6. **Action Buttons** - Secondary actions

---

### 5.7 Compact Section

**Purpose:** Grouped information with header

```tsx
<div class="compact-section">
  <div class="section-title">📋 Section Name</div>
  <div class="info-compact">
    <InfoRows fields={fields} />
  </div>
</div>
```

---

### 5.8 Info Row

**Purpose:** Key-value display

**Types:** `normal` | `highlight` | `device` | `full-width` | `hash`

```tsx
<div class={`info-row ${type}`}>
  <span class="info-label">{label}</span>
  <span class={`info-value ${format}`}>{value}</span>
</div>
```

---

### 5.9 Hash Card

**Purpose:** Display computed hash with verification status

**Variants:** `verified` | `failed` | `no-stored`

```tsx
<div class={`hash-card computed ${variant}`}>
  <div class="hash-header">
    <span class="hash-algo-label">🔐 {algorithm}</span>
    <span class={`verify-status ${status}`}>{statusText}</span>
    <button class="copy-btn">📋</button>
  </div>
  <code class="hash-full">{hash}</code>
  <div class="verification-detail">{detail}</div>
</div>
```

---

### 5.10 Status Bar

**Purpose:** Global status + system metrics

**Sections:**
- Left: Status icon + message
- Center: Item stats (count, size, selected)
- Right: System stats (CPU, memory, threads)

**Background color changes with status kind.**

---

## 6. Interaction Patterns

### 6.1 Selection Model

- **Single Click** → Select and view details
- **Checkbox Click** → Toggle selection without viewing
- **Shift+Click** → Range select (not implemented yet)
- **Ctrl/Cmd+Click** → Add to selection

### 6.2 Keyboard Navigation

| Key | Action |
|-----|--------|
| ↑/↓ | Navigate list |
| Enter | Select item |
| Space | Toggle checkbox |
| Home/End | Jump to first/last |
| Escape | Clear filter |

### 6.3 Hover States

- **File Row Hover** → Show tooltip with extended info
- **Button Hover** → Slight scale + brightness
- **Badge Hover** → Highlight effect

### 6.4 Loading States

- **Progress Bar** - For known-length operations
- **Indeterminate Bar** - For unknown-length operations  
- **Animated Hash Icon** - Spinning `#` symbol
- **Pulsing Dot** - Status indicator in header

### 6.5 Feedback Animations

```css
@keyframes pulse { 
  0%, 100% { opacity: 1; } 
  50% { opacity: 0.5; } 
}

@keyframes hash-spin { 
  0% { transform: rotate(0deg); } 
  100% { transform: rotate(360deg); } 
}
```

---

## 7. State Management Architecture

### Hook-Based Architecture

```
App.tsx
├── useFileManager (file discovery, selection, status)
│   ├── scanDir, discoveredFiles, selectedFiles, activeFile
│   ├── fileInfoMap, fileStatusMap
│   ├── filtering, sorting, keyboard navigation
│   └── browseScanDir, scanForFiles, loadFileInfo
│
└── useHashManager (depends on fileManager)
    ├── selectedHashAlgorithm, fileHashMap, hashHistory
    ├── segmentResults, segmentVerifyProgress
    └── hashSingleFile, hashSelectedFiles, verifySegments
```

### Signal-Based Reactivity (SolidJS)

```tsx
// State signals
const [items, setItems] = createSignal<Item[]>([]);
const [activeItem, setActiveItem] = createSignal<Item | null>(null);

// Derived/computed values
const filteredItems = createMemo(() => 
  items().filter(i => matchesFilter(i, filter()))
);

// Effects
createEffect(() => {
  // Runs when dependencies change
  console.log("Active item changed:", activeItem());
});
```

### Map-Based Lookup Pattern

```tsx
// Use Maps for O(1) lookup by key
const [statusMap, setStatusMap] = createSignal<Map<string, Status>>(new Map());

// Update pattern (immutable)
setStatusMap(prev => {
  const m = new Map(prev);
  m.set(key, newStatus);
  return m;
});
```

---

## 8. Responsive Behavior

### Breakpoints (Desktop App Focus)

| Width | Behavior |
|-------|----------|
| < 800px | File panel hides, toggle button appears |
| 800-1200px | Narrow file panel (280px) |
| > 1200px | Full file panel (320px) |

### Overflow Handling

- **Toolbar** → Horizontal scroll
- **File Panel** → Fixed width, content scrolls
- **Detail Panel** → Full vertical scroll
- **File Names** → Ellipsis truncation

---

## 9. Accessibility

### Keyboard Navigation
- All interactive elements focusable
- Logical tab order
- Arrow key navigation in lists
- Focus indicators visible

### Screen Reader Support
- Semantic HTML elements
- ARIA labels on icons
- Status announcements
- Meaningful alt text

### Visual Accessibility
- High contrast colors (WCAG AA)
- Focus visible states
- No color-only indicators
- Sufficient text size

---

## 10. Implementation Guide

### Project Structure

```
src/
├── App.tsx              # Root component, hook composition
├── App.css              # All styles (single file for simplicity)
├── types.ts             # TypeScript type definitions
├── utils.ts             # Shared utility functions
├── components/
│   ├── index.ts         # Re-exports
│   ├── Toolbar.tsx      # Top action bar
│   ├── StatusBar.tsx    # Bottom status bar
│   ├── FilePanel.tsx    # Left sidebar
│   ├── FileRow.tsx      # Single file item
│   └── DetailPanel.tsx  # Right detail view
└── hooks/
    ├── index.ts         # Re-exports with types
    ├── useFileManager.ts # File state management
    └── useHashManager.ts # Hash/verify operations
```

### Component Props Pattern

```tsx
interface ComponentProps {
  // Data
  items: Item[];
  activeItem: Item | null;
  
  // State
  busy: boolean;
  
  // Callbacks (on* prefix)
  onSelect: (item: Item) => void;
  onAction: () => void;
  
  // Render helpers
  formatValue: (v: number) => string;
}
```

### CSS Class Naming

- **Layout:** `.app`, `.main-layout`, `.file-panel`, `.detail-panel`
- **Components:** `.toolbar`, `.status-bar`, `.file-row`, `.hash-card`
- **States:** `.active`, `.selected`, `.focused`, `.hashing`, `.verified`
- **Types:** `.type-ad1`, `.type-e01`, `.type-raw`
- **Modifiers:** `.primary`, `.compact`, `.full-width`

### Event Handling

```tsx
// Click handler
onClick={() => onSelect(item)}

// With event access
onClick={(e) => { e.stopPropagation(); onAction(); }}

// Keyboard handler
onKeyDown={(e) => {
  if (e.key === "Enter") onSelect(items[focusedIndex]);
}}
```

---

## Quick Start Checklist

1. **Copy template files** to new project
2. **Update branding** in Header Bar
3. **Define types** for your domain
4. **Implement hooks** for state management
5. **Customize type colors** for your categories
6. **Add domain-specific detail sections**
7. **Connect to backend** (Tauri invoke calls)

---

## Files Included in Template

- `DESIGN_DOCUMENT.md` - This document
- `template.css` - Complete CSS design system
- `template-types.ts` - Generic type definitions
- `template-utils.ts` - Utility functions
- `template-App.tsx` - Root component structure
- `components/` - All component templates
- `hooks/` - State management hooks

---

*Design System v1.0 - FFX (Forensic File Explorer)*

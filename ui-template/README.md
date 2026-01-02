# UI Template Package

A complete, reusable design system and component library for building desktop applications with **Tauri + SolidJS**. Extracted from the AD1-tools forensic container analysis app.

## 📁 Contents

| File | Description |
|------|-------------|
| `DESIGN_DOCUMENT.md` | Comprehensive design system documentation |
| `template.css` | Complete CSS design system with variables and components |
| `template-types.ts` | TypeScript type definitions |
| `template-utils.ts` | Utility functions (formatting, helpers) |
| `template-hooks.ts` | SolidJS state management hooks |
| `template-components.tsx` | Reusable SolidJS UI components |
| `template-App.tsx` | Main application shell template |

## 🚀 Quick Start

### 1. Create a new Tauri + SolidJS project

```bash
npm create tauri-app@latest my-app -- --template solid-ts
cd my-app
```

### 2. Copy template files

Copy the template files to your `src/` directory and rename as needed:

```bash
cp template.css src/App.css
cp template-types.ts src/types.ts
cp template-utils.ts src/utils.ts
cp template-hooks.ts src/hooks/index.ts
cp template-components.tsx src/components/index.tsx
cp template-App.tsx src/App.tsx
```

### 3. Update imports

Adjust import paths in the copied files to match your project structure.

### 4. Install dependencies

```bash
npm install
```

### 5. Start development

```bash
npm run tauri dev
```

## 🎨 Design System

### Color Palette

```css
/* Backgrounds */
--bg: #0f1419;           /* Main background */
--bg-secondary: #1a2028;  /* Panels */
--bg-tertiary: #242c35;   /* Cards */
--bg-hover: #2a333d;      /* Hover states */

/* Accents */
--accent: #2f81f7;        /* Primary accent */
--accent-soft: #388bfd;   /* Hover accent */

/* Status */
--success: #3fb950;       /* OK/Success */
--warning: #d29922;       /* Warning */
--error: #f85149;         /* Error */

/* Text */
--text-primary: #e6edf3;
--text-secondary: #8b949e;
--text-muted: #6e7681;
```

### Typography

- **Sans-serif:** Inter, system fonts
- **Monospace:** JetBrains Mono, SF Mono, Menlo

### Layout Pattern

```
┌─────────────────────────────────────────┐
│               Header                    │
├─────────────────────────────────────────┤
│               Toolbar                   │
├─────────────────┬───────────────────────┤
│                 │                       │
│   File Panel    │    Detail Panel       │
│   (Sidebar)     │    (Content)          │
│                 │                       │
├─────────────────┴───────────────────────┤
│             Status Bar                  │
└─────────────────────────────────────────┘
```

## 🧩 Components

### Toolbar
Top action bar with directory selection, algorithm dropdown, and action buttons.

```tsx
<Toolbar
  currentPath="/path/to/dir"
  algorithms={ALGORITHMS}
  selectedAlgorithm="sha256"
  isProcessing={false}
  onBrowse={handleBrowse}
  onAlgorithmChange={setAlgorithm}
  onProcess={handleProcess}
  onCancel={handleCancel}
/>
```

### FilePanel
Left sidebar with search, category filters, and file list.

```tsx
<FilePanel
  items={files}
  categories={CATEGORIES}
  selectedId={selected?.id}
  searchText={filter.searchText}
  selectedCategories={filter.selectedCategories}
  onSelect={handleSelect}
  onSearchChange={setSearch}
  onCategoryToggle={toggleCategory}
/>
```

### DetailPanel
Right content area with header, actions, and flexible content slot.

```tsx
<DetailPanel
  title="File Name"
  subtitle="Category"
  isEmpty={!selected}
  actions={<button>Action</button>}
>
  <InfoSection items={details} />
</DetailPanel>
```

### StatusBar
Bottom bar with status message, counts, and system stats.

```tsx
<StatusBar
  status="Ready"
  itemCount={100}
  filteredCount={50}
  totalSize={1024000}
  stats={systemStats}
/>
```

## 🪝 Hooks

### `createSelectionManager<T>()`
Single-item selection state management.

```tsx
const selection = createSelectionManager<Item>((a, b) => a.id === b.id);
selection.setSelected(item);
selection.isSelected(item);
selection.clear();
```

### `createFilterManager(categories)`
Search and category filter state.

```tsx
const filter = createFilterManager(["doc", "image", "video"]);
filter.setSearchText("query");
filter.toggleCategory("doc");
filter.clearFilters();
```

### `createItemManager<T>(filterFn)`
Collection state with filtering and loading.

```tsx
const items = createItemManager<Item>((items, filter) => {
  // Return filtered items
});
await items.loadItems(() => fetchItems());
items.updateItem(id, { status: "ok" });
```

### `createSystemStats()`
Poll for system resource usage.

```tsx
const stats = createSystemStats();
stats.startPolling(fetchStats, 2000);
// stats.stats() -> { cpuUsage, memoryUsed, ... }
```

### `createToastManager()`
Toast notification system.

```tsx
const toasts = createToastManager();
toasts.show("Operation complete", "success");
toasts.dismiss(id);
```

## 📐 Customization

### Adding Categories

```tsx
const CATEGORIES: CategoryConfig[] = [
  { id: "custom", label: "Custom", icon: "🔮", colorClass: "type-custom" },
];
```

Add CSS:

```css
.type-custom { 
  background: var(--purple); 
  color: var(--purple-light); 
}
```

### Modifying Colors

Override CSS variables in your stylesheet:

```css
:root {
  --accent: #8b5cf6;  /* Purple accent */
  --bg: #1a1a2e;      /* Different dark background */
}
```

### Custom Components

Extend the base components or create new ones following the same patterns:

```tsx
const MyComponent: Component<MyProps> = (props) => {
  return (
    <div class="my-component">
      {/* Content */}
    </div>
  );
};
```

## 📋 Best Practices

1. **Use semantic status colors** - `--success`, `--warning`, `--error` for states
2. **Prefer CSS variables** - Makes theming and maintenance easier
3. **Use computed accessors** - `createMemo` for derived state
4. **Batch state updates** - Use `batch()` for multiple signal updates
5. **Clean up effects** - Use `onCleanup()` for intervals, listeners
6. **Type everything** - Full TypeScript for safety

## 📄 License

MIT License - Use freely for your projects.

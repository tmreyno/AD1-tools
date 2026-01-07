# CORE-FFX Extension Development Guide

This guide explains how to build extensions (add-ons) for CORE-FFX, the forensic file explorer.

## Overview

CORE-FFX supports several types of extensions:

| Type | Purpose | Example Use Cases |
|------|---------|-------------------|
| **Database Processor** | Parse processed forensic databases | Support for new AXIOM versions, Cellebrite, custom tools |
| **Container Parser** | Parse evidence container formats | New forensic image formats, encrypted containers |
| **Artifact Viewer** | Custom viewers for artifacts | Chat viewer, timeline viewer, map viewer |
| **Export Format** | New export/report formats | Custom PDF templates, Excel, XML |
| **Analysis Tool** | Analysis and search tools | Hash lookup, timeline correlation |
| **Integration** | Third-party integrations | Cloud APIs, external databases |

## Quick Start

### 1. Create Your Extension

```typescript
import { createArtifactViewer, registerExtension, enableExtension } from "@core-ffx/extensions";

// Define your extension
const myExtension = createArtifactViewer({
  manifest: {
    id: "com.example.my-viewer",
    name: "My Custom Viewer",
    version: "1.0.0",
    author: "Your Name",
  },
  
  artifactTypes: ["Chat", "Message"],
  
  canHandle(artifact) {
    return artifact.type === "Chat" || artifact.type === "Message";
  },
  
  Component: MyViewerComponent,
});

// Register and enable
await registerExtension(myExtension);
await enableExtension(myExtension.manifest.id);
```

### 2. Extension Manifest

Every extension requires a manifest with these fields:

```typescript
interface ExtensionManifest {
  id: string;          // Unique ID (e.g., "com.company.extension-name")
  name: string;        // Display name
  version: string;     // Semver (e.g., "1.0.0")
  description: string; // Brief description
  author: string;      // Author name
  category: ExtensionCategory;
  
  // Optional
  license?: string;    // License (e.g., "MIT")
  homepage?: string;   // Project URL
  repository?: string; // Git repository URL
  minAppVersion?: string; // Minimum CORE-FFX version
  keywords?: string[]; // Search keywords
  icon?: string;       // Emoji or icon URL
}
```

## Extension Types

### Database Processor

Add support for new forensic database formats:

```typescript
import { createDatabaseProcessor, ProcessedDatabase } from "@core-ffx/extensions";

const myProcessor = createDatabaseProcessor({
  manifest: {
    id: "com.example.my-tool-processor",
    name: "MyTool Database Processor",
    version: "1.0.0",
  },
  
  dbType: "MyTool",
  filePatterns: ["*.mydb", "Case.xml"],
  
  async detect(path: string): Promise<boolean> {
    // Check if path contains a MyTool database
    return await checkForMyToolFiles(path);
  },
  
  async parse(path: string): Promise<ProcessedDatabase> {
    // Parse and return database info
    return {
      db_type: "MyTool",
      path,
      name: "Parsed Case",
      // ... other fields
    };
  },
  
  async getCategories(db) {
    return [
      { name: "Messages", category: "Chat", count: 150 },
      { name: "Call Logs", category: "Mobile", count: 45 },
    ];
  },
  
  async queryArtifacts(db, category, options) {
    // Query and return artifacts
  },
});
```

### Container Parser

Add support for new evidence container formats:

```typescript
import { createContainerParser, ContainerInfo } from "@core-ffx/extensions";

const myParser = createContainerParser({
  manifest: {
    id: "com.example.my-format-parser",
    name: "MyFormat Parser",
    version: "1.0.0",
  },
  
  containerType: "MyFormat",
  fileExtensions: [".mfmt", ".mf01"],
  magicBytes: new Uint8Array([0x4D, 0x46, 0x4D, 0x54]), // "MFMT"
  
  async detect(path: string): Promise<boolean> {
    // Check magic bytes or file structure
  },
  
  async parse(path: string): Promise<ContainerInfo> {
    // Parse and return container info
  },
  
  async listEntries(path: string) {
    // Return list of files/folders in container
  },
  
  async extractEntry(containerPath, entryPath, destPath) {
    // Extract a single entry
  },
  
  async verify(path: string) {
    return { valid: true, message: "Container integrity verified" };
  },
});
```

### Artifact Viewer

Create custom viewers for specific artifact types:

```typescript
import { createArtifactViewer, ArtifactViewerProps } from "@core-ffx/extensions";
import { Component } from "solid-js";

const ChatViewer: Component<ArtifactViewerProps> = (props) => {
  return (
    <div class="chat-viewer">
      <div class="messages">
        {/* Render chat messages */}
      </div>
    </div>
  );
};

const chatViewerExtension = createArtifactViewer({
  manifest: {
    id: "com.example.chat-viewer",
    name: "Chat Viewer",
    version: "1.0.0",
    icon: "💬",
  },
  
  artifactTypes: ["Chat", "Message", "SMS", "iMessage"],
  categories: ["Chat", "Mobile"],
  priority: 100, // Higher = preferred
  
  canHandle(artifact) {
    return this.artifactTypes.includes(artifact.type);
  },
  
  Component: ChatViewer,
});
```

### Export Format

Add new export/report formats:

```typescript
import { createExportFormat, ExportData } from "@core-ffx/extensions";

const excelExporter = createExportFormat({
  manifest: {
    id: "com.example.excel-export",
    name: "Excel Export",
    version: "1.0.0",
    icon: "📊",
  },
  
  formatId: "xlsx",
  formatName: "Microsoft Excel",
  fileExtension: ".xlsx",
  mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  
  async export(data: ExportData, options) {
    // Generate Excel file
    const workbook = createWorkbook(data);
    return workbook.toBuffer();
  },
  
  preview(data) {
    // Return preview JSX
    return <div>Preview of {data.title}</div>;
  },
});
```

### Analysis Tool

Add analysis and search capabilities:

```typescript
import { createAnalysisTool, AnalysisToolProps } from "@core-ffx/extensions";
import { Component } from "solid-js";

const HashLookupTool: Component<AnalysisToolProps> = (props) => {
  // Tool UI implementation
};

const hashLookupExtension = createAnalysisTool({
  manifest: {
    id: "com.example.hash-lookup",
    name: "Hash Lookup",
    version: "1.0.0",
    icon: "🔍",
  },
  
  toolId: "hash-lookup",
  toolName: "Hash Lookup Tool",
  placement: "toolbar",
  
  Component: HashLookupTool,
  
  async analyze(input) {
    // Perform analysis
    return {
      success: true,
      type: "hash-lookup",
      title: "Hash Lookup Results",
      data: { /* results */ },
    };
  },
});
```

## Lifecycle Hooks

Extensions can implement lifecycle hooks:

```typescript
const myExtension = createDatabaseProcessor({
  // ... extension config
  
  async onLoad() {
    // Called when extension is first loaded
    // Initialize resources, load settings
  },
  
  async onEnable() {
    // Called when extension is enabled
    // Start services, register listeners
  },
  
  async onDisable() {
    // Called when extension is disabled
    // Stop services, cleanup listeners
  },
  
  async onUnload() {
    // Called when extension is unloaded
    // Final cleanup
  },
  
  onSettingsChange(settings) {
    // Called when app settings change
    // React to configuration changes
  },
});
```

## Registry API

### Registration

```typescript
import { registerExtension, unregisterExtension } from "@core-ffx/extensions";

// Register
await registerExtension(myExtension);

// Unregister
await unregisterExtension("com.example.my-extension");
```

### Enable/Disable

```typescript
import { enableExtension, disableExtension } from "@core-ffx/extensions";

await enableExtension("com.example.my-extension");
await disableExtension("com.example.my-extension");
```

### Querying Extensions

```typescript
import {
  getAllExtensions,
  getEnabledExtensions,
  getExtensionsByCategory,
  getDatabaseProcessors,
  getArtifactViewers,
  findViewerForArtifact,
} from "@core-ffx/extensions";

// Get all registered extensions
const all = getAllExtensions();

// Get only enabled extensions
const enabled = getEnabledExtensions();

// Get by category
const viewers = getExtensionsByCategory("artifact-viewer");

// Get specialized
const processors = getDatabaseProcessors();
const viewers = getArtifactViewers();

// Find viewer for an artifact
const viewer = findViewerForArtifact(myArtifact);
```

### Using in Components

```typescript
import { useExtensions } from "@core-ffx/extensions";

function MyComponent() {
  const extensions = useExtensions();
  
  // Reactive extension list
  const viewers = () => extensions.getArtifactViewers();
  
  // Find viewer for artifact
  const viewer = () => extensions.findViewerForArtifact(currentArtifact());
  
  return (
    <Show when={viewer()}>
      {(v) => <v.Component artifact={currentArtifact()} />}
    </Show>
  );
}
```

## Best Practices

### Extension IDs

Use reverse domain notation:
- ✅ `com.mycompany.my-extension`
- ✅ `io.github.username.extension-name`
- ❌ `my-extension`

### Error Handling

Always handle errors gracefully:

```typescript
async detect(path: string): Promise<boolean> {
  try {
    // Detection logic
    return true;
  } catch (err) {
    console.warn(`[MyExtension] Detection failed for ${path}:`, err);
    return false;
  }
}
```

### Performance

- Cache expensive operations
- Use lazy loading for large dependencies
- Implement pagination for large datasets
- Clean up resources in lifecycle hooks

### Testing

```typescript
import { describe, it, expect } from "vitest";
import { myExtension } from "./my-extension";

describe("MyExtension", () => {
  it("should detect valid databases", async () => {
    expect(await myExtension.detect("/path/to/valid")).toBe(true);
    expect(await myExtension.detect("/path/to/invalid")).toBe(false);
  });
});
```

## File Structure

Recommended extension project structure:

```
my-extension/
├── src/
│   ├── index.ts          # Main export
│   ├── extension.ts      # Extension definition
│   ├── components/       # UI components
│   │   └── Viewer.tsx
│   ├── parsers/          # Parsing logic
│   │   └── parser.ts
│   └── utils/            # Utilities
│       └── helpers.ts
├── package.json
├── tsconfig.json
└── README.md
```

## Examples

See the `src/extensions/examples/` directory for complete working examples:

- `timeline-viewer.tsx` - Artifact viewer example

## Support

- GitHub Issues: [Report bugs and request features](https://github.com/your-org/core-ffx/issues)
- Documentation: [Full API documentation](https://docs.core-ffx.com/extensions)

import { createSignal, createEffect, Show, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import type { DiscoveredFile } from "../types";

// --- Constants ---
const DEFAULT_MAX_CHARS = 100000; // 100KB of text
const LINE_NUMBER_WIDTH = 6;

interface TextViewerProps {
  file: DiscoveredFile;
}

export function TextViewer(props: TextViewerProps) {
  const [content, setContent] = createSignal<string>("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [totalSize, setTotalSize] = createSignal(0);
  const [loadedChars, setLoadedChars] = createSignal(0);
  
  // View options
  const [showLineNumbers, setShowLineNumbers] = createSignal(true);
  const [wordWrap, setWordWrap] = createSignal(true);
  const [fontSize, setFontSize] = createSignal(13);
  
  // Search
  const [searchQuery, setSearchQuery] = createSignal("");
  const [searchResults, setSearchResults] = createSignal<number[]>([]);
  const [currentResult, setCurrentResult] = createSignal(0);
  
  // Load file content
  const loadContent = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const text = await invoke<string>("viewer_read_text", {
        path: props.file.path,
        offset: 0,
        maxChars: DEFAULT_MAX_CHARS
      });
      setContent(text);
      setLoadedChars(text.length);
      setTotalSize(props.file.size);
    } catch (e) {
      setError(`Failed to load file: ${e}`);
      setContent("");
    } finally {
      setLoading(false);
    }
  };
  
  // Load on file change
  createEffect(() => {
    const file = props.file;
    if (!file) return;
    
    setContent("");
    setError(null);
    loadContent();
  });
  
  // Search functionality
  createEffect(() => {
    const query = searchQuery().toLowerCase();
    const text = content().toLowerCase();
    
    if (!query || !text) {
      setSearchResults([]);
      return;
    }
    
    const results: number[] = [];
    let pos = 0;
    while ((pos = text.indexOf(query, pos)) !== -1) {
      results.push(pos);
      pos += 1;
    }
    setSearchResults(results);
    setCurrentResult(results.length > 0 ? 0 : -1);
  });
  
  // Navigate search results
  const nextResult = () => {
    const results = searchResults();
    if (results.length === 0) return;
    setCurrentResult((currentResult() + 1) % results.length);
    scrollToResult();
  };
  
  const prevResult = () => {
    const results = searchResults();
    if (results.length === 0) return;
    setCurrentResult((currentResult() - 1 + results.length) % results.length);
    scrollToResult();
  };
  
  const scrollToResult = () => {
    // TODO: Implement scroll to result
    // This would require refs and more complex DOM manipulation
  };
  
  // Split content into lines
  const lines = () => content().split('\n');
  
  // Detect language for syntax highlighting (basic detection)
  const detectLanguage = (): string => {
    const ext = props.file.filename.split('.').pop()?.toLowerCase() || '';
    const langMap: Record<string, string> = {
      'js': 'javascript',
      'ts': 'typescript',
      'jsx': 'javascript',
      'tsx': 'typescript',
      'py': 'python',
      'rs': 'rust',
      'go': 'go',
      'java': 'java',
      'c': 'c',
      'cpp': 'cpp',
      'h': 'c',
      'hpp': 'cpp',
      'cs': 'csharp',
      'rb': 'ruby',
      'php': 'php',
      'html': 'html',
      'htm': 'html',
      'css': 'css',
      'scss': 'scss',
      'sass': 'sass',
      'less': 'less',
      'json': 'json',
      'xml': 'xml',
      'yaml': 'yaml',
      'yml': 'yaml',
      'toml': 'toml',
      'md': 'markdown',
      'sql': 'sql',
      'sh': 'bash',
      'bash': 'bash',
      'zsh': 'bash',
      'ps1': 'powershell',
      'bat': 'batch',
      'cmd': 'batch',
    };
    return langMap[ext] || 'plaintext';
  };
  
  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };
  
  const isTruncated = () => loadedChars() < totalSize();
  
  return (
    <div class="text-viewer">
      {/* Toolbar */}
      <div class="text-toolbar">
        <div class="text-toolbar-left">
          <span class="text-language">{detectLanguage()}</span>
          <span class="text-file-size">
            {formatFileSize(loadedChars())}
            <Show when={isTruncated()}>
              {" / " + formatFileSize(totalSize()) + " (truncated)"}
            </Show>
          </span>
          <span class="text-line-count">{lines().length} lines</span>
        </div>
        
        <div class="text-toolbar-center">
          {/* Search */}
          <div class="text-search">
            <input
              type="text"
              class="text-search-input"
              placeholder="Search..."
              value={searchQuery()}
              onInput={e => setSearchQuery(e.currentTarget.value)}
              onKeyDown={e => {
                if (e.key === "Enter") {
                  e.shiftKey ? prevResult() : nextResult();
                }
              }}
            />
            <Show when={searchQuery()}>
              <span class="text-search-count">
                {searchResults().length > 0 
                  ? `${currentResult() + 1}/${searchResults().length}`
                  : "No results"
                }
              </span>
              <button class="text-search-btn" onClick={prevResult} title="Previous (Shift+Enter)">
                ▲
              </button>
              <button class="text-search-btn" onClick={nextResult} title="Next (Enter)">
                ▼
              </button>
            </Show>
          </div>
        </div>
        
        <div class="text-toolbar-right">
          {/* View options */}
          <label class="text-option">
            <input
              type="checkbox"
              checked={showLineNumbers()}
              onChange={e => setShowLineNumbers(e.currentTarget.checked)}
            />
            Lines
          </label>
          <label class="text-option">
            <input
              type="checkbox"
              checked={wordWrap()}
              onChange={e => setWordWrap(e.currentTarget.checked)}
            />
            Wrap
          </label>
          
          {/* Font size */}
          <div class="text-font-size">
            <button 
              class="text-font-btn" 
              onClick={() => setFontSize(s => Math.max(10, s - 1))}
            >
              −
            </button>
            <span>{fontSize()}px</span>
            <button 
              class="text-font-btn" 
              onClick={() => setFontSize(s => Math.min(24, s + 1))}
            >
              +
            </button>
          </div>
        </div>
      </div>
      
      {/* Error display */}
      <Show when={error()}>
        <div class="text-error">{error()}</div>
      </Show>
      
      {/* Loading indicator */}
      <Show when={loading()}>
        <div class="text-loading">Loading...</div>
      </Show>
      
      {/* Content */}
      <Show when={!loading() && content()}>
        <div 
          class="text-content"
          classList={{ 'word-wrap': wordWrap() }}
          style={{ 'font-size': `${fontSize()}px` }}
        >
          <Show when={showLineNumbers()}>
            <div class="text-line-numbers">
              {lines().map((_, i) => (
                <div class="text-line-number">{i + 1}</div>
              ))}
            </div>
          </Show>
          <pre class="text-code">
            <code class={`language-${detectLanguage()}`}>
              {content()}
            </code>
          </pre>
        </div>
      </Show>
      
      {/* Truncation warning */}
      <Show when={!loading() && isTruncated()}>
        <div class="text-truncation-warning">
          ⚠️ File is truncated. Showing first {formatFileSize(loadedChars())} of {formatFileSize(totalSize())}.
        </div>
      </Show>
      
      {/* Empty state */}
      <Show when={!loading() && !content() && !error()}>
        <div class="text-empty">
          Select a text file to view its contents
        </div>
      </Show>
    </div>
  );
}
